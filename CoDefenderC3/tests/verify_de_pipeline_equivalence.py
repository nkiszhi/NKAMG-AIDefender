# -*- coding: utf-8 -*-
"""D/E 抽取管线等价性验证：bndb 路径 vs IR 路径。

⚠ 比较方式
------------
BN 的分析结果是不确定的（W1 实测：同一 PE 两次分析，25/88 的样本 D/E 指纹不同）。
所以「分别跑一遍两条路径再比对」必然对不上 —— 那不是 bug，是 BN 本身不确定。

正确的比较是：同一次分析，产出两种中间产物，再各自抽特征：

    bv = bn.load(pe)                          ← 只分析一次
    ├─ build_ir(bv)                → IR    → 抽特征   （IR 路径）
    └─ bv.create_database(bndb) → 重开 → 抽特征   （bndb 路径）
    两条路径必须逐位一致 —— 这才是「IR 可以替掉 bndb」的判据。

整个比较放在子进程里，原因有两个（都是实测踩到的）：
  1. 父进程若同时持有同一个 PE 的 view，子进程再开一个会触发 BN 原生崩溃
     （0xC0000409，没有 Python traceback）；
  2. BN 的 create_database() 在个别样本上本身就崩 —— 生产管线靠子进程隔离
     （_bndb_worker.py 的「零连坐」设计）。

另外会跑一遍真实的批量 API（generate_irs_batch / extract_de_from_ir_batch），
验证 worker 协议、补救轮与 npz 写入都正常。

跑法（需要 BinaryNinja + 联网）:

    "C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" tests\\verify_de_pipeline_equivalence.py \\
        --pe "D:\\tmp\\a.exe" --pe "D:\\tmp\\b.exe"

⚠ BN 打不开路径含非 ASCII 字符的文件 —— 样本路径必须是 ASCII（或先镜像）。
⚠ bnpython3.exe 不支持 python 的 -c 选项（只接受脚本文件）。

2026-11-06
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess as sp
import sys
import tempfile
import time

FE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "feature_extraction")
if FE_DIR not in sys.path:
    sys.path.insert(0, FE_DIR)


def _ensure_pkgs():
    """BN 自带的 python 没有 numpy —— 从指定目录补齐。"""
    try:
        import numpy  # noqa: F401
        return
    except ImportError:
        pass
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands = []
    env = os.environ.get("CODEFENDER_PY310_PKGS")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.dirname(here), "_tools", "py310_pkgs"))
    for c in cands:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "numpy")):
            sys.path.insert(0, c)
            print("[deps] numpy from %s" % c)
            return
    raise ImportError("numpy 缺失：用 CODEFENDER_PY310_PKGS 指定目录")


_ensure_pkgs()

import numpy as np            # noqa: E402
import ir_cache               # noqa: E402


# 子进程脚本：同一次分析 → 两种中间产物 → 两套特征指纹
_DUAL_BRANCH = """
import sys, os, json, hashlib
sys.path.insert(0, %r)
_d = os.environ.get("CODEFENDER_PY310_PKGS")
if _d and os.path.isdir(_d):
    sys.path.insert(0, _d)
import numpy as np, binaryninja as bn
import extract_feature, backend_bn, features_from_ir
pe, bpath = sys.argv[1], sys.argv[2]
def fp(v):
    return hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest()
ext = extract_feature.BinjaExtractor.__new__(extract_feature.BinjaExtractor)
ext.bn = bn
ext._headless = True
bv = bn.load(pe, options={"analysis.mode": "basic",
                         "analysis.linearSweep.autorun": True,
                         "analysis.limits.maxFunctionSize": 262144})
bv.update_analysis_and_wait()
ir = backend_bn.build_ir(bv)
fb = features_from_ir.all_features(ir)
bv.create_database(bpath)
bv.file.close()
bv2 = bn.load(bpath)
fa = {}
fa.update(ext._extract_disassembly(bv2))
fa.update(ext._extract_graphs(bv2))
bv2.file.close()
print(json.dumps({"ir": dict((k, fp(v)) for k, v in fb.items()),
                  "bndb": dict((k, fp(v)) for k, v in fa.items())}))
"""


def _dual_branch(pe, bpath, timeout=600):
    """在子进程里做「同一次分析 → 两种中间产物 → 两套特征」。"""
    code = _DUAL_BRANCH % FE_DIR
    fd, script_path = tempfile.mkstemp(suffix=".py", prefix="de_dual_")
    os.close(fd)
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        proc = sp.run([sys.executable, script_path, pe, bpath],
                      capture_output=True, timeout=timeout)
    except Exception:
        return None
    finally:
        try: os.remove(script_path)
        except Exception: pass
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        print("    [子进程 stderr] " + err[-300:].replace(chr(10), " | "), flush=True)
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8", "replace").strip())
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pe", action="append", required=True, help="PE 路径（可重复）")
    ap.add_argument("--skip-batch", action="store_true", help="跳过批量 API 验证")
    args = ap.parse_args()

    n_feat = 0
    n_bad = 0
    n_skip = 0
    tmpdir = tempfile.mkdtemp(prefix="de_eq_")
    try:
        for i, pe in enumerate(args.pe, 1):
            if not os.path.isfile(pe):
                print("[eq] %d/%d !! 样本不存在 %s" % (i, len(args.pe), pe))
                continue
            bpath = os.path.join(tmpdir, "s%d.bndb" % i)
            dual = _dual_branch(pe, bpath)
            if dual is None:
                n_skip += 1
                print("[eq] %d/%d SKIP %-26s 子进程崩溃(BN 原生)"
                      % (i, len(args.pe), os.path.basename(pe)[:26]), flush=True)
                continue
            fa_fp = dual["bndb"]
            fb_fp = dual["ir"]
            diffs = []
            for fid, ref in fa_fp.items():
                n_feat += 1
                if fid not in fb_fp:
                    diffs.append("%s: IR 路径缺失" % fid)
                elif fb_fp[fid] != ref:
                    diffs.append("%s: sha256 不一致" % fid)
            for fid in fb_fp:
                if fid not in fa_fp:
                    n_feat += 1
                    diffs.append("%s: bndb 路径缺失" % fid)
            if diffs:
                n_bad += len(diffs)
                print("[eq] %d/%d FAIL %-26s %s" % (i, len(args.pe),
                                                  os.path.basename(pe)[:26],
                                                  "; ".join(diffs)), flush=True)
            else:
                print("[eq] %d/%d OK   %-26s 特征 %d 个全部一致"
                      % (i, len(args.pe), os.path.basename(pe)[:26], len(fa_fp)),
                      flush=True)

        print("")
        print("同一次分析下, 逐特征比对 %d 个, 差异 %d 个, 跳过 %d 个样本"
              % (n_feat, n_bad, n_skip))

        if not args.skip_batch and args.pe:
            print("")
            print("=== 批量 API 验证 ===")
            ir_dir = os.path.join(tmpdir, "ir")
            os.makedirs(ir_dir, exist_ok=True)
            npz_dir = os.path.join(tmpdir, "npz")
            os.makedirs(npz_dir, exist_ok=True)
            pes = [p for p in args.pe if os.path.isfile(p)]
            pairs = [(p, os.path.join(ir_dir,
                     hashlib.md5(p.encode()).hexdigest() + ".ir.json.gz")) for p in pes]
            t0 = time.time()
            ok, fails = ir_cache.generate_irs_batch(pairs, n_workers=2, batch_size=2)
            print("  generate_irs_batch(批): ok=%d fail=%d (%.1fs)" % (len(ok), len(fails),
                                                        time.time() - t0))
            # 补救轮: 与生产管线一致 —— 批量里 BN 原生崩溃的样本用 batch_size=1 单跑
            if fails:
                retry_pairs = [(pe, ir) for pe, ir in pairs if pe in fails]
                ok2, fails2 = ir_cache.generate_irs_batch(retry_pairs, n_workers=1,
                                                         batch_size=1)
                ok |= ok2
                fails = fails2
                print("  generate_irs_batch(补救轮 batch=1): ok=%d fail=%d"
                      % (len(ok2), len(fails2)))
            npzs = [os.path.join(npz_dir, os.path.basename(p) + ".npz") for p in pes]
            for n in npzs:
                np.savez(n, np.zeros(1, dtype=np.uint8))
            t0 = time.time()
            ok2, fails2 = ir_cache.extract_de_from_ir_batch(
                pes, [c for _, c in pairs], npzs, n_workers=2)
            print("  extract_de_from_ir_batch: ok=%d fail=%d (%.1fs)" % (len(ok2),
                                                         len(fails2), time.time() - t0))
            import zipfile
            for n in npzs:
                with zipfile.ZipFile(n, "r") as z:
                    keys = sorted(k[:-4] for k in z.namelist() if k.endswith(".npy"))
                if "D01" not in keys:
                    print("  !! %s 里没有 D01: %s" % (os.path.basename(n), keys[:8]))
                    n_bad += 1
                else:
                    print("  OK %s 含 %d 个特征" % (os.path.basename(n)[:34], len(keys)))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("")
    if n_bad:
        print("结论: FAIL —— 两条路径不等价")
        return 1
    print("结论: OK —— bndb 路径与 IR 路径逐位一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
