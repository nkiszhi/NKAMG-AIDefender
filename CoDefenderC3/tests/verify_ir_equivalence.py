# -*- coding: utf-8 -*-
"""IR 等价性验证：bndb → IR → 特征  vs  bndb → 特征（现有代码）。

这是 Phase 1 的硬判据 —— 中间多了一层 IR，两边的特征必须**逐位相同**。

跑法（需要 BinaryNinja + 联网）：

    "C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" tests\\verify_ir_equivalence.py \\
        --bndb-dir "D:\\VM_Share\\CoDefenderC3_v8\\minimal_dataset\\.cache\\bndb"

2026-11-05
"""
import argparse
import glob
import hashlib
import os
import sys
import time

FE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "feature_extraction")
if FE_DIR not in sys.path:
    sys.path.insert(0, FE_DIR)

def _ensure_pkgs():
    """BN 自带的 python 没有 numpy —— 从指定目录补齐。

    BN 的启动器忽略 PYTHONPATH，所以只能靠 sys.path.insert。
    """
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
    cands.append(os.path.join(here, "_tools", "py310_pkgs"))
    for c in cands:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "numpy")):
            sys.path.insert(0, c)
            print("[deps] numpy from %s" % c)
            return
    raise ImportError("numpy 缺失：用 CODEFENDER_PY310_PKGS 指定目录")


_ensure_pkgs()

import numpy as np            # noqa: E402
import binaryninja as bn      # noqa: E402

import extract_feature        # noqa: E402
import backend_bn             # noqa: E402
import features_from_ir       # noqa: E402


def fp(arr):
    a = np.ascontiguousarray(arr)
    return hashlib.sha256(a.tobytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bndb-dir", required=True)
    ap.add_argument("--ir-out", default=None, help="把 IR 落盘到该目录（测体积）")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.bndb_dir, "*.bndb")))
    if args.limit:
        files = files[:args.limit]
    if not files:
        print("目录里没有 .bndb: %s" % args.bndb_dir)
        return 2

    ext = extract_feature.BinjaExtractor.__new__(extract_feature.BinjaExtractor)
    ext.bn = bn
    ext._headless = True

    n_feat = 0
    n_bad = 0
    bad_files = []
    sizes = []
    sizes_gz = []
    t0 = time.time()

    for i, path in enumerate(files, 1):
        bv = bn.load(path)
        if bv is None:
            print("[eq] %3d/%d !! load failed %s" % (i, len(files), os.path.basename(path)))
            bad_files.append(os.path.basename(path))
            continue
        try:
            old = {}
            old.update(ext._extract_disassembly(bv))
            old.update(ext._extract_graphs(bv))

            ir = backend_bn.build_ir(bv)
            new = features_from_ir.all_features(ir)

            diffs = []
            for fid, ref in old.items():
                n_feat += 1
                if fid not in new:
                    diffs.append("%s: new missing" % fid)
                    continue
                if fp(new[fid]) != fp(ref):
                    diffs.append("%s: sha256 mismatch" % fid)
            for fid in new:
                if fid not in old:
                    n_feat += 1
                    diffs.append("%s: old missing" % fid)

            if args.ir_out:
                os.makedirs(args.ir_out, exist_ok=True)
                jp = os.path.join(args.ir_out, os.path.basename(path) + ".ir.json")
                ir.save(jp)
                sizes.append(os.path.getsize(jp))
                gz = jp + ".gz"
                ir.save(gz)
                sizes_gz.append(os.path.getsize(gz))

            if diffs:
                n_bad += len(diffs)
                bad_files.append(os.path.basename(path))
                print("[eq] %3d/%d FAIL %-36s %s" % (i, len(files), os.path.basename(path)[:36],
                                                  "; ".join(diffs)))
            else:
                print("[eq] %3d/%d OK   %-36s funcs=%d ins=%d" % (
                    i, len(files), os.path.basename(path)[:36], ir.n_functions, ir.n_instructions))
        finally:
            try:
                bv.file.close()
            except Exception:
                pass

    print("")
    print("bndb %d 个, 其中 %d 个有差异; 共比对 %d 个特征, 差异 %d 个"
          % (len(files), len(bad_files), n_feat, n_bad))
    print("用时 %.1fs" % (time.time() - t0))
    if sizes:
        print("IR 体积: json 平均 %.1f KB / 最大 %.1f KB; gz 平均 %.1f KB"
              % (sum(sizes) / len(sizes) / 1024.0, max(sizes) / 1024.0,
                 sum(sizes_gz) / len(sizes_gz) / 1024.0))
    if bad_files:
        print("结论: FAIL —— IR 路径与原路径不等价")
        for b in bad_files[:10]:
            print("   - %s" % b)
        return 1
    print("结论: OK —— IR 路径与原路径逐位一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
