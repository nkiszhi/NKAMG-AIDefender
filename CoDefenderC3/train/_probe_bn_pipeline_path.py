# -*- coding: utf-8 -*-
"""
探针: 验证训练管线真正使用的 BN 子进程路径（PE → .bndb → D/E）。

覆盖点（与 data_loader 中提 D/E 的路径一致）:
  1) generate_bndbs_batch()  — 子进程 + bn.create_database(), 历史上 Windows 崩溃高发
  2) extract_de_from_bndb_batch() — 从 bndb 秒开抽 D/E

用法:
  python train/_probe_bn_pipeline_path.py [PE目录] [临时工作目录]
"""
import os
import sys
import time
import tempfile
import shutil

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, REPO)

DEFAULT_SRC = r"D:\nkproject\data_test\20260928"


def collect(src, limit=4):
    pcs = []
    if os.path.isfile(src):
        return [src]
    for sub in ("benign", "malicious"):
        d = os.path.join(src, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if os.path.isfile(p) and os.path.getsize(p) > 4096:
                pcs.append(p)
            if len(pcs) >= limit:
                break
        if len(pcs) >= limit:
            break
    if not pcs:  # 源目录本身就是扁平结构
        for fn in sorted(os.listdir(src)):
            p = os.path.join(src, fn)
            if os.path.isfile(p) and os.path.getsize(p) > 4096:
                pcs.append(p)
            if len(pcs) >= limit:
                break
    return pcs[:limit]


def main(argv):
    src = argv[1] if len(argv) > 1 else DEFAULT_SRC
    work = argv[2] if len(argv) > 2 else os.path.join(tempfile.gettempdir(), "_bn_pipe_test")
    if os.path.isdir(work):
        shutil.rmtree(work, ignore_errors=True)
    bndb_dir = os.path.join(work, "bndb")
    npz_dir = os.path.join(work, "npz")
    os.makedirs(bndb_dir, exist_ok=True)
    os.makedirs(npz_dir, exist_ok=True)

    pcs = collect(src)
    if not pcs:
        print("[X] 未找到样本: %s" % src)
        return 1
    print("样本 %d 个:" % len(pcs))
    for p in pcs:
        print("   %s (%.1f KB)" % (os.path.basename(p)[:40], os.path.getsize(p) / 1024.0))

    import numpy as np
    from feature_extraction.extract_feature import BinjaExtractor

    ext = BinjaExtractor(headless=True, require_bn=True)

    # ── 1. PE → bndb（子进程路径）──
    pairs = [(p, os.path.join(bndb_dir, os.path.basename(p) + ".bndb")) for p in pcs]
    print("\n=== 1) generate_bndbs_batch（子进程）===")
    t0 = time.time()
    ok_set, fail_reasons = ext.generate_bndbs_batch(pairs, n_workers=2, batch_size=4)
    dt = time.time() - t0
    print("  耗时 %.2fs  成功 %d / %d" % (dt, len(ok_set), len(pcs)))
    for pe in pcs:
        if pe in ok_set:
            bp = dict(pairs)[pe]
            sz = os.path.getsize(bp) if os.path.exists(bp) else -1
            print("    [OK] %s  bndb=%.1f MB" % (os.path.basename(pe)[:36], sz / 1048576.0))
        else:
            print("    [X] %s  原因=%s" % (os.path.basename(pe)[:36], fail_reasons.get(pe, "?")))
    if not ok_set:
        print("\n[X] 全部 bndb 生成失败 —— 训练侧 D/E 会整体缺失")
        return 1

    # ── 2. bndb → D/E（子进程路径）──
    print("\n=== 2) extract_de_from_bndb_batch ===")
    ok_list = [p for p in pcs if p in ok_set]
    bndb_list = [dict(pairs)[p] for p in ok_list]
    npz_list = [os.path.join(npz_dir, os.path.basename(p) + ".npz") for p in ok_list]
    t0 = time.time()
    res = ext.extract_de_from_bndb_batch(ok_list, bndb_list, npz_list)
    dt = time.time() - t0
    print("  耗时 %.2fs  返回类型=%s" % (dt, type(res).__name__))
    de_ok_set, de_fail = (res if isinstance(res, tuple) and len(res) == 2 else (set(), {}))
    print("  子进程报告成功 %d / %d" % (len(de_ok_set), len(ok_list)))
    for pe in ok_list:
        if pe not in de_ok_set:
            print("    [!] 子进程标记失败: %s -> %s"
                  % (os.path.basename(pe)[:34], de_fail.get(pe, "?")))

    n_ok = 0
    for pe, npz in zip(ok_list, npz_list):
        exists = os.path.exists(npz)
        keys = []
        if exists:
            with np.load(npz, allow_pickle=True) as z:
                keys = [k for k in z.files if k[0] in ("D", "E")]
        if exists and keys:
            n_ok += 1
            print("    [OK] %s  D/E 视角 %d 个: %s" % (
                os.path.basename(pe)[:34], len(keys), ",".join(sorted(keys))))
        else:
            print("    [X] %s  npz存在=%s keys=%s" % (os.path.basename(pe)[:34], exists, keys))

    print("\n=== 结论 ===")
    if n_ok == len(ok_list):
        print("  [OK] 子进程 bndb + D/E 路径全部通过（%d/%d）" % (n_ok, len(pcs)))
        rc = 0
    else:
        print("  [X] 部分失败（%d/%d）" % (n_ok, len(pcs)))
        rc = 1
    print("  临时目录保留供检查: %s" % work)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
