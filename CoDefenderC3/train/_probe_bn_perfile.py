# -*- coding: utf-8 -*-
"""探针: 逐文件（单样本单 worker）跑 BN 子进程路径，定位崩溃样本与原因。"""
import os
import sys
import time
import tempfile
import shutil

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, REPO)

SRC = r"D:\nkproject\data_test\20260928"


def collect(limit=6):
    pcs = []
    for sub in ("benign", "malicious"):
        d = os.path.join(SRC, sub)
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
    return pcs[:limit]


def main():
    work = os.path.join(tempfile.gettempdir(), "_bn_perfile")
    if os.path.isdir(work):
        shutil.rmtree(work, ignore_errors=True)
    bndb_dir = os.path.join(work, "bndb")
    os.makedirs(bndb_dir, exist_ok=True)

    from feature_extraction.extract_feature import BinjaExtractor
    ext = BinjaExtractor(headless=True, require_bn=True)

    pcs = collect()
    print("逐文件测试 %d 个样本（n_workers=1, batch_size=1）\n" % len(pcs))
    good, bad = 0, 0
    for p in pcs:
        bp = os.path.join(bndb_dir, os.path.basename(p) + ".bndb")
        t0 = time.time()
        ok, reasons = ext.generate_bndbs_batch([(p, bp)], n_workers=1, batch_size=1)
        dt = time.time() - t0
        sz = os.path.getsize(bp) if os.path.exists(bp) else -1
        if p in ok:
            good += 1
            print("  [OK] %-46s %7.0f KB  %.1fs  bndb=%.1fMB"
                  % (os.path.basename(p)[:44], os.path.getsize(p) / 1024.0, dt, sz / 1048576.0))
        else:
            bad += 1
            print("  [X]  %-46s %7.0f KB  %.1fs  原因=%s"
                  % (os.path.basename(p)[:44], os.path.getsize(p) / 1024.0, dt,
                     reasons.get(p, "?")))
    print("\n结果: 成功 %d / 失败 %d" % (good, bad))
    print("临时目录: %s" % work)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
