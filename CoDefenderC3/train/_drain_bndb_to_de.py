# -*- coding: utf-8 -*-
"""把已有 .bndb 转成 D/E 写回 npz —— 零额外磁盘、**不删除任何文件**。

背景（2026-10-10）：
  上一轮 build（10-09 22:50 起，跑了 14h28m）在 BinaryNinja 生成 bndb 阶段
  成功率只有 20%。实测原因是 batch_size=5：一个 worker 进程连续分析 5 个文件，
  第 2 个起就硬崩溃 → 每批只有 1 个报 OK。但崩溃发生在 `create_database()`
  **之后**，所以磁盘上的 .bndb 其实是完整的（抽检 6/6 可被 BN 正常加载）。

  因此那 8467 个 bndb 不用重跑，直接走「阶段2: bndb → D/E」这条秒开路径即可
  （项目自带持久化 Worker，零连坐，单文件崩溃不影响其它）。

  本脚本刻意：
    - 设 CODEFENDER_KEEP_BNDB=1 → 不触发任何删除 API（本机 safe-delete 钩子会
      拦截批量删除并杀进程）
    - 不清理、不归档、不改动 bndb 目录
    - 分 chunk 处理，每个 chunk 结束打印进度 → 可随时 Ctrl+C，重跑自动跳过已完成
"""
import os
import sys
import time
import glob
import hashlib
import argparse

REPO = os.environ.get(
    "CODEFENDER_REPO", r"D:/VM_Share/CoDefenderC3_v8/CoDefenderC3")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "feature_extraction"))

# 关键：全程不删任何文件
os.environ.setdefault("CODEFENDER_KEEP_BNDB", "1")

import numpy as np
from feature_extraction.extract_feature import BinjaExtractor


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def has_de(npz_path):
    try:
        with np.load(npz_path, allow_pickle=True) as z:
            return any(k.startswith("D") for k in z.files)
    except Exception:
        return False


def collect(out):
    bndb_dir = os.path.join(out, ".cache", "bndb")
    npz_dir = os.path.join(out, ".cache", "per_sample")
    paths = []
    for cls in ("benign", "malicious"):
        d = os.path.join(out, cls)
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if ".link-tmp-" in f:
                continue
            paths.append(os.path.join(d, f).replace("/", "\\"))
    todo = []
    skip_no_bndb = skip_no_npz = skip_done = 0
    for p in paths:
        k = md5(p)
        bp = os.path.join(bndb_dir, k + ".bndb")
        npz = os.path.join(npz_dir, k + ".npz")
        if not os.path.exists(bp):
            skip_no_bndb += 1
            continue
        if not os.path.exists(npz):
            skip_no_npz += 1
            continue
        if has_de(npz):
            skip_done += 1
            continue
        todo.append((p, bp, npz))
    print("样本 %d | 待转换 %d | 无bndb %d | 无npz %d | 已有D/E %d"
          % (len(paths), len(todo), skip_no_bndb, skip_no_npz, skip_done),
          flush=True)
    return todo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--chunk", type=int, default=400)
    ap.add_argument("--limit", type=int, default=0, help="只做前 N 个（冒烟用）")
    a = ap.parse_args()

    todo = collect(a.out)
    if a.limit:
        todo = todo[:a.limit]
        print("--limit 生效，只做 %d 个" % len(todo), flush=True)
    if not todo:
        print("没有需要转换的样本。")
        return

    ext = BinjaExtractor()
    n_chunk = (len(todo) + a.chunk - 1) // a.chunk
    done = 0
    t0 = time.time()
    for i in range(0, len(todo), a.chunk):
        ch = todo[i:i + a.chunk]
        ok, fail = ext.extract_de_from_bndb_batch(
            [c[0] for c in ch],
            [c[1] for c in ch],
            [c[2] for c in ch],
            n_workers=a.workers,
        )
        done += len(ok)
        el = time.time() - t0
        print("[chunk %d/%d] ok=%d fail=%d | 累计成功 %d/%d | %.0fs (%.1f/s)"
              % (i // a.chunk + 1, n_chunk, len(ok), len(fail), done, len(todo),
                 el, done / max(el, 0.01)), flush=True)
    print("DONE 成功 %d / %d，用时 %.0fs" % (done, len(todo), time.time() - t0),
          flush=True)


if __name__ == "__main__":
    main()
