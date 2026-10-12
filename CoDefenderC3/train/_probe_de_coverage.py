#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
_probe_de_coverage.py — 按 **build 门禁口径**复核某数据集的 D/E 覆盖率（秒级，不写盘）

用途
----
`build_minimal_dataset.py` 在 `--views full` 下要求 D/E 覆盖率 **100%**，否则 exit=1
（因为 `_build_month_cache` 是严格模式：缺任一视角 → 整个样本被静默丢掉）。
本脚本复现同一口径，直接告出**还缺哪些样本、缺在哪一步**，避免为了看一眼而重跑
几十分钟的构建。

用法
----
  python CoDefenderC3/train/_probe_de_coverage.py <数据集目录>

输出：快速特征 x/N、D/E 特征 y/N、覆盖率、以及每个缺失样本的归类：
  · 在 bndb_slow.log 里 → 慢样本（超时/子进程崩溃）→ **直接重跑 build 即会自动补救**
  · 在 bndb_fail/de_fail 日志中 → 已标记永久失败，**直接重跑 build 不会重试**
  · 无 bndb      → BinaryNinja 生不出 bndb（用 _probe_bndb_fail.py 单独复现）
  · 有 bndb 无 npz → 快速/合并阶段没写出来
  · 有 bndb 有 npz 无 D → D/E 提取失败（de_fail.log）
退出码：0 = 覆盖率 100%；1 = 有缺口；2 = 用法/路径错误。
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (REPO_ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def main(argv=None):
    ap = argparse.ArgumentParser(description="按 build 门禁口径复核 D/E 覆盖率")
    ap.add_argument("dataset", help="数据集目录（含 benign/ 与 malicious/ 与 .cache/）")
    args = ap.parse_args(argv)

    ds = os.path.normpath(os.path.abspath(args.dataset))
    if not os.path.isdir(ds):
        print("[X] 数据集目录不存在: %s" % ds)
        return 2

    from data_loader import PELoader
    from build_minimal_dataset import has_de_keys

    loader = PELoader(data_dir=ds)
    paths = []
    for sub in ("benign", "malicious"):
        d = os.path.join(ds, sub)
        if not os.path.isdir(d):
            print("[X] 缺少子目录: %s" % d)
            return 2
        paths += [os.path.normpath(os.path.abspath(os.path.join(d, f)))
                  for f in sorted(os.listdir(d))]

    pd = os.path.join(loader.cache_dir, "per_sample")

    def _load_log(name):
        p = os.path.join(pd, name + ".log")
        if not os.path.exists(p):
            return set()
        with open(p, encoding="utf-8") as f:
            return {os.path.normcase(l.strip()) for l in f if l.strip()}

    bndb_fail = _load_log("bndb_fail")
    de_fail = _load_log("de_fail")
    # bndb_slow.log 是 `路径\t次数`，只取路径
    slow_counts = {os.path.normcase(k): v
                   for k, v in loader._load_slow_log().items()}

    ok_fast, ok_de, gaps = [], [], []
    for p in paths:
        has_npz = os.path.exists(loader._sample_cache_path(p))
        has_bndb = loader._is_valid_bndb(p)
        has_de = has_de_keys(loader, p)
        if has_npz:
            ok_fast.append(p)
        if has_de:
            ok_de.append(p)
            continue
        key = os.path.normcase(p)
        if key in bndb_fail:
            why = "已记入 bndb_fail.log（永久失败，重跑不重试）"
        elif key in de_fail:
            why = "已记入 de_fail.log（永久失败，重跑不重试）"
        elif key in slow_counts:
            why = ("慢样本 bndb_slow.log（第 %d 次尝试，超时/崩溃）"
                   "→ 直接重跑 build 会放宽超时自动补救" % slow_counts[key])
        elif not has_bndb:
            why = "无 bndb（BinaryNinja 生成失败）"
        elif not has_npz:
            why = "有 bndb 但无 per_sample npz（快速/合并阶段没写出）"
        else:
            why = "npz 里没有 D* 键（D/E 提取失败）"
        gaps.append((p, why))

    cov = len(ok_de) / max(len(paths), 1)
    print("  数据集      : %s" % ds)
    print("  样本总数    : %d" % len(paths))
    print("  快速特征    : %d/%d" % (len(ok_fast), len(paths)))
    print("  D/E 特征    : %d/%d  → 覆盖率 %.1f%%" % (len(ok_de), len(paths), cov * 100))
    if gaps:
        n_slow = sum(1 for p, _ in gaps if os.path.normcase(p) in slow_counts)
        n_hard = sum(1 for p, _ in gaps
                     if os.path.normcase(p) in bndb_fail
                     or os.path.normcase(p) in de_fail)
        print("\n  缺口归类: 慢样本 %d / 永久失败 %d / 其他 %d"
              % (n_slow, n_hard, len(gaps) - n_slow - n_hard))
        print("  缺口样本（%d 个）:" % len(gaps))
        for p, why in gaps[:20]:
            print("    %-10s %s\n               %s" % (
                os.path.basename(os.path.dirname(p)), os.path.basename(p)[:20] + "…", why))
        if len(gaps) > 20:
            print("    ... 还有 %d 个" % (len(gaps) - 20))
    print("\n  门禁结果: %s" % ("通过 → 可直接重跑 build（--views full）"
                               if cov == 1.0 else
                               "不通过 → 按上面的归类修复（直接重跑 / 清失败日志 / 换 --views fast）"))
    return 0 if cov == 1.0 else 1


if __name__ == "__main__":
    sys.exit(main())
