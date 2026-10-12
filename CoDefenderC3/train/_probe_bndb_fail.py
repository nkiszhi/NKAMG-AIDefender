#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
_probe_bndb_fail.py — 诊断**单个样本**为什么生不出 bndb（→ 缺 D/E → build 门禁拦截）

背景
----
`build_minimal_dataset.py` 要求 D/E 覆盖率 100%，否则拒绝继续构建
（因为 `_build_month_cache` 是严格模式：缺任一视角 → 整个样本被静默丢掉）。
覆盖率不足几乎总是因为 **BinaryNinja 无法为该样本生成 bndb**。
`data_loader` 会把这类样本写进 `<数据集>/.cache/per_sample/bndb_fail.log` 与
`de_fail.log`，**此后 `_find_need_de()` 会永久排除它们 —— 直接重跑 build 不会再尝试**。

用法
----
  # 自动推导 bndb 输出位置（<样本所在目录>/.cache/bndb）
  python CoDefenderC3/train/_probe_bndb_fail.py <PE路径>
  # 显式指定数据集目录（bndb 落到 <数据集>/.cache/bndb）
  python CoDefenderC3/train/_probe_bndb_fail.py <PE路径> --dataset <数据集目录>

退出码：0 = 本次成功生成 bndb；1 = 仍然失败（原因已打印）；2 = 用法/路径错误。
"""
import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (REPO_ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def bndb_path_for(pe_path, cache_dir):
    """与 PELoader._bndb_cache_path 完全一致：md5(路径字符串) + .bndb"""
    return os.path.join(cache_dir, "bndb",
                        hashlib.md5(pe_path.encode()).hexdigest() + ".bndb")


def main(argv=None):
    ap = argparse.ArgumentParser(description="诊断单样本 bndb 生成失败原因")
    ap.add_argument("pe", help="PE 样本路径（必须是数据集里的那个绝对路径）")
    ap.add_argument("--dataset", default=None,
                    help="数据集目录（默认取样本所在目录：<pe 的父目录>/.. ）")
    args = ap.parse_args(argv)

    pe = os.path.normpath(os.path.abspath(args.pe))
    if not os.path.isfile(pe):
        print("[X] 样本不存在: %s" % pe)
        return 2
    ds = args.dataset or os.path.dirname(os.path.dirname(pe))
    ds = os.path.normpath(os.path.abspath(ds))
    cache_dir = os.path.join(ds, ".cache")
    if not os.path.isdir(cache_dir):
        print("[X] 找不到缓存目录: %s（用 --dataset 指定数据集目录）" % cache_dir)
        return 2

    out = bndb_path_for(pe, cache_dir)
    print("  样本  : %s (%d B)" % (pe, os.path.getsize(pe)))
    print("  bndb  : %s" % out)
    if os.path.exists(out):
        print("  [i] bndb 已存在 → 本样本不缺 D/E，问题在别处（D/E 提取阶段）。")
        return 0

    os.makedirs(os.path.dirname(out), exist_ok=True)
    from feature_extraction.extract_feature import BinjaExtractor

    print("  调用 BinaryNinja（单样本、batch_size=1，约 40s）...")
    ok, reasons = BinjaExtractor().generate_bndbs_batch(
        [(pe, out)], n_workers=1, batch_size=1)
    if pe in ok or os.path.exists(out):
        print("  [OK] bndb 生成成功 → 属**一次性失败**（BN 偶发崩溃）。")
        print("       修复：删掉失败日志里的这一行，再重跑同样的 build 命令；")
        print("             bndb_fail.log / de_fail.log 位于 %s" % os.path.join(cache_dir, "per_sample"))
        return 0

    print("  [X] 仍然失败（BN 无法解析该样本）：")
    print("      原因: %s" % reasons.get(pe, "(未返回原因)"))
    print("       对策：a) 换 --views fast 退回 11 视角（该样本保留，9 个 BN 模型冻结继承）")
    print("             b) 加 --allow-partial-de 继续：该样本被归档到 <数据集>/.dropped-*/（等于丢样本）")
    print("             c) 从源目录里剔除该样本后重建")
    return 1


if __name__ == "__main__":
    sys.exit(main())
