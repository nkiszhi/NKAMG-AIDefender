# -*- coding: utf-8 -*-
"""推理期特征掩码（实验 A：判定 D/E 模型退化是否由进程随机哈希造成）。

背景
----
D01/D02/D03/D07 在训练期由多个**独立子进程**（``feature_extraction/_ir_worker.py``）
生成，映射用的是 Python 内置 ``hash()``；而 ``str`` 的 hash 每进程随机 ⇒ 训练集
本身是多套随机 salt 的混合。推理端无论用哪种确定性映射都无法与之对齐，
依赖这些维度的模型输出接近随机（实测：OpcodeLSTM 的 BN 侧 AUC 0.508，
95%CI [0.457, 0.560]，覆盖 0.5）。

SMDA 后端已把 n-gram 哈希固定为 ``zlib.crc32``，但**既有权重**仍是在随机 salt
下训练出来的，直接套用会让哈希维退化为纯噪声，并可能压过真实信号
（实测 OpcodeStatNet：BN 0.868 → SMDA 0.340，低于随机）。

用途
----
把指定视图中的"哈希依赖特征段"整段置零，使模型只能依赖未被污染的真实特征
（V6_opcode_stat 中仅剩 D04 指令类别分布 / D05 函数统计 / D06 基本块统计），
用于判定退化的主因，并给出"零重训可恢复"的上限。

开关
----
环境变量 ``CODEFENDER_MASK_VIEWS``：逗号分隔的视图名，默认空 = 关闭。

    CODEFENDER_MASK_VIEWS=V6_opcode_stat          # 实验 A：只掩 V6_opcode_stat 的 D02/D03
    CODEFENDER_MASK_VIEWS=V6_opcode_stat,V6_opcode_seq

掩码只作用于推理期的视图拼装：不修改任何权重，不改变视图维度，可随时开关对比。
"""
from __future__ import annotations

import os
from typing import Dict, List, Sequence, Tuple

import numpy as np

# 依赖 Python 进程随机 hash() 的特征（训练期不可复现）
HASH_DEPENDENT_FEATURES: Tuple[str, ...] = ("D01", "D02", "D03", "D07")

ENV_KEY = "CODEFENDER_MASK_VIEWS"

_cache: Dict[str, frozenset] = {}


def enabled_views() -> frozenset:
    """当前启用的掩码视图集合（按环境变量取值缓存）。"""
    raw = (os.environ.get(ENV_KEY) or "").strip()
    if raw not in _cache:
        _cache[raw] = frozenset(v.strip() for v in raw.split(",") if v.strip())
    return _cache[raw]


def mask_features_for_view(view_name: str) -> Tuple[str, ...]:
    """该视图内需要置零的哈希依赖特征 id；视图未启用时返回空元组。"""
    if view_name not in enabled_views():
        return ()
    return HASH_DEPENDENT_FEATURES


def apply_view_mask(
    view_name: str,
    available_ids: Sequence[str],
    parts: Sequence[np.ndarray],
) -> Tuple[List[np.ndarray], List[str]]:
    """把 parts 中属于哈希依赖特征的段整段置零。

    参数
    ----
    view_name      视图名（V6_opcode_stat 等）
    available_ids  parts 对应的特征 id 列表（顺序与 parts 一致）
    parts          各特征的一维数组

    返回
    ----
    (新 parts, 被掩码的特征 id 列表)；未启用时原样返回。
    """
    targets = mask_features_for_view(view_name)
    if not targets:
        return list(parts), []

    masked: List[str] = []
    new_parts: List[np.ndarray] = []
    for fid, arr in zip(available_ids, parts):
        if fid in targets:
            masked.append(fid)
            new_parts.append(np.zeros_like(arr))
        else:
            new_parts.append(arr)
    return new_parts, masked


def _self_test() -> None:
    ids = ["D02", "D03", "D04", "D05", "D06"]
    parts = [np.ones(256), np.ones(256), np.full(15, 7.0), np.full(12, 3.0), np.full(10, 5.0)]
    row0 = np.concatenate(parts)

    os.environ.pop(ENV_KEY, None)
    parts1, masked1 = apply_view_mask("V6_opcode_stat", ids, parts)
    assert masked1 == [] and np.array_equal(np.concatenate(parts1), row0), "关闭时不应掩码"

    os.environ[ENV_KEY] = "V6_opcode_stat"
    parts2, masked2 = apply_view_mask("V6_opcode_stat", ids, parts)
    row2 = np.concatenate(parts2)
    assert masked2 == ["D02", "D03"], f"掩码特征不正确: {masked2}"
    assert row2.shape == row0.shape, "掩码不得改变维度"
    assert row2[:512].sum() == 0, "D02/D03 应被置零"
    assert row2[512:].sum() == row0[512:].sum(), "D04/D05/D06 应保持原值"
    assert np.array_equal(row2[512:], row0[512:]), "D04/D05/D06 不应被改动"

    parts3, masked3 = apply_view_mask("V6_opcode_seq", ["D01"], [np.ones(4096)])
    assert masked3 == [] and parts3[0].sum() == 4096, "未启用的视图不应被掩码"

    parts4, masked4 = apply_view_mask("V6_func_embed", ["D07"], [np.ones(6144)])
    assert masked4 == [] and parts4[0].sum() == 6144, "未启用的视图不应被掩码"

    os.environ[ENV_KEY] = "V6_opcode_seq,V6_func_embed"
    assert apply_view_mask("V6_opcode_seq", ["D01"], [np.ones(4096)])[1] == ["D01"]
    assert apply_view_mask("V6_func_embed", ["D07"], [np.ones(6144)])[1] == ["D07"]

    os.environ.pop(ENV_KEY, None)
    print("view_masking self-test: OK")


if __name__ == "__main__":
    _self_test()
