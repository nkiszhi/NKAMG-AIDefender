# -*- coding: utf-8 -*-
"""确定性哈希工具：统一 SMDA / fast / BN 三条特征提取路径的编码口径。

为什么要统一
------------
Python 内置 ``hash()`` 对 ``str`` 是**每进程随机**的（未设置 ``PYTHONHASHSEED`` 时，
进程启动时随机取种子）。于是：

    训练进程 A: hash("CreateFileA") = 137  →  A06[137] += 1
    推理进程 B: hash("CreateFileA") = 42   →  A06[42]  += 1

模型在训练时学到"A06 第 137 号桶 = CreateFileA"，推理时 CreateFileA 跑到了 42 号桶，
这一维的权重完全指向错误语义 —— 而且**永远修不好**，因为训练期的映射已不可复现。

本模块统一用 ``zlib.crc32``（确定性、跨进程/跨机器/跨 Python 版本一致），
使"同名 → 同桶"在训练与推理之间、以及 SMDA 与 BN 两条后端之间都成立。

注意：改成 crc32 等于**给特征重新编号**，旧权重随之作废，需要重训。
"""
from __future__ import annotations

import zlib

__all__ = ["stable_bucket", "stable_hash", "stable_seed"]


def stable_bucket(text: str, modulo: int) -> int:
    """把字符串确定性地映射到 [0, modulo) 的桶号。

    参数
    ----
    text    待映射的字符串（助记符 / API 名 / 字符串 / n-gram 片段）
    modulo  桶数，必须为正

    返回
    ----
    int  桶号。相同输入在任何进程、任何机器上都返回相同结果。
    """
    if modulo <= 0:
        raise ValueError("modulo must be positive, got %r" % (modulo,))
    return zlib.crc32(text.encode("utf-8", "ignore")) % modulo


def stable_hash(value) -> int:
    """test_lm-compatible CRC32; the original main stable_bucket is unchanged."""
    if isinstance(value, str):
        data = value.encode("utf-8", "ignore")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
    else:
        data = str(value).encode("utf-8", "ignore")
    return zlib.crc32(data) & 0xFFFFFFFF


def stable_seed(value) -> int:
    return stable_hash(value) & 0x7FFFFFFF
