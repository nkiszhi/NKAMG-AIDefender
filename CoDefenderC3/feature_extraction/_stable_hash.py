# -*- coding: utf-8 -*-
"""跨进程稳定的字符串哈希（feature hashing 专用）。

为什么不能用内置 hash()
────────────────────────
CPython 3.3+ 起 str.__hash__ 默认使用 SipHash-1-3，且**每个进程启动时
随机生成一个 secret**（来源是 PYTHONHASHSEED 环境变量，未设置则随机取）。
设计目的是防哈希表 DoS 攻击，但代价是：

    同一进程内    hash(s) 稳定
    不同进程      hash(s) 是**完全另一套映射**

这在本项目里造成实打实的特征错位：

    训练    D/E 特征在**子进程**抽取
            feature_extraction/_ir_worker.py（由 train/data_loader.py
            的 ProcessPoolExecutor 拉起，4~16 个 worker）
    推理    D/E 特征在**主进程**抽取
            engine/app.py:666 -> ext.extract_de_only()

于是同一个 PE 文件：

    训练:  D01[i] = hash("mov") % 511 + 1  ->  63
    推理:  D01[i] = hash("mov") % 511 + 1  ->  398

OpcodeLSTM 的 embedding 表里 emb[63] 训练时学的是 "mov"，推理时喂进去的却是
另一个随机槽位 —— 纯噪声。

训练集自身也不自洽：多个 worker 各有各的 seed，分多轮抽取时每轮 seed 又不同，
同一个文件在同一个数据集里对应多个互相矛盾的特征向量。

解决办法
────────
用 zlib.crc32 这种**纯函数**做哈希：跨进程 / 跨机器 / 跨 Python 版本完全
一致，不需要改任何启动脚本，性能也与内置 hash 同量级。

代价（必须知道）
----------------
**换成稳定 hash 之后，所有经过 hash 分桶的特征语义全部改变**：
A06 / C01 / C04 / D01 / D02 / D03 / D07，以及 unified.py 的 opcode_seq /
func_embed —— 对应模型**必须重训**。这是必然的：旧权重本来就是在随机映射上
训出来的，从来就没有"正确"过。

2026-11-05
"""
import zlib

__all__ = ["stable_hash", "stable_bucket", "stable_seed"]

# crc32 的结果落在 0 .. 2**32-1，本身已非负；这里再掩一次，纯属防御
_MASK32 = 0xFFFFFFFF
_MASK31 = 0x7FFFFFFF


def stable_hash(s) -> int:
    """返回跨进程稳定的非负整数哈希。

    Args:
        s: str / bytes / bytearray。str 按 UTF-8 编码（无法编码的字符丢弃）。

    Returns:
        int: 0 .. 2**32-1 的非负整数，同一输入在任何进程、任何机器上相同。
    """
    if isinstance(s, str):
        b = s.encode("utf-8", errors="ignore")
    elif isinstance(s, (bytes, bytearray, memoryview)):
        b = bytes(s)
    else:
        b = str(s).encode("utf-8", errors="ignore")
    return zlib.crc32(b) & _MASK32


def stable_bucket(s, dim: int) -> int:
    """把 s 映射到 [0, dim) 的桶号。

    Args:
        s: 待映射的值。
        dim: 桶数，必须 > 0。

    Returns:
        int: 桶号。同一 s 在任何进程上都得到同一桶号。
    """
    if dim <= 0:
        raise ValueError("dim must be positive, got %r" % (dim,))
    return stable_hash(s) % dim


def stable_seed(s) -> int:
    """返回可安全用作随机种子的 31 位非负整数。

    替代 hash(pe_path) % 2**31 这类写法 —— 后者每进程都不同，
    会让 np.random.RandomState(seed) 在每次运行里给出不同的"确定性"随机值。
    """
    return stable_hash(s) & _MASK31
