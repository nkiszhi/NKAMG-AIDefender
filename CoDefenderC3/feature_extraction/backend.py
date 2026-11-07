# -*- coding: utf-8 -*-
"""后端调度：按配置选 BN / SMDA，把 PE 变成 ProgramIR。

两个"档位"（profile）
--------------------
同一个 PE 在不同用途下需要**不同深度的分析**：

=============  ==========================  ==============================
profile        用途                        BN 分析模式
=============  ==========================  ==============================
"features"     D01-D07 / E03-E04           basic（线性扫描，快）
"graph"        MalGraph 的 CFG / FCG      full（要算 MLIL 才能还原调用边）
=============  ==========================  ==============================

⚠ 两档的 IR **不能混用**：basic 档下 BN 不会为大多数函数算 MLIL
  （实测 521/612 个函数 mlil 为 None），拿它做 FCG 会得到空调用图。

后端选择
--------
环境变量 CODEFENDER_DISASM_BACKEND：bn（默认）/ smda。

选择 SMDA 时**不会 import binaryninja** —— 这是"把 BN 依赖彻底切掉"的关键。

2026-11-07
"""
from __future__ import annotations

import os


def _env_backend() -> str:
    raw = (os.environ.get("CODEFENDER_DISASM_BACKEND") or "bn").strip().lower()
    return raw if raw in ("bn", "smda") else "bn"


def current_backend() -> str:
    """当前后端名（"bn" / "smda"）。"""
    return _env_backend()


def build_ir_for_features(path: str):
    """PE → ProgramIR（features 档：D01-D07 / E03-E04）。"""
    be = _env_backend()
    if be == "smda":
        from .backend_smda import build_ir
        return build_ir(path, with_calls=False)
    from .backend_bn import build_ir_from_path
    return build_ir_from_path(path, analysis="basic")


def build_ir_for_graph(path: str):
    """PE → ProgramIR（graph 档：MalGraph 的 CFG/FCG，含 call_sites）。"""
    be = _env_backend()
    if be == "smda":
        from .backend_smda import build_ir
        return build_ir(path, with_calls=True)
    from .backend_bn import build_ir_from_path
    return build_ir_from_path(path, analysis="full")
