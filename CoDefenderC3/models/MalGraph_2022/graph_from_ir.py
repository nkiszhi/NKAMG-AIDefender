# -*- coding: utf-8 -*-
"""IR → MalGraph 图特征（CFG/ACFG + FCG）。

本模块把 MalGraph 从 BinaryNinja 里彻底解耦出来：

    PE ──▶ ProgramIR（backend_bn / backend_smda）──▶ 本模块 ──▶ MalGraph 特征

与旧实现（utils.py::extract_cfg_and_fcg、build_malgraph_cache_fast.py 里那份
副本）**逐项等价**：

* 11 维块特征的维度顺序、口径完全不变；
* FCG 边的构造规则（本地函数 / 导入函数 / 间接调用）完全不变；
* 外部函数名词表的统计口径不变。

块特征 11 维（顺序固定）::

    [call, transfer, arithmetic, logic, compare, move, termination,
     data_declaration, total_instructions, constants, offspring_count]

对应关系（IR 字段 → 旧实现的 token 统计）：

===============  ======================================================
IR               旧实现（BN token 统计）
===============  ======================================================
keywords         块内"关键字 token"序列（逐 token 匹配操作码类别）
constant_count   块内**非关键字**的 IntegerToken + StringToken 个数
instructions     每行反汇编的渲染助记符（只用来数 total_instructions）
outgoing_count   len(block.outgoing_edges)
===============  ======================================================

⚠ 为什么要有 keywords 这个字段：旧实现是"逐 token 按优先级 elif 匹配"，
  所以一个文本恰好是关键字的 token 会被算进它的类别，而不是算成常量。
  例如 BN 渲染的 je 指令后面若带注解 { "or" }，那个 "or" 是 StringToken，
  旧实现会把它算成一次 logic。把关键字序列搬进 IR，才能 1:1 复刻。

2026-11-07
"""
from __future__ import annotations

# 助记符分类集合（与旧实现里的 token 匹配列表一一对应）
CALL_TOK = {"call"}
TRANSFER_TOK = {"jmp", "jz", "jnz", "je", "jne"}
ARITHMETIC_TOK = {"add", "sub", "mul", "div"}
LOGIC_TOK = {"and", "or", "xor"}
COMPARE_TOK = {"cmp"}
MOVE_TOK = {"mov"}
TERMINATION_TOK = {"ret", "hlt"}
DATA_DECLARATION_TOK = {"db", "dw", "dd"}


def block_feature_vector(block):
    """一个基本块的 11 维特征。

    维度顺序与旧实现完全一致（MalGraph 的第一层 GCN 直接吃这个向量）。
    """
    call = transfer = arithmetic = logic = compare = move = 0
    termination = data_decl = 0
    # 优先用 IR 里的关键字 token 序列（与旧实现 1:1）。
    # 老 IR 文件没有这个字段时，退回"按渲染助记符统计"（对 BN 后端等价）。
    if block.keywords:
        for kw in block.keywords:
            if kw in CALL_TOK:
                call += 1
            elif kw in TRANSFER_TOK:
                transfer += 1
            elif kw in ARITHMETIC_TOK:
                arithmetic += 1
            elif kw in LOGIC_TOK:
                logic += 1
            elif kw in COMPARE_TOK:
                compare += 1
            elif kw in MOVE_TOK:
                move += 1
            elif kw in TERMINATION_TOK:
                termination += 1
            elif kw in DATA_DECLARATION_TOK:
                data_decl += 1
    else:
        for m in block.instructions:
            if m in CALL_TOK:
                call += 1
            elif m in TRANSFER_TOK:
                transfer += 1
            elif m in ARITHMETIC_TOK:
                arithmetic += 1
            elif m in LOGIC_TOK:
                logic += 1
            elif m in COMPARE_TOK:
                compare += 1
            elif m in MOVE_TOK:
                move += 1
            elif m in TERMINATION_TOK:
                termination += 1
            elif m in DATA_DECLARATION_TOK:
                data_decl += 1
    return [
        call, transfer, arithmetic, logic, compare, move, termination,
        data_decl,
        len(block.instructions),      # total_instructions
        int(block.constant_count),    # constants
        int(block.outgoing_count),    # offspring_count
    ]


def extract_cfg_and_fcg_from_ir(ir, vocab_dict=None):
    """从 ProgramIR 构造 MalGraph 的图特征。

    Args:
        ir:         ProgramIR（必须是含 call_sites / external_symbols 的
                    "graph" 档位 IR）
        vocab_dict: 外部函数名 → 出现次数的累加字典（训练时统计词表用）；
                     传 None 则不统计

    Returns:
        dict: {function_edges, acfg_list, function_names, function_number}
    """
    if vocab_dict is None:
        vocab_dict = {}

    local_functions = list(ir.functions)
    external_functions = [n for (_a, n) in ir.external_symbols]

    # 外部函数词表统计（与旧实现一致：每个导入符号记一次）
    for name in external_functions:
        vocab_dict[name] = vocab_dict.get(name, 0) + 1

    n_local = len(local_functions)
    total_function_count = n_local + len(external_functions)

    # 函数索引映射：本地函数用起始地址，外部函数用名字
    # （与旧实现 function_index 的构造一致）
    function_index = {}
    for idx, f in enumerate(local_functions):
        function_index[int(f.start)] = idx
    for idx, name in enumerate(external_functions):
        function_index[name] = idx + n_local

    # ── FCG：函数调用边 ──────────────────────────────────────────────
    function_edges = [[], []]
    for caller_idx, f in enumerate(local_functions):
        for cs in f.call_sites:
            callee_idx = None
            if cs.kind == "func" and cs.target is not None:
                callee_idx = function_index.get(int(cs.target))
            elif cs.kind == "import" and cs.name:
                callee_idx = function_index.get(cs.name)
            if callee_idx is not None:
                function_edges[0].append(caller_idx)
                function_edges[1].append(callee_idx)

    # ── ACFG / CFG：每函数的基本块特征 + 块间边 ───────────────────────
    acfg_list = []
    for f in local_functions:
        block_index = {int(b.start): i for i, b in enumerate(f.blocks)}
        cfg_data = {
            "block_number": len(f.blocks),
            "block_edges": [[], []],
            "block_features": [],
        }
        edge_src, edge_dst = cfg_data["block_edges"]
        for b in f.blocks:
            cfg_data["block_features"].append(block_feature_vector(b))
            src_idx = block_index.get(int(b.start))
            if src_idx is None:
                continue
            for succ in b.successors:
                dst_idx = block_index.get(int(succ))
                if dst_idx is not None:
                    edge_src.append(src_idx)
                    edge_dst.append(dst_idx)
        acfg_list.append(cfg_data)

    return {
        "function_edges": function_edges,
        "acfg_list": acfg_list,
        "function_names": [f.name for f in local_functions] + external_functions,
        "function_number": total_function_count,
    }
