# -*- coding: utf-8 -*-
"""IR 版特征层：D01-D07 / E03-E04 由 ProgramIR 计算。

这是 Phase 1 的第 4 步（与 backend_bn.py 配套）。

⚠ 本文件是 extract_feature.py::_extract_disassembly / _extract_graphs 的
   等价转写：输入从 BinaryView 换成 ProgramIR，计算式逐条保持一致。
   任何「顺手优化」都会破坏「IR → 特征」与「bv → 特征」的逐位等价，
   而那正是 Phase 1 的验收判据（G2 门禁）。

常量：尺寸常量（MAX_OPCODES / NGRAM_DIM / MAX_FUNCTIONS）引用 extract_feature，
指令类别表（_CAT_LOOKUP / _CAT_NAMES）引用 insn_categories ——
两边共用同一份，避免多套后端各维护一份类别定义导致漂移。

2026-11-05
"""
from __future__ import annotations

from collections import Counter, defaultdict

try:
    from ._stable_hash import stable_hash
    from .extract_feature import MAX_FUNCTIONS, MAX_OPCODES, NGRAM_DIM
    from .insn_categories import CAT_LOOKUP as _CAT_LOOKUP
    from .insn_categories import CAT_NAMES as _CAT_NAMES
except ImportError:                                 # 直接按文件加载时的回退
    from _stable_hash import stable_hash
    from extract_feature import MAX_FUNCTIONS, MAX_OPCODES, NGRAM_DIM
    from insn_categories import CAT_LOOKUP as _CAT_LOOKUP
    from insn_categories import CAT_NAMES as _CAT_NAMES


def _call_depth_ir(fmap, start, visited, depth, max_depth):
    """IR 版调用深度。

    与 extract_feature.py::_call_depth 等价：
    · 每层最多看前 5 个 callee
    · 深度上限 10
    · visited 按起始地址去重（防环）
    · callee 查不到对应函数时不再下探
    """
    if depth >= max_depth:
        return depth
    if start is None or start in visited:
        return depth
    visited.add(start)
    max_d = depth
    f = fmap.get(start)
    if f is None:
        return max_d
    for c in list(f.callees)[:5]:
        d = _call_depth_ir(fmap, c, visited, depth + 1, max_depth)
        if d is not None:
            max_d = max(max_d, d)
    return max_d


def disassembly_features(ir) -> dict:
    """D01-D07：由 ProgramIR 计算（等价于 _extract_disassembly(bv)）。"""
    import numpy as np

    feats = {}
    all_opcodes = []
    global_opcode_counts = Counter()
    global_cat_counts = Counter()
    func_data = []
    all_bb_sizes = []
    all_bb_out_edges = []

    for f in ir.functions:
        func_ops = Counter()
        func_bb_count = 0
        for b in f.blocks:
            func_bb_count += 1
            if b.length is not None:
                all_bb_sizes.append(b.length)
            all_bb_out_edges.append(len(b.successors))
            for m in b.instructions:
                all_opcodes.append(m)
                global_opcode_counts[m] += 1
                global_cat_counts[_CAT_LOOKUP.get(m, "other")] += 1
                func_ops[m] += 1
        func_data.append({
            "ops": func_ops, "n_bbs": func_bb_count, "size": f.size,
            "n_callees": len(f.callees), "is_leaf": f.is_leaf,
            "is_recursive": f.is_recursive,
        })

    n_funcs = len(func_data)

    d01 = np.zeros(MAX_OPCODES, dtype=np.int64)
    for i, op in enumerate(all_opcodes[:MAX_OPCODES]):
        d01[i] = stable_hash(op) % 511 + 1
    feats["D01"] = d01

    d02 = np.zeros(NGRAM_DIM, dtype=np.float32)
    for i in range(len(all_opcodes) - 1):
        d02[stable_hash(all_opcodes[i] + "_" + all_opcodes[i + 1]) % NGRAM_DIM] += 1
    if d02.sum() > 0:
        d02 = np.log1p(d02); d02 /= np.linalg.norm(d02) + 1e-8
    feats["D02"] = d02

    d03 = np.zeros(NGRAM_DIM, dtype=np.float32)
    for i in range(len(all_opcodes) - 2):
        d03[stable_hash("_".join(all_opcodes[i:i + 3])) % NGRAM_DIM] += 1
    if d03.sum() > 0:
        d03 = np.log1p(d03); d03 /= np.linalg.norm(d03) + 1e-8
    feats["D03"] = d03

    d04 = np.zeros(len(_CAT_NAMES), dtype=np.float32)
    total_cat = sum(global_cat_counts.values()) or 1
    for i, cat in enumerate(_CAT_NAMES):
        d04[i] = global_cat_counts.get(cat, 0) / total_cat
    feats["D04"] = d04

    d05 = np.zeros(12, dtype=np.float32)
    d05[0] = n_funcs
    if n_funcs > 0:
        sizes = [fd["size"] for fd in func_data if fd["size"] > 0]
        if sizes:
            d05[1] = np.mean(sizes); d05[2] = np.max(sizes); d05[3] = np.std(sizes)
        bbc = [fd["n_bbs"] for fd in func_data]
        if bbc:
            d05[4] = np.mean(bbc); d05[5] = np.max(bbc)
        d05[6] = sum(1 for fd in func_data if fd["is_leaf"])
        d05[7] = sum(1 for fd in func_data if fd["is_recursive"])
        d05[8] = d05[6] / n_funcs
        d05[9] = len(all_opcodes)
        d05[10] = len(all_opcodes) / n_funcs
        d05[11] = len(global_opcode_counts)
    feats["D05"] = d05

    d06 = np.zeros(10, dtype=np.float32)
    n_bbs_total = sum(fd["n_bbs"] for fd in func_data)
    d06[0] = n_bbs_total
    if all_bb_sizes:
        d06[1] = np.mean(all_bb_sizes); d06[2] = np.max(all_bb_sizes)
        d06[3] = np.std(all_bb_sizes)
    if all_bb_out_edges:
        d06[4] = np.mean(all_bb_out_edges); d06[5] = np.max(all_bb_out_edges)
        d06[6] = sum(1 for e in all_bb_out_edges if e == 0)
        d06[7] = sum(1 for e in all_bb_out_edges if e > 1)
        d06[8] = d06[7] / max(n_bbs_total, 1)
    if all_bb_sizes:
        d06[9] = sum(all_bb_sizes) / max(n_bbs_total, 1)
    feats["D06"] = d06

    d07 = np.zeros(MAX_FUNCTIONS * 128, dtype=np.float32)
    for fi in range(min(n_funcs, MAX_FUNCTIONS)):
        emb = np.zeros(128, dtype=np.float32)
        for op, cnt in func_data[fi]["ops"].items():
            emb[stable_hash(op) % 128] += cnt
        if emb.sum() > 0:
            emb /= np.linalg.norm(emb) + 1e-8
        d07[fi * 128:(fi + 1) * 128] = emb
    feats["D07"] = d07

    return feats


def graph_features(ir) -> dict:
    """E03-E04：由 ProgramIR 计算（等价于 _extract_graphs(bv)）。"""
    import numpy as np

    feats = {}
    funcs = ir.functions
    n_funcs = len(funcs)

    cfg_nodes, cfg_edges = 0, 0
    cg_edges = 0
    cg_adj = defaultdict(set)
    func_bb_counts = []
    back_edges = 0
    leaf_funcs = 0
    recursive_funcs = 0
    out_degrees = []
    in_degree_map = defaultdict(int)

    for fi, f in enumerate(funcs):
        fstart = f.start

        n_bbs = 0
        for b in f.blocks:
            n_bbs += 1
            cfg_nodes += 1
            bb_start = b.start
            edges = b.successors
            n_edges = len(edges)
            cfg_edges += n_edges
            if fi < 100 and bb_start is not None:
                for t in edges:
                    if t is not None and t <= bb_start:
                        back_edges += 1
        func_bb_counts.append(n_bbs)

        callees_list = f.callees
        n_callees = len(callees_list)
        out_degrees.append(n_callees)
        if n_callees == 0:
            leaf_funcs += 1

        for cstart in callees_list:
            if cstart is None or fstart is None:
                continue
            cg_edges += 1
            cg_adj[fstart].add(cstart)
            in_degree_map[cstart] += 1
            if cstart == fstart:
                recursive_funcs += 1

    e03 = np.zeros(12, dtype=np.float32)
    e03[0] = cfg_nodes
    e03[1] = cfg_edges
    e03[2] = cfg_edges / max(cfg_nodes, 1)
    if func_bb_counts:
        e03[3] = max(func_bb_counts)
        e03[4] = np.mean(func_bb_counts)
        e03[5] = np.std(func_bb_counts)
    e03[6] = back_edges
    e03[7] = n_funcs
    e03[8] = cfg_nodes / max(n_funcs, 1)
    e03[9] = cfg_edges / max(n_funcs, 1)
    e03[10] = back_edges / max(n_funcs, 1)
    e03[11] = 1.0 if cfg_nodes > 0 else 0.0
    feats["E03"] = e03

    e04 = np.zeros(10, dtype=np.float32)
    e04[0] = n_funcs
    e04[1] = cg_edges
    e04[2] = cg_edges / max(n_funcs, 1)
    e04[3] = leaf_funcs / max(n_funcs, 1)
    e04[4] = recursive_funcs / max(n_funcs, 1)
    depths = []
    fmap = ir.function_map()
    for f in funcs[:50]:
        d = _call_depth_ir(fmap, f.start, set(), 0, 10)
        if d is not None:
            depths.append(d)
    e04[5] = max(depths) if depths else 0
    e04[6] = np.mean(depths) if depths else 0
    if out_degrees:
        e04[7] = max(out_degrees)
    in_degrees = list(in_degree_map.values())
    if in_degrees:
        e04[8] = max(in_degrees)
    e04[9] = len(set().union(*cg_adj.values())) if cg_adj else 0
    feats["E04"] = e04

    return feats


def all_features(ir) -> dict:
    """D01-D07 + E03-E04。"""
    feats = {}
    feats.update(disassembly_features(ir))
    feats.update(graph_features(ir))
    return feats
