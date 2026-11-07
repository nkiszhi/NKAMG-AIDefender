# -*- coding: utf-8 -*-
"""MalGraph 图特征的跨后端对比 / BN 等价性验证。

两个子命令：

``bn-equivalence``
    **等价性判据（最重要）**：把「BN 直读实现」（本文件里逐行保留的旧版
    extract_cfg_and_fcg）与「BN → ProgramIR → graph_from_ir」两条路径的结果
    逐字段比对，必须**完全一致**。不一致就说明这次重构改了行为。

``compare``
    跨后端对比：BN-IR vs SMDA-IR 的 MalGraph 特征差异报告
    （函数数 / FCG 边数 / 11 维块特征的逐维差异 / 外部函数名重合度）。

用法：

    python tests/compare_malgraph_backends.py bn-equivalence \\
        --samples D:\\VM_Share\\CoDefenderC3_v9\\_pe_ascii

    python tests/compare_malgraph_backends.py compare \\
        --samples D:\\VM_Share\\CoDefenderC3_v9\\_pe_ascii

BN 相关子命令需要能联网（BinaryNinja 的许可在线校验）。

2026-11-07
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ══════════════════════════════════════════════════════════════════════
# 旧版实现（逐行保留，作为等价性判据的参照物）
# ══════════════════════════════════════════════════════════════════════
def _legacy_extract_cfg_and_fcg(file_path, vocab_dict, include_tailcall=True, bv=None):
    """**旧版** MalGraph 特征提取（直接读 BinaryNinja）。

    这份代码是从 models/MalGraph_2022/utils.py 原样搬过来的参照实现，
    不要"顺手优化" —— 一旦改了，就失去了等价性判据的意义。
    """
    try:
        from feature_extraction.bn_runtime import ensure_binaryninja
        ensure_binaryninja()
        from binaryninja import (BinaryViewType, SymbolType,
                                 MediumLevelILOperation)
        import hashlib

        file_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)
        file_hash = file_hash.hexdigest()

        if bv is None:
            bv = BinaryViewType["PE"].open(file_path)
            if not bv:
                raise ValueError(f"无法打开文件：{file_path}")
            bv.update_analysis_and_wait()

        for extern_func in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol):
            if extern_func.name in vocab_dict:
                vocab_dict[extern_func.name] = vocab_dict[extern_func.name] + 1
            else:
                vocab_dict[extern_func.name] = 1

        local_functions = list(bv.functions)
        external_functions = [
            sym.name for sym in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol)
        ]

        local_function_count = len(local_functions)
        total_function_count = local_function_count + len(external_functions)

        function_edges = [[], []]

        function_index = {}
        for idx, func in enumerate(local_functions):
            function_index[func.start] = idx
        for idx, name in enumerate(external_functions):
            function_index[name] = idx + local_function_count
        external_symbols = bv.get_symbols_of_type(SymbolType.ImportAddressSymbol)
        import_address_map = {sym.address: sym.name for sym in external_symbols}

        for func in local_functions:
            caller_idx = function_index[func.start]
            for block in func.mlil:
                for instr in block:
                    _op = instr.operation
                    _is_call = (_op == MediumLevelILOperation.MLIL_CALL)
                    if include_tailcall:
                        _is_call = _is_call or (_op ==
                                                MediumLevelILOperation.MLIL_TAILCALL)
                    if _is_call:
                        dest = instr.dest
                        callee_idx = None
                        if dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                            call_address = dest.constant
                            if call_address in function_index:
                                callee_idx = function_index[call_address]
                            elif call_address in import_address_map:
                                callee_name = import_address_map[call_address]
                                callee_idx = function_index[callee_name]
                        elif dest.operation == MediumLevelILOperation.MLIL_IMPORT:
                            symbol = bv.get_symbol_at(instr.address)
                            if symbol and symbol.name in function_index:
                                callee_idx = function_index[symbol.name]
                        else:
                            continue

                        if callee_idx is not None:
                            function_edges[0].append(caller_idx)
                            function_edges[1].append(callee_idx)

        acfg_list = []
        for func in local_functions:
            cfg_data = {
                "block_number": len(func.basic_blocks),
                "block_edges": [[], []],
                "block_features": []
            }
            block_map = {block: idx for idx, block in enumerate(func.basic_blocks)}
            for block in func.basic_blocks:
                feature_counts = {
                    "call": 0, "transfer": 0, "arithmetic": 0, "logic": 0,
                    "compare": 0, "move": 0, "termination": 0,
                    "data_declaration": 0, "total_instructions": 0,
                    "constants": 0,
                }
                for instr in block.disassembly_text:
                    if hasattr(instr, "tokens"):
                        feature_counts["total_instructions"] += 1
                        for token in instr.tokens:
                            if token.text in ["call"]:
                                feature_counts["call"] += 1
                            elif token.text in ["jmp", "jz", "jnz", "je", "jne"]:
                                feature_counts["transfer"] += 1
                            elif token.text in ["add", "sub", "mul", "div"]:
                                feature_counts["arithmetic"] += 1
                            elif token.text in ["and", "or", "xor"]:
                                feature_counts["logic"] += 1
                            elif token.text in ["cmp"]:
                                feature_counts["compare"] += 1
                            elif token.text in ["mov"]:
                                feature_counts["move"] += 1
                            elif token.text in ["ret", "hlt"]:
                                feature_counts["termination"] += 1
                            elif token.text in ["db", "dw", "dd"]:
                                feature_counts["data_declaration"] += 1
                            elif token.type.name in ["IntegerToken", "StringToken"]:
                                feature_counts["constants"] += 1

                offspring_count = len(block.outgoing_edges)
                block_features = [
                    feature_counts["call"], feature_counts["transfer"],
                    feature_counts["arithmetic"], feature_counts["logic"],
                    feature_counts["compare"], feature_counts["move"],
                    feature_counts["termination"],
                    feature_counts["data_declaration"],
                    feature_counts["total_instructions"],
                    feature_counts["constants"], offspring_count,
                ]
                cfg_data["block_features"].append(block_features)
                for edge in block.outgoing_edges:
                    src_idx = block_map.get(block)
                    dst_idx = block_map.get(edge.target)
                    if src_idx is not None and dst_idx is not None:
                        cfg_data["block_edges"][0].append(src_idx)
                        cfg_data["block_edges"][1].append(dst_idx)
            acfg_list.append(cfg_data)

        return {
            "function_edges": function_edges,
            "acfg_list": acfg_list,
            "function_names": [func.name for func in local_functions] + external_functions,
            "function_number": total_function_count,
            "hash": file_hash,
        }
    except Exception as e:
        print(f"处理文件时出错：{e}")
        return None



# ══════════════════════════════════════════════════════════════════════
# 新实现（IR 路径）
# ══════════════════════════════════════════════════════════════════════
def _ir_extract_cfg_and_fcg(file_path, vocab_dict, backend="bn"):
    """IR 路径：PE → ProgramIR → MalGraph 特征。"""
    from feature_extraction.backend import build_ir_for_graph
    from models.MalGraph_2022.graph_from_ir import extract_cfg_and_fcg_from_ir
    import hashlib

    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    ir = build_ir_for_graph(file_path)
    res = extract_cfg_and_fcg_from_ir(ir, vocab_dict)
    res["hash"] = h.hexdigest()
    return res


def _sample_list(args):
    files = sorted(glob.glob(os.path.join(args.samples, "*.bin")))
    files += sorted(glob.glob(os.path.join(args.samples, "*.exe")))
    if args.limit:
        files = files[:args.limit]
    return files


def _diff_features(old, new):
    """逐维对比 11 维块特征。返回 (维度名, old_sum, new_sum, absdiff_sum)。"""
    names = ["call", "transfer", "arithmetic", "logic", "compare", "move",
             "termination", "data_decl", "total_ins", "constants", "offspring"]
    n = min(len(old), len(new))
    sums_old = [0] * 11
    sums_new = [0] * 11
    for i in range(n):
        fo = old[i]
        fn = new[i]
        for d in range(11):
            sums_old[d] += fo[d]
            sums_new[d] += fn[d]
    return names, sums_old, sums_new


def _dim_mismatches(a, b):
    """逐块逐维比对两份 acfg_list，返回 {(函数号, 块号, 维度号)} 的差异集合。"""
    out = set()
    if len(a) != len(b):
        return {(-1, -1, -1)}
    for fi, (ao, an) in enumerate(zip(a, b)):
        fo = ao["block_features"]
        fn = an["block_features"]
        if len(fo) != len(fn):
            out.add((fi, -1, -1))
            continue
        for bi, (x, y) in enumerate(zip(fo, fn)):
            for d in range(11):
                if x[d] != y[d]:
                    out.add((fi, bi, d))
    return out


def cmd_bn_equivalence(args):
    """BN 直读 vs BN→IR→graph_from_ir：必须逐字段一致。

    ⚠ 关键：**两条路径必须跑在同一个 BinaryView 上**。
      BN 的「PE → 实时分析」本身是不确定的（多线程分析 / 函数发现顺序 /
      机器负载），同一文件两次打开可能得到不同的反汇编。

    ⚠ 还有一个更隐蔽的坑：BN 在**同一个 view 上重复渲染**时，
      「地址操作数」有时渲染成 IntegerToken（算常量）、有时渲染成
      代码符号（不算常量）——取决于 BN 内部惰性分析的状态。
      实测：旧实现自己跑两遍，constants 维度就有 3~1024 个块不一致。
      所以判据不能是"逐位相同"，而是：

        · 旧实现跑两遍都不同的维度 → 判定为「BN 自身不稳定」，不计入失败
        · 旧实现跑两遍相同的维度 → 新实现必须完全一致

    结构类字段（函数数 / 函数名 / FCG 边 / 块数 / 块边）要求**完全一致**。
    """
    from feature_extraction.bn_runtime import ensure_binaryninja
    ensure_binaryninja()
    import binaryninja as bn
    from feature_extraction.backend_bn import build_ir
    from models.MalGraph_2022.graph_from_ir import extract_cfg_and_fcg_from_ir

    files = _sample_list(args)
    if not files:
        print("没有样本: %s" % args.samples)
        return 2
    n_ok = 0
    n_bad = 0
    n_skip = 0
    bad = []
    tot_unstable = 0
    tot_real = 0
    names11 = ["call", "transfer", "arithmetic", "logic", "compare", "move",
               "termination", "data_decl", "total_ins", "constants", "offspring"]
    for i, path in enumerate(files, 1):
        name = os.path.basename(path)
        try:
            bv = bn.load(path)
            bv.update_analysis_and_wait()
        except Exception as e:
            print("[eq] %3d/%d SKIP %-28s 打不开: %s" % (i, len(files), name[:28], e))
            n_skip += 1
            continue

        v1 = {}
        L1 = _legacy_extract_cfg_and_fcg(path, v1, bv=bv)
        runs = [L1]
        for _k in range(max(1, args.legacy_runs - 1)):
            runs.append(_legacy_extract_cfg_and_fcg(path, {}, bv=bv))
        L2 = runs[1] if len(runs) > 1 else L1
        if any(r is None for r in runs):
            # 旧实现会因为某个函数 mlil 为 None 直接抛异常 → 整份样本返回 None。
            # 新实现跳过该函数继续（这是**改进**，不是回归）。
            print("[eq] %3d/%d SKIP %-28s 旧实现自身失败（mlil=None 等），无法比对"
                  % (i, len(files), name[:28]))
            n_skip += 1
            continue
        v_new = {}
        try:
            ir = build_ir(bv, with_calls=True)
            NEW = extract_cfg_and_fcg_from_ir(ir, v_new)
        except Exception as e:
            print("[eq] %3d/%d FAIL %-28s 新实现异常: %s" % (i, len(files), name[:28], e))
            n_bad += 1
            bad.append(name)
            continue

        diffs = []
        if L1["function_number"] != NEW["function_number"]:
            diffs.append("function_number %d != %d"
                         % (L1["function_number"], NEW["function_number"]))
        if L1["function_names"] != NEW["function_names"]:
            diffs.append("function_names 不同（%d vs %d 项）"
                         % (len(L1["function_names"]), len(NEW["function_names"])))
        if L1["function_edges"] != NEW["function_edges"]:
            diffs.append("function_edges 不同（%d vs %d 条）"
                         % (len(L1["function_edges"][0]),
                            len(NEW["function_edges"][0])))
        if len(L1["acfg_list"]) != len(NEW["acfg_list"]):
            diffs.append("acfg_list 长度不同（%d vs %d）"
                         % (len(L1["acfg_list"]), len(NEW["acfg_list"])))
        else:
            for fi, (ao, an) in enumerate(zip(L1["acfg_list"], NEW["acfg_list"])):
                if ao["block_number"] != an["block_number"]:
                    diffs.append("func#%d block_number %d != %d"
                                 % (fi, ao["block_number"], an["block_number"]))
                    break
                if ao["block_edges"] != an["block_edges"]:
                    diffs.append("func#%d block_edges 不同" % fi)
                    break
        if v1 != v_new:
            diffs.append("vocab_dict 不同（%d vs %d 项）" % (len(v1), len(v_new)))

        # 维度级：先扣掉「BN 自身不稳定」的部分
        unstable = set()
        for _a in range(len(runs)):
            for _b in range(_a + 1, len(runs)):
                unstable |= _dim_mismatches(runs[_a]["acfg_list"],
                                           runs[_b]["acfg_list"])
        real = _dim_mismatches(L1["acfg_list"], NEW["acfg_list"])
        real = {x for x in real if x not in unstable}
        tot_unstable += len(unstable)
        tot_real += len(real)
        if real:
            by_dim = {}
            for (_fi, _bi, d) in real:
                by_dim[names11[d] if d >= 0 else "?"] = by_dim.get(
                    names11[d] if d >= 0 else "?", 0) + 1
            diffs.append("块特征维度不一致（已排除 BN 自身不稳定项）: %s"
                         % ", ".join("%s×%d" % (k, v) for k, v in by_dim.items()))

        if diffs:
            n_bad += 1
            bad.append(name)
            print("[eq] %3d/%d FAIL %-28s %s" % (i, len(files), name[:28],
                                                 "; ".join(diffs)))
        else:
            n_ok += 1
            print("[eq] %3d/%d OK   %-28s funcs=%d edges=%d blocks=%d"
                  % (i, len(files), name[:28], NEW["function_number"],
                     len(NEW["function_edges"][0]),
                     sum(len(a["block_features"]) for a in NEW["acfg_list"])))
        try:
            bv.file.close()
        except Exception:
            pass

    print("")
    print("等价性: %d 个一致 / %d 个不一致 / %d 个跳过" % (n_ok, n_bad, n_skip))
    print("BN 自身不稳定（同一 view 跑两遍就不一致）的块×维: %d" % tot_unstable)
    print("扣除不稳定项后，新实现与旧实现的不一致: %d" % tot_real)
    if n_bad:
        print("结论: FAIL —— IR 路径与旧 BN 直读实现不等价")
        for b in bad[:10]:
            print("   - %s" % b)
        return 1
    print("结论: OK —— 同一 BinaryView 上，IR 路径与旧 BN 直读实现逐字段一致")
    return 0

def cmd_compare(args):
    """BN-IR vs SMDA-IR 的 MalGraph 特征差异报告。"""
    files = _sample_list(args)
    if not files:
        print("没有样本: %s" % args.samples)
        return 2
    from feature_extraction.backend_bn import build_ir_from_path as bn_ir
    from feature_extraction.backend_smda import build_ir as smda_ir
    from models.MalGraph_2022.graph_from_ir import extract_cfg_and_fcg_from_ir

    agg = {
        "n": 0, "bn_funcs": 0, "smda_funcs": 0,
        "bn_edges": 0, "smda_edges": 0,
        "bn_blocks": 0, "smda_blocks": 0,
        "ext_overlap": [], "ext_bn": 0, "ext_smda": 0,
    }
    dim_bn = [0] * 11
    dim_smda = [0] * 11
    for i, path in enumerate(files, 1):
        name = os.path.basename(path)
        try:
            ir_b = bn_ir(path, analysis="full")
            r_b = extract_cfg_and_fcg_from_ir(ir_b, {})
        except Exception as e:
            print("[cmp] %3d/%d BN 失败 %s: %s" % (i, len(files), name[:24], e))
            continue
        try:
            ir_s = smda_ir(path, with_calls=True)
            r_s = extract_cfg_and_fcg_from_ir(ir_s, {})
        except Exception as e:
            print("[cmp] %3d/%d SMDA 失败 %s: %s" % (i, len(files), name[:24], e))
            continue

        ext_b = set(r_b["function_names"][len(r_b["acfg_list"]):])
        ext_s = set(r_s["function_names"][len(r_s["acfg_list"]):])
        agg["n"] += 1
        agg["bn_funcs"] += r_b["function_number"]
        agg["smda_funcs"] += r_s["function_number"]
        agg["bn_edges"] += len(r_b["function_edges"][0])
        agg["smda_edges"] += len(r_s["function_edges"][0])
        agg["bn_blocks"] += sum(len(a["block_features"]) for a in r_b["acfg_list"])
        agg["smda_blocks"] += sum(len(a["block_features"]) for a in r_s["acfg_list"])
        agg["ext_bn"] += len(ext_b)
        agg["ext_smda"] += len(ext_s)
        inter = len(ext_b & ext_s)
        union = len(ext_b | ext_s) or 1
        agg["ext_overlap"].append(inter / float(union))
        sb = [sum(bf[d] for a in r_b["acfg_list"] for bf in a["block_features"])
              for d in range(11)]
        ss = [sum(bf[d] for a in r_s["acfg_list"] for bf in a["block_features"])
              for d in range(11)]
        for d in range(11):
            dim_bn[d] += sb[d]
            dim_smda[d] += ss[d]
        print("[cmp] %3d/%d %-24s BN(funcs=%d edges=%d blocks=%d ext=%d) "
              "SMDA(funcs=%d edges=%d blocks=%d ext=%d) Jaccard=%.3f"
              % (i, len(files), name[:24], r_b["function_number"],
                 len(r_b["function_edges"][0]), agg["bn_blocks"], len(ext_b),
                 r_s["function_number"], len(r_s["function_edges"][0]),
                 agg["smda_blocks"], len(ext_s), inter / float(union)))

    if not agg["n"]:
        print("没有可对比的样本")
        return 1
    names = ["call", "transfer", "arithmetic", "logic", "compare", "move",
             "termination", "data_decl", "total_ins", "constants", "offspring"]
    print("")
    print("=== 汇总（%d 个样本）===" % agg["n"])
    print("函数数     BN %d   SMDA %d   (%.1f%%)"
          % (agg["bn_funcs"], agg["smda_funcs"],
             100.0 * agg["smda_funcs"] / max(agg["bn_funcs"], 1)))
    print("FCG 边     BN %d   SMDA %d   (%.1f%%)"
          % (agg["bn_edges"], agg["smda_edges"],
             100.0 * agg["smda_edges"] / max(agg["bn_edges"], 1)))
    print("基本块     BN %d   SMDA %d   (%.1f%%)"
          % (agg["bn_blocks"], agg["smda_blocks"],
             100.0 * agg["smda_blocks"] / max(agg["bn_blocks"], 1)))
    if agg["ext_overlap"]:
        print("外部函数名 Jaccard 平均 %.3f（BN %d / SMDA %d）"
              % (sum(agg["ext_overlap"]) / len(agg["ext_overlap"]),
                 agg["ext_bn"], agg["ext_smda"]))
    print("")
    print("11 维块特征总量对比：")
    print("  %-12s %12s %12s %8s" % ("维度", "BN", "SMDA", "差异%"))
    for d in range(11):
        b = dim_bn[d]
        m = dim_smda[d]
        print("  %-12s %12d %12d %8s"
              % (names[d], b, m,
                 ("%+.1f%%" % (100.0 * (m - b) / b)) if b else ("n/a")))
    return 0




# ══════════════════════════════════════════════════════════════════════
# 函数发现质量（prologue 覆盖率）
# ══════════════════════════════════════════════════════════════════════
# 为什么要这个指标
# ----------------
# 只比"函数个数"会被 BN 的**线性扫描**骗：BN 会把 .text 里的数据区域也
# 扫成函数（实测某个良性样本：BN 280 个函数里只有 7 个带正常序言，
# 其余全是把数据字节当指令解出来的噪声）。
#
# 而 SMDA 走递归下降 + 序言打分，没有入口点就几乎什么都找不到 ——
# 于是"BN 280 / SMDA 6"看起来像 SMDA 覆盖率崩了，其实是 BN 在造噪声。
#
# 客观判据：**函数入口处有没有常见序言**（push ebp; mov ebp,esp /
# sub rsp,imm8 / push rbx; sub rsp,imm8 ...）。
# 用 SMDA 自带的 COMMON_PROLOGUES 打分表（smda/intel/definitions.py），
# 分数 >= 30 视为"像真函数"。

_PROLOGUE_MIN_SCORE = 30


def _va_reader(pe_path):
    """返回一个 VA → 原始字节的读取器（按 PE 节映射）。"""
    import pefile
    pe = pefile.PE(pe_path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    segs = [(base + s.VirtualAddress, s.get_data()) for s in pe.sections]
    pe.close()

    def read(va, n=16):
        for lo, data in segs:
            if lo <= va < lo + len(data):
                off = va - lo
                return data[off:off + n]
        return b""
    return read


def _prologue_score(read, va, bits):
    """用 SMDA 的序言表给函数入口打分（0 = 不像函数入口）。"""
    try:
        from smda.intel.definitions import COMMON_PROLOGUES
    except Exception:
        return 0
    w = read(va, 16)
    if not w:
        return 0
    if w[:4] == b"\xf3\x0f\x1e\xfa":       # endbr64 (CET 落地垫)
        w = w[4:]
    best = 0
    for _length, per_bitness in COMMON_PROLOGUES.items():
        for pat, sc in (per_bitness.get(bits) or {}).items():
            if w[:len(pat)] == pat and sc > best:
                best = sc
    return best


def cmd_coverage(args):
    """BN vs SMDA 的函数发现质量对比（序言覆盖率）。"""
    from feature_extraction.backend_bn import build_ir_from_path as bn_ir
    from feature_extraction.backend_smda import build_ir as smda_ir

    files = _sample_list(args)
    if not files:
        print("没有样本: %s" % args.samples)
        return 2

    tot = {"bn": 0, "bn_strong": 0, "smda": 0, "smda_strong": 0, "common": 0}
    print("%-26s %-18s %-18s %s" % ("sample", "BN 总/序言", "SMDA 总/序言", "交集"))
    for i, path in enumerate(files, 1):
        name = os.path.basename(path)
        try:
            ir_b = bn_ir(path, analysis="full")
            ir_s = smda_ir(path, with_calls=True)
        except Exception as e:
            print("[cov] %3d/%d SKIP %-24s %s" % (i, len(files), name[:24], e))
            continue
        bits = 64 if int(ir_b.bitness or 0) == 64 else 32
        read = _va_reader(path)
        sb = {int(f.start) for f in ir_b.functions}
        ss = {int(f.start) for f in ir_s.functions}
        bs = sum(1 for a in sb if _prologue_score(read, a, bits) >= _PROLOGUE_MIN_SCORE)
        ss_s = sum(1 for a in ss if _prologue_score(read, a, bits) >= _PROLOGUE_MIN_SCORE)
        common = len(sb & ss)
        tot["bn"] += len(sb)
        tot["bn_strong"] += bs
        tot["smda"] += len(ss)
        tot["smda_strong"] += ss_s
        tot["common"] += common
        print("[cov] %3d/%d %-26s %5d/%5d (%4.1f%%)  %5d/%5d (%4.1f%%)  %5d"
              % (i, len(files), name[:26], len(sb), bs,
                 100.0 * bs / max(len(sb), 1),
                 len(ss), ss_s, 100.0 * ss_s / max(len(ss), 1), common))

    print("")
    print("=== 汇总 ===")
    print("函数总数     BN %6d   SMDA %6d   (%.1f%%)"
          % (tot["bn"], tot["smda"], 100.0 * tot["smda"] / max(tot["bn"], 1)))
    print("带序言的函数 BN %6d   SMDA %6d   (%.1f%%)"
          % (tot["bn_strong"], tot["smda_strong"],
             100.0 * tot["smda_strong"] / max(tot["bn_strong"], 1)))
    print("  → BN 的序言占比 %.1f%%，SMDA %.1f%%"
          % (100.0 * tot["bn_strong"] / max(tot["bn"], 1),
             100.0 * tot["smda_strong"] / max(tot["smda"], 1)))
    print("函数起点交集 %6d" % tot["common"])
    return 0
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["bn-equivalence", "compare", "coverage"])
    ap.add_argument("--samples", required=True, help="样本目录")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--legacy-runs", type=int, default=3,
                    help="旧实现在同一个 view 上跑几遍（用来度量 BN 自身的不稳定度）")
    args = ap.parse_args()
    if args.cmd == "bn-equivalence":
        return cmd_bn_equivalence(args)
    if args.cmd == "coverage":
        return cmd_coverage(args)
    return cmd_compare(args)


if __name__ == "__main__":
    sys.exit(main())
