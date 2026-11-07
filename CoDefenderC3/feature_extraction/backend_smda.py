# -*- coding: utf-8 -*-
"""SMDA 后端适配器：PE → ProgramIR。

这是 SMDA 迁移 Phase 2 的核心：按 docs/IR_CONTRACT.md 的契约，产出与 backend_bn.py
同构的 ProgramIR，让特征层无需改动。

⚠ 三个必须知道的差异（BN vs SMDA）
---------------------------------
1. 地址基准：SMDA 的函数/块偏移是 RVA，BN 用虚拟地址(VA)。
   本适配器统一转成 VA（base + rva），使两个后端的 IR 落在同一地址空间 ——
   否则跨后端比对毫无意义。（契约第 2.1 节 I4）
2. 函数发现：BN 靠自己的分析引擎；SMDA 用递归下降 + FunctionCandidate 管理
   （还带 .pdata 异常处理、跳转表、尾调用等分析）。
   两者发现的函数集合与顺序必然不同 —— 这是后端差异，不是 bug。
3. .NET 程序集：SMDA 会把带 .NET 元数据的 PE 当 CIL/IL 反汇编
   （助记符是 ldarg.0/call/castclass 之类）。此时它与 BN 的原生 x86 视角完全不可比。
   本适配器用 backend="intel" 强制走原生后端。

2026-11-07
"""
from __future__ import annotations

import os
import sys

try:
    from .ir import (BasicBlock, CallSite, Function, OP_KEYWORD_SET, ProgramIR)
except ImportError:
    from ir import (BasicBlock, CallSite, Function, OP_KEYWORD_SET, ProgramIR)


def _smda_import():
    """导入 SMDA（按当前解释器版本挑正确的依赖目录）。"""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ver = "%d%d" % sys.version_info[:2]
    # 每个版本目录都是**自包含**的（lief/capstone 是按 ABI 编的，必须用对应版本）:
    #   py310_pkgs → python 3.10 (BN 自带的 bnpython3)
    #   py312_pkgs → python 3.12 (普通 python)
    cands = []
    env = os.environ.get("CODEFENDER_SMDA_PKGS")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.dirname(here), "_tools", "py%s_pkgs" % ver))
    for c in cands:
        if not os.path.isdir(os.path.join(c, "smda")):
            continue
        # lief / capstone 是按 ABI 编的扩展：目录里没有就用解释器已装的版本。
        # （py311_pkgs 只放纯 Python 包，lief/capstone 走 conda 环境）
        if c not in sys.path:
            sys.path.insert(0, c)
        try:
            import lief  # noqa: F401
            import capstone  # noqa: F401
        except Exception as e:
            raise ImportError("目录 %s 里没有可用的 lief/capstone: %s" % (c, e))
        return c
    raise ImportError("找不到 smda；用 CODEFENDER_SMDA_PKGS 指定目录")



# ── MalGraph 需要的额外信息 ────────────────────────────────────────────

# 分支/调用类助记符：它们的立即数操作数是**代码目标**，BN 会渲染成代码符号
# （CodeSymbolToken）而不是整数，所以统计"常量个数"时要排除。
_BRANCH_MNEMONICS = frozenset({
    "call", "callq", "lcall", "jmp", "jmpq", "ljmp",
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge",
    "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
    "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
    "jrcxz", "js", "jz", "loop", "loope", "loopne", "loopnz", "loopz",
})


def _import_table(pe_path):
    """[(IAT 地址, 符号名)] —— 与 BN 的 ImportAddressSymbol 同一形态。

    BN 的 ImportAddressSymbol.name 是**裸函数名**（不含 dll 前缀），
    MalGraph 的外部函数词表就是按这个名字统计的，所以这里也用裸名。
    """
    out = []
    try:
        import pefile
        pe = pefile.PE(pe_path, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in entry.imports:
                    try:
                        addr = int(imp.address)
                    except Exception:
                        continue
                    if imp.name:
                        out.append((addr, imp.name.decode("ascii", "ignore")))
                    elif imp.ordinal:
                        out.append((addr, "ordinal_%d" % int(imp.ordinal)))
        finally:
            pe.close()
    except Exception:
        return tuple()
    return tuple(out)


def _export_names(pe_path):
    """{导出地址: 导出名} —— 用来给函数起接近 BN 的名字。"""
    out = {}
    try:
        import pefile
        pe = pefile.PE(pe_path, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if exp is not None:
                for sym in exp.symbols:
                    try:
                        if sym.name and sym.address:
                            out[int(sym.address)] = sym.name.decode("ascii", "ignore")
                    except Exception:
                        continue
        finally:
            pe.close()
    except Exception:
        return {}
    return out


def _cs_op_kinds():
    """(CS_OP_IMM, CS_OP_MEM) —— capstone 的通用操作数类型常量。"""
    try:
        import capstone
        return capstone.CS_OP_IMM, capstone.CS_OP_MEM
    except Exception:
        return 2, 3


def _smda_constant_count(block) -> int:
    """块内立即数操作数个数（**近似** BN 的 IntegerToken 口径）。

    ⚠ 与 BN 不可能逐位一致：BN 数的是反汇编 token 类型，SMDA 只能从
    capstone 的操作数类型推断。分支/调用目标的立即数已排除（BN 渲染成
    代码符号，不算常量）。
    """
    imm_t, _mem_t = _cs_op_kinds()
    count = 0
    for ins in (getattr(block, "instructions", None) or []):
        m = (ins.mnemonic or "").strip().lower()
        try:
            detailed = ins.getDetailed()
            ops = list(detailed.operands)
        except Exception:
            continue
        for op in ops:
            try:
                if op.type == imm_t:
                    if m in _BRANCH_MNEMONICS:
                        continue
                    count += 1
            except Exception:
                continue
    return count


def _smda_call_sites(blocks, local_starts, import_by_addr):
    """从指令流重建调用点（SMDA 没有 MLIL，只能靠 capstone 的操作数）。

    * call rel32      → capstone IMM 操作数（已经是绝对地址）→ 本地函数 / 导入槽
    * call [rip+disp] → 绝对地址 = 下一条指令地址 + disp → 导入槽
    * call [reg]      → 间接调用 → unknown（旧 BN 实现同样丢弃）
    """
    imm_t, mem_t = _cs_op_kinds()
    sites = []
    for b in blocks:
        for ins in (getattr(b, "instructions", None) or []):
            m = (ins.mnemonic or "").strip().lower()
            if m not in ("call", "callq", "lcall"):
                continue
            try:
                addr = int(ins.offset)
            except Exception:
                addr = 0
            target = None
            try:
                detailed = ins.getDetailed()
                ops = list(detailed.operands)
            except Exception:
                ops = []
            if ops:
                op = ops[0]
                try:
                    otype = op.type
                except Exception:
                    otype = None
                if otype == imm_t:
                    try:
                        target = int(op.imm)
                    except Exception:
                        target = None
                elif otype == mem_t:
                    try:
                        disp = int(op.mem.disp)
                        base = int(op.mem.base)
                    except Exception:
                        disp, base = 0, 0
                    try:
                        base_name = detailed.reg_name(base)
                    except Exception:
                        base_name = ""
                    if base_name == "rip":
                        target = int(detailed.address) + int(detailed.size) + disp
                    elif not base_name:
                        target = disp
            if target is None:
                sites.append(CallSite(address=addr, kind="unknown"))
                continue
            if target in local_starts:
                sites.append(CallSite(address=addr, target=target, kind="func"))
            elif target in import_by_addr:
                sites.append(CallSite(address=addr, target=target,
                                      name=import_by_addr[target], kind="import"))
            else:
                sites.append(CallSite(address=addr, target=target, kind="unknown"))
    return tuple(sites)
def _pe_info(pe_path):
    """(image_base, bitness, machine) —— 用 pefile 读 PE 头。"""
    import pefile
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        bitness = 64 if machine == 0x8664 else 32
        return base, bitness, machine
    finally:
        pe.close()


def _imports(pe_path):
    """导入符号全名（dll.func），与 BN 的 sym.full_name 同一形态。"""
    out = []
    try:
        import pefile
        pe = pefile.PE(pe_path, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                dll = (entry.dll or b"").decode("ascii", "ignore").lower()
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    out.append("%s.%s" % (dll, imp.name.decode("ascii", "ignore")))
        finally:
            pe.close()
    except Exception:
        return tuple()
    return tuple(out)


def build_ir(pe_path, backend="intel", addr_mode="auto", with_calls=False):
    """把一个 PE 转成 ProgramIR（SMDA 后端）。

    Args:
        pe_path:   PE 文件路径（必须是 ASCII 路径）
        backend:   SMDA 后端，默认 "intel"（强制原生 x86/x64，避免 .NET 被当 IL）
        addr_mode: "auto"（默认）= 自动判定；"va" = 强制加 imagebase；"rva" = 保留原值
        with_calls: 是否重建调用点（MalGraph 的 FCG 需要）。默认 False。
    """
    _smda_import()
    from smda.Disassembler import Disassembler
    import smda

    base, bitness, machine = _pe_info(pe_path)
    report = Disassembler(backend=backend).disassembleFile(pe_path)
    report_base = int(getattr(report, "base_addr", 0) or 0)
    if not report_base:
        report_base = base

    # 地址基准判定：
    # 实测 SMDA 对原生 PE 给的偏移**已经是 VA**（不是 RVA）；
    # 而 .NET（IL 模式）给的是很小的 IL 偏移（明显 < imagebase）。
    # 一律加 base 会把 VA 抬高一个 imagebase（实测差 0x10000000）。
    _offs = [f.offset for f in report.getFunctions() if f.offset is not None]
    _min_off = min(_offs) if _offs else 0
    _already_va = bool(_offs) and _min_off >= report_base

    def to_addr(off):
        if off is None:
            return None
        if addr_mode == "rva":
            return int(off)
        if addr_mode == "va":
            return int(report_base) + int(off)
        return int(off) if _already_va else int(report_base) + int(off)

    # 导入表（IAT 地址 → 符号名）与导出名
    import_table = _import_table(pe_path)
    import_by_addr = {}
    for _a, _n in import_table:
        import_by_addr[_a] = _n
    export_names = _export_names(pe_path) if with_calls else {}

    report_funcs = list(report.getFunctions())   # getFunctions() 返回生成器
    # 本地函数起始地址集合（判定 call 目标是本地函数还是导入槽）
    local_starts = set()
    for _f in report_funcs:
        _a = to_addr(_f.offset)
        if _a is not None:
            local_starts.add(int(_a))

    functions = []
    for f in report_funcs:
        f_start = to_addr(f.offset)
        blocks = []
        try:
            bb_list = f.getBlocks()
        except Exception:
            bb_list = []
        for b in bb_list:
            insns = []
            keywords = []
            for ins in (b.instructions or []):
                m = (ins.mnemonic or "").strip().lower()
                if m:
                    insns.append(m)
                    if m in OP_KEYWORD_SET:
                        keywords.append(m)
            try:
                succ = [to_addr(x) for x in b.getSuccessors()]
            except Exception:
                succ = []
            blocks.append(BasicBlock(
                start=to_addr(b.offset),
                length=(None if b.length is None else int(b.length)),
                instructions=tuple(insns),
                successors=tuple(succ),
                constant_count=_smda_constant_count(b),
                n_outgoing=len(succ),
                keywords=tuple(keywords),
            ))
        size = 0
        try:
            ends = [b.offset + (b.length or 0) for b in bb_list]
            if ends and f.offset is not None:
                size = max(ends) - f.offset
        except Exception:
            size = 0
        callees = []
        try:
            for xref in f.getCodeOutrefs():
                src = xref.from_instruction
                if not src or not (src.mnemonic or "").lower().startswith("call"):
                    continue
                dst_fn = xref.to_instruction.smda_function
                if dst_fn is not None and dst_fn.offset is not None:
                    callees.append(to_addr(dst_fn.offset))
        except Exception:
            callees = []
        fname = ""
        if f_start is not None:
            fname = export_names.get(int(f_start)) or ("sub_%x" % int(f_start))
        calls = ()
        if with_calls:
            calls = _smda_call_sites(bb_list, local_starts, import_by_addr)
        functions.append(Function(
            start=f_start,
            size=int(size or 0),
            blocks=tuple(blocks),
            callees=tuple(callees),
            callees_known=True,
            name=fname,
            call_sites=calls,
        ))

    arch = "x86_64" if bitness == 64 else "x86"
    return ProgramIR(
        functions=tuple(functions),
        imports=_imports(pe_path),
        external_symbols=tuple(import_table),
        arch=arch,
        bitness=bitness,
        backend="smda",
        backend_version=str(getattr(smda, "__version__", "unknown")),
    )
