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
    from .ir import BasicBlock, Function, ProgramIR
except ImportError:
    from ir import BasicBlock, Function, ProgramIR


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
        if os.path.isdir(os.path.join(c, "smda")) and os.path.isdir(os.path.join(c, "lief")):
            if c not in sys.path:
                sys.path.insert(0, c)
            return c
    raise ImportError("找不到 smda/lief；用 CODEFENDER_SMDA_PKGS 指定目录")


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


def build_ir(pe_path, backend="intel", addr_mode="auto"):
    """把一个 PE 转成 ProgramIR（SMDA 后端）。

    Args:
        pe_path:   PE 文件路径（必须是 ASCII 路径）
        backend:   SMDA 后端，默认 "intel"（强制原生 x86/x64，避免 .NET 被当 IL）
        addr_mode: "auto"（默认）= 自动判定；"va" = 强制加 imagebase；"rva" = 保留原值
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

    functions = []
    for f in report.getFunctions():
        f_start = to_addr(f.offset)
        blocks = []
        try:
            bb_list = f.getBlocks()
        except Exception:
            bb_list = []
        for b in bb_list:
            insns = []
            for ins in (b.instructions or []):
                m = (ins.mnemonic or "").strip().lower()
                if m:
                    insns.append(m)
            try:
                succ = [to_addr(x) for x in b.getSuccessors()]
            except Exception:
                succ = []
            blocks.append(BasicBlock(
                start=to_addr(b.offset),
                length=(None if b.length is None else int(b.length)),
                instructions=tuple(insns),
                successors=tuple(succ),
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
        functions.append(Function(
            start=f_start,
            size=int(size or 0),
            blocks=tuple(blocks),
            callees=tuple(callees),
            callees_known=True,
        ))

    arch = "x86_64" if bitness == 64 else "x86"
    return ProgramIR(
        functions=tuple(functions),
        imports=_imports(pe_path),
        arch=arch,
        bitness=bitness,
        backend="smda",
        backend_version=str(getattr(smda, "__version__", "unknown")),
    )
