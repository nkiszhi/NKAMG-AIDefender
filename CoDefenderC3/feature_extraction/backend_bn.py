# -*- coding: utf-8 -*-
"""BinaryNinja 后端适配器：BinaryView → ProgramIR。

这是 Phase 1 的第 2 步：**只做适配，不碰特征计算**。
特征层由 features_from_ir.py 消费 IR。

⚠ 忠实度要求（改这个文件前先读）
----------------------------------
本适配器逐行复刻 `extract_feature.py::_extract_disassembly` 的遍历结构与
异常语义。原因：原代码的错误分支会影响最终特征，适配器必须复现同样的结果，
否则「IR → 特征」就与「bv → 特征」不等价。

具体复刻的要点：

1. 函数级异常边界：原代码在遍历某个函数的基本块时若抛异常，该函数**剩余的块**
   不再处理（但已处理的部分保留）。适配器用同样的 try/except 包住整个块循环。
2. 块级字段的取值时机：原代码先记 block.length、再记 len(outgoing_edges)，
   最后才提取指令。所以即使指令提取失败，块的长度与边数**仍然计入**。
   → 适配器先构造块（带 length/successors），再填 instructions。
3. disassembly_text 的 AttributeError 回退：原代码 except AttributeError 时
   改为直接迭代 block（IL 指令）。其它异常则中止该函数。
4. callees 取不到时：原代码把 n_callees 留 0、is_leaf 留 False、is_recursive 留 False。
   → IR 用 callees_known=False 表达这个状态（is_leaf/is_recursive 都为 False）。
5. 函数大小口径：total_bytes 为真值时用它，否则 highest_address - start。
6. callees 保留重复与顺序（调用边按重数计）。
7. successors 原样透传：不排序、不去重（E03 回边判定依赖地址序）。

2026-11-05
"""
from __future__ import annotations

from typing import Optional, Tuple

try:
    from .ir import BasicBlock, Function, ProgramIR
except ImportError:                                 # 直接按文件加载时的回退
    from ir import BasicBlock, Function, ProgramIR


def _parse_mnemonic(line) -> str:
    """从一条指令行里取助记符。

    ⚠ 与生产代码 extract_feature.py::_parse_mnemonic **刻意不同**。

    生产代码取 tokens[0].text，而 BN 5.x 的 DisassemblyTextLine.tokens[0] 是**空串**
    （缩进/地址占位），真正的助记符在 tokens[1] 或 line.il_instruction.mnemonic：

        tokens = ["", "lea", "     ", "rax", ", ", "["]
        il_instruction.mnemonic == "lea"

    于是生产的 opcode 类特征（D01/D02/D03/D04/D07）在实测里几乎全空：
    30537 个基本块里只有 11.6% 带指令，平均每块 0.12 条指令。
    本适配器按 IR 契约取**真实助记符**（il_instruction.mnemonic 优先）。

    注：extract_feature.py 的同一处缺陷仍未修（那是生产代码，改它会变更现有特征语义，
    需要单独决策 —— 见 docs/IR_CONTRACT.md 的「生产缺陷」一节）。
    """
    try:
        ins = getattr(line, "il_instruction", None)
        if ins is not None:
            m = getattr(ins, "mnemonic", None)
            if m:
                return str(m).strip().lower()
    except Exception:
        pass
    try:
        if hasattr(line, "tokens"):
            tokens = line.tokens
        elif isinstance(line, tuple):
            tokens = line[0] if line else []
        else:
            tokens = line
        if tokens and len(tokens) > 0:
            for tk in tokens:
                text = tk.text if hasattr(tk, "text") else str(tk)
                text = (text or "").strip().lower()
                if text:                      # 跳过前导空 token
                    return text
    except Exception:
        pass
    return ""


def _block_successors(block) -> Tuple[int, ...]:
    """后继基本块的起始地址（原样透传，不排序不去重）。"""
    try:
        out = []
        for edge in block.outgoing_edges:
            try:
                t = edge.target
                if t is not None and t.start is not None:
                    out.append(int(t.start))
            except Exception:
                continue
        return tuple(out)
    except Exception:
        return ()


def _function_size(func) -> int:
    """函数字节数：total_bytes 为真值时用它，否则 highest_address - start。"""
    try:
        if hasattr(func, "total_bytes") and func.total_bytes:
            return int(func.total_bytes)
        if func.highest_address and func.start:
            return int(func.highest_address - func.start)
    except Exception:
        pass
    return 0


def _function_callees(func):
    """(callees 地址元组, 是否取到)。

    取不到时返回 ((), False) —— 对应原代码 except 分支（n_callees=0, is_leaf=False）。
    """
    try:
        callees = list(func.callees)
        return tuple(int(c.start) for c in callees if getattr(c, "start", None) is not None), True
    except Exception:
        return (), False


def _detect_arch(bv):
    """从 bv 探测架构名与位数。

    BN 5.x: bv.arch.name ("x86" / "x86_64")、bv.arch.address_size (4 / 8)。
    """
    try:
        a = bv.arch
        name = str(getattr(a, "name", "") or "")
        size = int(getattr(a, "address_size", 0) or 0)
        if name and size:
            return name, size * 8
    except Exception:
        pass
    return "unknown", 0


def build_ir(bv, backend_version: Optional[str] = None, arch: Optional[str] = None,
             bitness: Optional[int] = None) -> ProgramIR:
    """把一个 BinaryView 转成 ProgramIR。

    Args:
        bv:             binaryninja.BinaryView（已 update_analysis_and_wait）
        backend_version: 记录进 IR 的后端版本（如 "5.2.8722"）
        arch:           覆盖自动探测的架构名
        bitness:        覆盖自动探测的位数（32/64）
    """
    if backend_version is None:
        try:
            import binaryninja
            backend_version = binaryninja.core_version()
        except Exception:
            backend_version = "unknown"
    if arch is None or bitness is None:
        a_name, a_bits = _detect_arch(bv)
        arch = arch or a_name
        bitness = bitness if bitness is not None else a_bits

    functions = []
    for func in bv.functions:
        blocks = []
        try:
            for block in func.basic_blocks:
                length = None
                try:
                    length = block.length
                except Exception:
                    length = None
                succ = _block_successors(block)
                ins = []
                failed = False
                try:
                    try:
                        lines = block.disassembly_text
                    except AttributeError:
                        lines = block
                    for line in lines:
                        m = _parse_mnemonic(line)
                        if m:
                            ins.append(m)
                except Exception:
                    # 复刻原代码：指令提取失败 → 保留已收集的部分，
                    # 且该函数的剩余块不再处理。
                    failed = True
                blocks.append(BasicBlock(
                    start=int(getattr(block, "start", 0) or 0),
                    length=length,
                    instructions=tuple(ins),
                    successors=succ,
                ))
                if failed:
                    break
        except Exception:
            pass

        callees, known = _function_callees(func)
        functions.append(Function(
            start=int(getattr(func, "start", 0) or 0),
            size=_function_size(func),
            blocks=tuple(blocks),
            callees=callees,
            callees_known=known,
        ))

    imports = ()
    try:
        import binaryninja as bn
        syms = bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol)
        imports = tuple(str(s.full_name) for s in syms if getattr(s, "full_name", None))
    except Exception:
        imports = ()

    return ProgramIR(
        functions=tuple(functions),
        imports=imports,
        arch=str(arch or "unknown"),
        bitness=int(bitness or 0),
        backend="bn",
        backend_version=str(backend_version),
    )


def build_ir_from_path(path: str, **kwargs) -> ProgramIR:
    """打开一个 PE 或 .bndb，转成 ProgramIR。

    ⚠ BN 打不开路径含非 ASCII 字符的文件 —— 调用方需自行保证路径是 ASCII
    （或先镜像到临时目录）。
    """
    import binaryninja as bn
    bv = bn.load(path, options={
        "analysis.mode": "basic",
        "analysis.linearSweep.autorun": True,
        "analysis.limits.maxFunctionSize": 262144,
    })
    if bv is None:
        raise RuntimeError("BinaryNinja failed to load: %s" % path)
    try:
        try:
            bv.update_analysis_and_wait()
        except Exception:
            pass
        return build_ir(bv, **kwargs)
    finally:
        try:
            bv.file.close()
        except Exception:
            pass
