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
    from .ir import (BasicBlock, CallSite, Function, OP_KEYWORD_SET, ProgramIR)
    from .bn_runtime import ensure_binaryninja
except ImportError:                                 # 直接按文件加载时的回退
    from ir import (BasicBlock, CallSite, Function, OP_KEYWORD_SET, ProgramIR)
    from bn_runtime import ensure_binaryninja


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
            # ① 优先取"渲染助记符"：token 类型为 InstructionToken 的那个。
            #    ⚠ 不能简单取"第一个非空 token" —— BN 有时会在最前面塞一个
            #    TagToken（如 "🚫🚫🚫"）或注解行（"{ Does not return }"），
            #    那样会把真正的助记符（and/or/xor/je/...）漏掉，
            #    MalGraph 的 11 维块特征就会与旧实现对不上。
            for tk in tokens:
                try:
                    if getattr(getattr(tk, "type", None), "name", None) == "InstructionToken":
                        text = (tk.text or "").strip().lower()
                        if text:
                            return text
                except Exception:
                    continue
            # ② 兜底：第一个非空 token（注解行只有这一个 token）
            for tk in tokens:
                text = tk.text if hasattr(tk, "text") else str(tk)
                text = (text or "").strip().lower()
                if text:
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


# ── MalGraph 需要的额外信息 ────────────────────────────────────────────
#   11 维块特征里只有 "constants" 需要 token 级信息（立即数/字符串操作数个数），
#   其余 8 个类别都能由「每行的渲染助记符」推出。BN 的 DisassemblyTextLine
#   里，渲染助记符就是第一个非空 token（tokens[0] 是空的地址分隔符）。
#   → constant_count 必须按 token 类型精确统计，否则与旧实现不一致。

_CONST_TOKEN_TYPES = ("IntegerToken", "StringToken")


def _block_token_stats(block):
    """块的 (关键字 token 序列, 常量个数)。

    ⚠ 严格复刻旧实现的 token 分类规则（逐 token、按优先级 elif）：

        call > transfer > arithmetic > logic > compare > move >
        termination > data_declaration > constants

    因为是 elif 链，**一个文本恰好是关键字的 token 会被算进它的类别，
    而不是算成常量**。典型例子：BN 把 je 指令后面注解里的字符串 "or"
    渲染成 StringToken，旧实现会把它算成一次 logic（而不是常量）。

    返回：
        keywords       关键字 token 的文本序列（保持顺序与重复）
        constant_count 非关键字的 IntegerToken / StringToken 个数
    """
    keywords = []
    consts = 0
    try:
        lines = block.disassembly_text
    except Exception:
        return (), 0
    try:
        for line in lines:
            tokens = getattr(line, "tokens", None)
            if not tokens:
                continue
            for t in tokens:
                try:
                    text = (t.text or "").strip().lower()
                except Exception:
                    continue
                if text in OP_KEYWORD_SET:
                    keywords.append(text)
                    continue           # elif 链：关键字 token 不再当常量
                try:
                    tn = t.type.name
                except Exception:
                    continue
                if tn in _CONST_TOKEN_TYPES:
                    consts += 1
    except Exception:
        pass
    return tuple(keywords), consts


def _block_outgoing_count(block) -> int:
    """块的后继边条数（原始 outgoing_edges 条数，可能与 successors 长度不同）。"""
    try:
        return len(block.outgoing_edges)
    except Exception:
        return 0


def _function_call_sites(bv, func, local_starts, import_by_addr):
    """从 MLIL 还原调用点。

    与旧实现（utils.py / build_malgraph_cache_fast.py）的解析顺序完全一致：

    * dest 是 MLIL_CONST_PTR → 目标是常量地址
        - 命中本地函数起始地址 → kind="func"
        - 否则命中导入槽地址     → kind="import"（带符号名）
        - 都不命中                → kind="unknown"（旧实现直接丢弃这条边）
    * dest 是 MLIL_IMPORT → 用「调用指令地址上的符号名」当导入名
        - 取不到符号 → kind="unknown"（旧实现同样丢弃）
    * 其它 dest（间接调用等） → kind="unknown"

    注：旧实现只认 MLIL_CALL；这里同时认 MLIL_TAILCALL
    （与 build_malgraph_cache_fast.py 的版本一致）。
    """
    sites = []
    try:
        import binaryninja as bn
        MLIL_CALL = bn.MediumLevelILOperation.MLIL_CALL
        MLIL_TAIL = bn.MediumLevelILOperation.MLIL_TAILCALL
        CONST_PTR = bn.MediumLevelILOperation.MLIL_CONST_PTR
        IMPORT = bn.MediumLevelILOperation.MLIL_IMPORT
    except Exception:
        return ()
    try:
        mlil = func.mlil
    except Exception:
        mlil = None
    if mlil is None:
        return ()
    try:
        blocks = list(mlil)
    except Exception:
        return ()
    for block in blocks:
        try:
            instrs = list(block)
        except Exception:
            continue
        for instr in instrs:
            try:
                op = instr.operation
            except Exception:
                continue
            if op != MLIL_CALL and op != MLIL_TAIL:
                continue
            try:
                addr = int(instr.address)
            except Exception:
                addr = 0
            try:
                dest = instr.dest
                dop = dest.operation
            except Exception:
                sites.append(CallSite(address=addr, kind="unknown"))
                continue
            if dop == CONST_PTR:
                try:
                    target = int(dest.constant)
                except Exception:
                    sites.append(CallSite(address=addr, kind="unknown"))
                    continue
                if target in local_starts:
                    sites.append(CallSite(address=addr, target=target, kind="func"))
                elif target in import_by_addr:
                    sites.append(CallSite(address=addr, target=target,
                                          name=import_by_addr[target], kind="import"))
                else:
                    sites.append(CallSite(address=addr, target=target, kind="unknown"))
            elif dop == IMPORT:
                name = None
                sym_addr = None
                try:
                    sym = bv.get_symbol_at(addr)
                except Exception:
                    sym = None
                if sym is not None:
                    try:
                        name = str(sym.name)
                    except Exception:
                        name = None
                    try:
                        sym_addr = int(sym.address)
                    except Exception:
                        sym_addr = None
                sites.append(CallSite(
                    address=addr, target=sym_addr, name=name,
                    kind=("import" if name else "unknown")))
            else:
                sites.append(CallSite(address=addr, kind="unknown"))
    return tuple(sites)


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
             bitness: Optional[int] = None, with_calls: bool = False) -> ProgramIR:
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

    # 先把函数对象收集起来：本地函数起始地址要用来判定「调用目标是本地函数
    # 还是导入槽」（旧实现的解析顺序：先本地，后导入）。
    try:
        func_objs = list(bv.functions)
    except Exception:
        func_objs = []
    local_starts = set()
    for _f in func_objs:
        try:
            local_starts.add(int(_f.start))
        except Exception:
            pass

    # 导入槽地址 → 符号名
    #   external_list 保持 BN 的原始顺序（MalGraph 的外部函数索引依赖它）
    #   import_by_addr 是「地址 → 名字」的字典（同名地址时后者覆盖前者，
    #   与旧实现 {sym.address: sym.name for sym in syms} 的语义一致）
    external_list = []
    import_by_addr = {}
    try:
        import binaryninja as bn
        for _s in bv.get_symbols_of_type(bn.SymbolType.ImportAddressSymbol):
            try:
                if getattr(_s, "name", None):
                    _pair = (int(_s.address), str(_s.name))
                    external_list.append(_pair)
                    import_by_addr[_pair[0]] = _pair[1]
            except Exception:
                continue
    except Exception:
        pass

    # ── 第一遍：先算 MLIL 调用点 ──────────────────────────────────────
    # ⚠ 顺序很重要，不能调换：旧实现是「先遍历所有函数的 MLIL，再遍历基本块」。
    #   BN 算完 MLIL 会补充符号 / 细化分析，这会影响随后反汇编里
    #   「同一个地址渲染成代码符号还是整数」——于是 MalGraph 的 constants
    #   维度就会差 1~3。先块后 MLIL 会与旧实现对不上。
    call_sites_list = []
    if with_calls:
        for func in func_objs:
            call_sites_list.append(
                _function_call_sites(bv, func, local_starts, import_by_addr))
    else:
        call_sites_list = [()] * len(func_objs)

    # ── 第二遍：基本块 ────────────────────────────────────────────────
    functions = []
    for fidx, func in enumerate(func_objs):
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
                keywords, consts = _block_token_stats(block)
                blocks.append(BasicBlock(
                    start=int(getattr(block, "start", 0) or 0),
                    length=length,
                    instructions=tuple(ins),
                    successors=succ,
                    constant_count=consts,
                    n_outgoing=_block_outgoing_count(block),
                    keywords=keywords,
                ))
                if failed:
                    break
        except Exception:
            pass

        callees, known = _function_callees(func)
        fname = ""
        try:
            fname = str(func.name or "")
        except Exception:
            fname = ""
        calls = call_sites_list[fidx] if fidx < len(call_sites_list) else ()
        functions.append(Function(
            start=int(getattr(func, "start", 0) or 0),
            size=_function_size(func),
            blocks=tuple(blocks),
            callees=callees,
            callees_known=known,
            name=fname,
            call_sites=calls,
        ))

    imports = ()
    try:
        import binaryninja as bn
        syms = bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol)
        imports = tuple(str(s.full_name) for s in syms if getattr(s, "full_name", None))
    except Exception:
        imports = ()

    # 导入槽地址 → 符号名（MalGraph 的 FCG 要靠它把 call 目标解析成外部函数）
    external_symbols = tuple(external_list)

    return ProgramIR(
        functions=tuple(functions),
        imports=imports,
        external_symbols=external_symbols,
        arch=str(arch or "unknown"),
        bitness=int(bitness or 0),
        backend="bn",
        backend_version=str(backend_version),
    )


def build_ir_from_path(path: str, analysis: str = "basic", **kwargs) -> ProgramIR:
    """打开一个 PE 或 .bndb，转成 ProgramIR。

    analysis
    --------
    "basic"  线性扫描 + 基础分析（快）。**D/E 特征用这一档** —— 它与
             .bndb 门禁的采集口径一致（见 docs/BASELINE_FIXTURE.md）。
    "full"   BN 默认全量分析（慢）。**MalGraph 的 FCG 必须用这一档** ——
             只有全量分析才会算 MLIL，而 MLIL 是还原调用边的唯一来源
             （"basic" 档下 85% 的函数 mlil 为 None）。

    ⚠ BN 打不开路径含非 ASCII 字符的文件 —— 调用方需自行保证路径是 ASCII
    （或先镜像到临时目录）。
    """
    bn = ensure_binaryninja()
    if analysis == "full":
        if "with_calls" not in kwargs:
            kwargs["with_calls"] = True
        bv = bn.load(path)
    else:
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
