"""SMDA 后端：用 SMDA（https://github.com/danielplohmann/smda）替代 BinaryNinja 做
反汇编 / CFG / 调用图提取，产出与 BN 版**逐位对齐**的 D/E 特征与 MalGraph 输入。

为什么换 SMDA：
- 速度：内置 capstone 后端对普通 PE 是**亚秒级**（BN 通常 30~130s）
- 稳定性：SMDA 自带协作式时间预算（SmdaConfig.TIMEOUT），不会像 BN 那样在畸形样本上挂死
- 许可：BSD-3，无需商业授权；BN 需 license

与 BN 版的差异（有意为之，需配合重训）：
- 操作码/n-gram 哈希由进程随机的 hash() 改为 **zlib.crc32 稳定哈希**
  （BN 版每次进程运行结果不同，是已知缺陷；改后 D02/D03/D07 的分布随之变化，
    依赖这些特征的模型（Opcode*/AsmEmbedNet）必须重训）
- 导入函数名来自 SMDA 的 apirefs（形如 "dll.dll!FuncName"），与 BN 的导入符号同名空间

用法：
    from feature_extraction.smda_extract import SmdaExtractor
    ex = SmdaExtractor(timeout=120)
    feats = ex.extract_de(pe_path)                  # D01-D07 + E03/E04
    mal = ex.extract_cfg_and_fcg(pe_path, vocab)    # MalGraph 兼容结构
"""
from __future__ import annotations

import hashlib
import os
import zlib
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

import numpy as np

try:
    from insn_categories import CAT_LOOKUP, CAT_NAMES
except ImportError:  # 仅把 feature_extraction/ 放进 sys.path 的场景（如训练侧 worker）
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from insn_categories import CAT_LOOKUP, CAT_NAMES

def _api_name(name: str) -> str:
    """SMDA 的导入名形如 "api-ms-win-core...dll!EventWriteTransfer"。

    MalGraph 词表（train_external_function_name_vocab.jsonl）是用 BinaryNinja 的导入
    符号名建的（多为纯函数名），因此默认去掉 "dll!" 前缀以**复用现有词表**；
    需要保留原始名时设 CODEFENDER_SMDA_API_NAME_STYLE=raw。
    """
    if os.environ.get("CODEFENDER_SMDA_API_NAME_STYLE", "short").strip().lower() == "raw":
        return name
    if "!" in name:
        return name.rsplit("!", 1)[1]
    return name


def _local_name(func) -> str:
    """本地函数名：SMDA 对未命名函数返回空串，补成 BN 风格的 sub_<addr>。"""
    name = (getattr(func, "function_name", "") or "").strip()
    if name:
        return name
    offset = getattr(func, "offset", None)
    return f"sub_{offset:x}" if offset is not None else ""


MAX_OPCODES = 4096
NGRAM_DIM = 256
MAX_FUNCTIONS = 48
FUNC_EMB_DIM = 128
BLOCK_FEATURE_DIM = 11


# 进程级共享分析缓存：同一路径只分析一次（D/E 与 MalGraph 各需要一次结果）
_REPORT_CACHE: Dict[str, Any] = {}


# 稳定哈希：与 extract_feature.py 共用同一实现（feature_extraction/hashing.py），
# 保证 SMDA 后端与 fast/BN 路径的编码口径完全一致。
try:
    from feature_extraction.hashing import stable_bucket as _stable_bucket
except ImportError:  # 仅 feature_extraction/ 在 sys.path 时
    from hashing import stable_bucket as _stable_bucket


class SmdaExtractor:
    """SMDA 后端的特征提取器，接口与 BinjaExtractor 对齐。"""

    def __init__(self, timeout: int = 120, backend: Optional[str] = None):
        self.timeout = int(timeout)
        self.backend = backend or os.environ.get("CODEFENDER_SMDA_BACKEND", "") or None
        self._disassembler = None

    # ── 内部：加载 ───────────────────────────────────────────────
    def _get_disassembler(self):
        if self._disassembler is None:
            from smda.Disassembler import Disassembler
            from smda.SmdaConfig import SmdaConfig

            cfg = SmdaConfig()
            # SMDA 自带协作式预算：到点即停止并返回已完成的部分，不会挂死
            cfg.TIMEOUT = max(30, self.timeout)
            cfg.WITH_STRINGS = False
            cfg.STORE_BUFFER = False
            self._disassembler = Disassembler(cfg, backend=self.backend)
        return self._disassembler

    def _analyze(self, pe_path: str):
        """分析文件；同一路径在一次进程内复用结果（D/E 与 MalGraph 各要一次）。"""
        try:
            st = os.stat(pe_path)
            key = (st.st_mtime_ns, st.st_size)
        except OSError:
            key = None
        cached = _REPORT_CACHE.get(pe_path)
        if cached and key is not None and cached[0] == key:
            return cached[1]
        d = self._get_disassembler()
        report = d.disassembleFile(pe_path)
        if report is None:
            raise RuntimeError(f"SMDA failed to analyze: {pe_path}")
        if key is not None:
            _REPORT_CACHE[pe_path] = (key, report)
        return report

    # ── 内部：遍历助手 ──────────────────────────────────────────
    @staticmethod
    def _instructions_of(func) -> List[Any]:
        """函数内全部指令（按地址升序）。"""
        ins = []
        for _addr, block_ins in sorted(getattr(func, "blocks", {}).items()):
            ins.extend(block_ins)
        return ins

    @staticmethod
    def _call_edges(func, local_index: Dict[int, int], api_index: Dict[str, int]):
        """函数的调用边：(被调函数索引, 是否递归)。

        - 直接调用本地函数 → 本地索引
        - 调用导入 API → 外部索引（api_index 里是 "dll!Name"）
        """
        edges = []
        apirefs = getattr(func, "apirefs", {}) or {}
        for xr in func.getCodeOutrefs():
            src = getattr(xr, "from_instruction", None)
            tgt = getattr(xr, "to_instruction", None)
            if src is None or tgt is None:
                continue
            if (src.mnemonic or "").lower() != "call":
                continue
            api_name = apirefs.get(src.offset)
            if api_name is not None:
                api_name = _api_name(api_name)
            if api_name is not None and api_name in api_index:
                edges.append((api_index[api_name], False))
                continue
            callee = getattr(xr, "to_function", None)
            if callee is not None:
                off = getattr(callee, "offset", None)
                if off is not None and off in local_index:
                    edges.append((local_index[off], off == getattr(func, "offset", None)))
        return edges

    # ── D/E 特征 ────────────────────────────────────────────────
    def extract_de(self, pe_path: str) -> Dict[str, np.ndarray]:
        """D01-D07 + E03/E04，口径与 BN 版一致（哈希改为稳定 crc32）。"""
        report = self._analyze(pe_path)
        funcs = list(report.getFunctions())

        all_opcodes: List[str] = []
        global_opcode_counts: Counter = Counter()
        global_cat_counts: Counter = Counter()
        func_data: List[Dict[str, Any]] = []
        all_bb_sizes: List[int] = []
        all_bb_out_edges: List[int] = []
        cfg_nodes = 0
        cfg_edges = 0
        cg_edges = 0
        back_edges = 0
        leaf_funcs = 0
        recursive_funcs = 0
        out_degrees: List[int] = []
        in_degree_map: Dict[int, int] = defaultdict(int)
        cg_adj: Dict[int, set] = defaultdict(set)

        for fi, func in enumerate(funcs):
            func_ops: Counter = Counter()
            n_bbs = 0
            fsize = 0
            blocks = getattr(func, "blocks", {}) or {}
            blockrefs = getattr(func, "blockrefs", {}) or {}
            for addr, block_ins in blocks.items():
                n_bbs += 1
                cfg_nodes += 1
                size = 0
                for ins in block_ins:
                    m = (ins.mnemonic or "").strip().lower()
                    size += getattr(ins, "size", 0) or len(getattr(ins, "bytes", b"") or b"")
                    if m:
                        all_opcodes.append(m)
                        global_opcode_counts[m] += 1
                        global_cat_counts[CAT_LOOKUP.get(m, "other")] += 1
                        func_ops[m] += 1
                all_bb_sizes.append(size)
                succ = blockrefs.get(addr) or []
                all_bb_out_edges.append(len(succ))
                cfg_edges += len(succ)
                if fi < 100:
                    for s in succ:
                        if s is not None and s <= addr:
                            back_edges += 1
            fsize = sum(all_bb_sizes[-n_bbs:]) if n_bbs else 0

            # 调用关系
            local_index = {getattr(f2, "offset", None): i2 for i2, f2 in enumerate(funcs)}
            api_names = set()
            for _addr2, block_ins2 in blocks.items():
                for ins2 in block_ins2:
                    if (ins2.mnemonic or "").lower() == "call":
                        nm = (getattr(func, "apirefs", {}) or {}).get(ins2.offset)
                        if nm:
                            api_names.add(_api_name(nm))
            callees = self._call_edges(func, local_index, {n: 0 for n in api_names})
            n_callees = len(callees)
            out_degrees.append(n_callees)
            is_leaf = n_callees == 0
            if is_leaf:
                leaf_funcs += 1
            is_recursive = any(rec for _idx, rec in callees)
            if is_recursive:
                recursive_funcs += 1
            fstart = getattr(func, "offset", None)
            for callee_idx, _rec in callees:
                cg_edges += 1
                if callee_idx < len(funcs):
                    cstart = getattr(funcs[callee_idx], "offset", None)
                    if cstart is not None and fstart is not None:
                        cg_adj[fstart].add(cstart)
                        in_degree_map[cstart] += 1

            func_data.append({
                "ops": func_ops, "n_bbs": n_bbs, "size": fsize,
                "n_callees": n_callees, "is_leaf": is_leaf, "is_recursive": is_recursive,
            })

        n_funcs = len(func_data)
        feats: Dict[str, np.ndarray] = {}

        # D01 操作码序列
        d01 = np.zeros(MAX_OPCODES, dtype=np.int64)
        for i, op in enumerate(all_opcodes[:MAX_OPCODES]):
            d01[i] = _stable_bucket(op, 511) + 1
        feats["D01"] = d01

        # D02/D03 n-gram
        d02 = np.zeros(NGRAM_DIM, dtype=np.float32)
        for i in range(len(all_opcodes) - 1):
            d02[_stable_bucket(all_opcodes[i] + "_" + all_opcodes[i + 1], NGRAM_DIM)] += 1
        if d02.sum() > 0:
            d02 = np.log1p(d02); d02 /= np.linalg.norm(d02) + 1e-8
        feats["D02"] = d02

        d03 = np.zeros(NGRAM_DIM, dtype=np.float32)
        for i in range(len(all_opcodes) - 2):
            d03[_stable_bucket("_".join(all_opcodes[i:i + 3]), NGRAM_DIM)] += 1
        if d03.sum() > 0:
            d03 = np.log1p(d03); d03 /= np.linalg.norm(d03) + 1e-8
        feats["D03"] = d03

        # D04 类别分布
        d04 = np.zeros(len(CAT_NAMES), dtype=np.float32)
        total_cat = sum(global_cat_counts.values()) or 1
        for i, cat in enumerate(CAT_NAMES):
            d04[i] = global_cat_counts.get(cat, 0) / total_cat
        feats["D04"] = d04

        # D05 函数统计
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

        # D06 基本块统计
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

        # D07 每函数嵌入
        d07 = np.zeros(MAX_FUNCTIONS * FUNC_EMB_DIM, dtype=np.float32)
        for fi in range(min(n_funcs, MAX_FUNCTIONS)):
            emb = np.zeros(FUNC_EMB_DIM, dtype=np.float32)
            for op, cnt in func_data[fi]["ops"].items():
                emb[_stable_bucket(op, FUNC_EMB_DIM)] += cnt
            if emb.sum() > 0:
                emb /= np.linalg.norm(emb) + 1e-8
            d07[fi * FUNC_EMB_DIM:(fi + 1) * FUNC_EMB_DIM] = emb
        feats["D07"] = d07

        # E03 CFG 统计
        cg_edges = sum(out_degrees)
        e03 = np.zeros(12, dtype=np.float32)
        e03[0] = cfg_nodes
        e03[1] = cfg_edges
        e03[2] = cfg_edges / max(cfg_nodes, 1)
        if func_data:
            bbc = [fd["n_bbs"] for fd in func_data]
            e03[3] = max(bbc); e03[4] = np.mean(bbc); e03[5] = np.std(bbc)
        e03[6] = back_edges
        e03[7] = n_funcs
        e03[8] = cfg_nodes / max(n_funcs, 1)
        e03[9] = cfg_edges / max(n_funcs, 1)
        e03[10] = back_edges / max(n_funcs, 1)
        e03[11] = 1.0 if cfg_nodes > 0 else 0.0
        feats["E03"] = e03

        # E04 调用图统计
        e04 = np.zeros(10, dtype=np.float32)
        e04[0] = n_funcs
        e04[1] = cg_edges
        e04[2] = cg_edges / max(n_funcs, 1)
        e04[3] = leaf_funcs / max(n_funcs, 1)
        e04[4] = recursive_funcs / max(n_funcs, 1)
        depths = []
        for func in funcs[:50]:
            d = self._call_depth(func, set(), 0, 10)
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

    def _call_depth(self, func, visited, depth, max_depth):
        """调用深度（与 BN 版 _call_depth 口径一致：最深可达 10 层）。"""
        if depth >= max_depth:
            return depth
        if getattr(func, "offset", None) in visited:
            return depth
        visited = visited | {getattr(func, "offset", None)}
        best = depth
        try:
            for xr in func.getCodeOutrefs():
                src = getattr(xr, "from_instruction", None)
                if src is None or (src.mnemonic or "").lower() != "call":
                    continue
                callee = getattr(xr, "to_function", None)
                if callee is None:
                    continue
                d = self._call_depth(callee, visited, depth + 1, max_depth)
                best = max(best, d)
        except Exception:
            pass
        return best

    # ── MalGraph 兼容的 CFG/FCG ─────────────────────────────────
    def extract_cfg_and_fcg(self, pe_path: str, vocab_dict: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
        """产出与 models/MalGraph_2022/utils.py 完全同构的结果。"""
        try:
            report = self._analyze(pe_path)
            funcs = list(report.getFunctions())
            if not funcs:
                return None

            file_hash = hashlib.sha256()
            with open(pe_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            file_hash = file_hash.hexdigest()

            local_functions = funcs
            local_index = {getattr(f, "offset", None): i for i, f in enumerate(local_functions)}

            # 外部（导入）函数名：来自各函数 apirefs
            external_names: List[str] = []
            seen_ext = set()
            for func in local_functions:
                for nm in (getattr(func, "apirefs", {}) or {}).values():
                    nm = _api_name(nm)
                    if nm and nm not in seen_ext:
                        seen_ext.add(nm)
                        external_names.append(nm)
            if vocab_dict is not None:
                for nm in external_names:
                    vocab_dict[nm] = vocab_dict.get(nm, 0) + 1
            external_index = {nm: len(local_functions) + i for i, nm in enumerate(external_names)}

            function_edges = [[], []]
            for func in local_functions:
                caller_idx = local_index.get(getattr(func, "offset", None))
                if caller_idx is None:
                    continue
                for callee_idx, _rec in self._call_edges(func, local_index, external_index):
                    function_edges[0].append(caller_idx)
                    function_edges[1].append(callee_idx)

            acfg_list = []
            for func in local_functions:
                blocks = getattr(func, "blocks", {}) or {}
                blockrefs = getattr(func, "blockrefs", {}) or {}
                block_addrs = sorted(blocks.keys())
                block_map = {addr: idx for idx, addr in enumerate(block_addrs)}
                cfg_data = {
                    "block_number": len(block_addrs),
                    "block_edges": [[], []],
                    "block_features": [],
                }
                for addr in block_addrs:
                    counts = {
                        "call": 0, "transfer": 0, "arithmetic": 0, "logic": 0, "compare": 0,
                        "move": 0, "termination": 0, "data_declaration": 0,
                        "total_instructions": 0, "constants": 0,
                    }
                    for ins in blocks[addr]:
                        counts["total_instructions"] += 1
                        m = (ins.mnemonic or "").strip().lower()
                        if m in ("call",):
                            counts["call"] += 1
                        elif m in ("jmp", "jz", "jnz", "je", "jne"):
                            counts["transfer"] += 1
                        elif m in ("add", "sub", "mul", "div"):
                            counts["arithmetic"] += 1
                        elif m in ("and", "or", "xor"):
                            counts["logic"] += 1
                        elif m == "cmp":
                            counts["compare"] += 1
                        elif m == "mov":
                            counts["move"] += 1
                        elif m in ("ret", "hlt"):
                            counts["termination"] += 1
                        elif m in ("db", "dw", "dd"):
                            counts["data_declaration"] += 1
                        else:
                            ops = getattr(ins, "operands", None) or []
                            if any(isinstance(o, (int, str)) and str(o).strip() for o in ops):
                                counts["constants"] += 1
                    offspring_count = len(blockrefs.get(addr) or [])
                    cfg_data["block_features"].append([
                        counts["call"], counts["transfer"], counts["arithmetic"], counts["logic"],
                        counts["compare"], counts["move"], counts["termination"],
                        counts["data_declaration"], counts["total_instructions"],
                        counts["constants"], offspring_count,
                    ])
                    src_idx = block_map.get(addr)
                    for succ in (blockrefs.get(addr) or []):
                        dst_idx = block_map.get(succ)
                        if src_idx is not None and dst_idx is not None:
                            cfg_data["block_edges"][0].append(src_idx)
                            cfg_data["block_edges"][1].append(dst_idx)
                acfg_list.append(cfg_data)

            return {
                "function_edges": function_edges,
                "acfg_list": acfg_list,
                "function_names": [_local_name(f) for f in local_functions] + external_names,
                "function_number": len(local_functions) + len(external_names),
                "hash": file_hash,
            }
        except Exception as exc:  # 与 BN 版一致：打印并返回 None，不中断批处理
            print(f"处理文件时出错(SMDA)：{exc}")
            return None
