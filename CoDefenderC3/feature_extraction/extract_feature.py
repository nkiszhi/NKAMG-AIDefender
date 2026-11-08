"""
BinaryNinja Feature Extractor — All 48 Features (§4.2.1, Appendix C)
======================================================================
Replaces LIEF + pefile + capstone + IDA/Ghidra with a single BinaryNinja API.

Dimensions:
  A. PE Structure  (A01-A15):  264 + imports + exports + security = ~600d
  B. Byte Stats    (B01-B07):  raw bytes + 256+256+256+8+65536+6 = ~66k
  C. Strings       (C01-C04):  variable + 10+30+256 = ~300d
  D. Disassembly   (D01-D07):  4096+256+256+15+12+10+6144 = ~10k
  E. Graph         (E01-E04):  graph structs + 12+10 = ~22d stats
  F. Visualization (F01-F04):  256²×8 = ~524k (images)
  G. Hashes        (G01-G04):  4×128 = 512d
  H. Metadata      (H01-H03):  ~60d

Usage:
    from feature_extractor import BinjaExtractor
    ext = BinjaExtractor()
    features = ext.extract_fast(pe_path)   # A/B/C/F/G/H (纯 Python)
    features.update(ext.extract_de_only(pe_path))   # D/E (走 ProgramIR)
    features = ext.extract_batch(paths, n_workers=8)

Requires: pip install binaryninja (commercial license)
"""
import os, sys, hashlib, math, struct, time
import logging
from collections import Counter, defaultdict
from typing import Dict, Optional
import numpy as np

logger = logging.getLogger("codefender.feature_extraction")

# 跨进程稳定的字符串哈希（feature hashing）
# 内置 hash(str) 每进程随机 → 训练(子进程)与推理(主进程)桶号不同 → 特征语义错位。
# 详见 feature_extraction/_stable_hash.py 的说明。
try:
    from ._stable_hash import stable_hash          # ① 包内导入: feature_extraction.extract_feature
except ImportError:
    try:
        from _stable_hash import stable_hash        # ② 同目录在 sys.path 上
    except ImportError:
        # ③ 兜底: 按本文件路径直接加载（不依赖 sys.path）。
        #    train/data_loader.py 的 _extract_fast_chunk 就是用 importlib 按路径
        #    加载本文件的 —— 那种场景下 feature_extraction/ 不在 sys.path 上，
        #    ②会失败，必须走这一级。
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "_stable_hash",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "_stable_hash.py"))
        _sh = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_sh)
        stable_hash = _sh.stable_hash

# BinaryNinja 运行时引导（路径注入 + 许可激活）—— 见 feature_extraction/bn_bootstrap.py
# 三级回退与上面 _stable_hash 同款:
#   ① 包内导入 feature_extraction.extract_feature（服务进程 / ProcessPool 子进程）
#   ② 同目录导入 extract_feature（worker 以顶层模块导入时）
#   ③ 按文件路径加载（train/data_loader.py 用 importlib 按路径加载本文件时）
try:
    from .bn_bootstrap import bootstrap_bn
except ImportError:
    try:
        from bn_bootstrap import bootstrap_bn
    except ImportError:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "_bn_bootstrap",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "bn_bootstrap.py"))
        _bm = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_bm)
        bootstrap_bn = _bm.bootstrap_bn

# BinaryNinja import (deferred to allow module-level import without crash)
_BN = None

def _env_int(name: str, default: int) -> int:
    """Helper to read integer from environment variable."""
    try:
        return int(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default


def _get_bn():
    global _BN
    if _BN is None:
        # 路径注入 + 许可激活必须在 import binaryninja 之前完成:
        #   ① BN 的 python 包目录不在 sys.path 上 → ModuleNotFoundError
        #   ② BN 不会自动读 license.dat → 未激活 → bn.load() 抛 C++ 异常
        #      (Windows Error 0xe06d7363) "Unable to create new BinaryView"
        bn = bootstrap_bn()
        _BN = bn
        
        # 设置BinaryNinja工作线程数（提升分析性能）
        # 默认2线程，可通过环境变量 BN_WORKER_THREADS 调整
        # 建议：4-8 线程（取决于CPU核心数）
        try:
            worker_threads = max(1, _env_int("BN_WORKER_THREADS", 8))
            bn.set_worker_thread_count(worker_threads)
        except Exception:
            pass
        
        # 抑制 BinaryNinja 分析日志 (warn/info), 只保留严重错误
        try:
            bn.log.log_to_stderr(bn.LogLevel.ErrorLog)
        except Exception:
            pass
        try:
            bn.disable_default_log()
        except Exception:
            pass
    return _BN


# ═══════════════════════════════════════
#  Constants
# ═══════════════════════════════════════
MAX_BYTES     = 2 * 1024 * 1024   # 2MB max for raw byte sequence (B01)
MAX_SECTIONS  = 48                # zero-pad sections to this count (A04)
MAX_OPCODES   = 4096              # opcode sequence length (D01)
MAX_FUNCTIONS = 48                # functions for Asm embedding (D07)
IMPORT_BUCKETS = 256              # import hash bucket count (A06)
IMG_SIZE       = 256              # visualization image size (F01-F04)
NGRAM_DIM      = 256              # n-gram TF-IDF output dim (D02-D03)
ENTROPY_BINS   = 256              # entropy histogram bins (B04)
BLOCK_SIZE     = 1024             # entropy block size
STR_MAX_STRINGS = 5000            # 字符串条数上限 (C01-C04)
STR_C01_STRINGS = 2000            # C01 参与统计的字符串条数
STR_C04_STRINGS = 200             # C04 参与 n-gram 统计的字符串条数

# x86 instruction categories (15 classes, D04)
INSN_CATEGORIES = {
    "arithmetic": {"add","sub","mul","imul","div","idiv","inc","dec","neg","adc","sbb"},
    "logic":      {"and","or","xor","not","shl","shr","sar","sal","rol","ror","rcl","rcr"},
    "transfer":   {"mov","movzx","movsx","lea","xchg","cmov","movaps","movdqa"},
    "branch":     {"jmp","je","jne","jz","jnz","jg","jl","jge","jle","ja","jb","jae","jbe",
                   "call","ret","loop","int"},
    "stack":      {"push","pop","pusha","popa","pushf","popf","enter","leave"},
    "string":     {"movs","cmps","scas","lods","stos","rep","repe","repne"},
    "flag":       {"stc","clc","cmc","std","cld","sti","cli","lahf","sahf"},
    "float":      {"fld","fst","fstp","fadd","fsub","fmul","fdiv","fcom","fxch"},
    "simd":       {"addps","mulps","subps","divps","paddb","paddw","paddd","pxor",
                   "xmm","ymm","zmm"},
    "system":     {"syscall","sysenter","rdtsc","cpuid","rdmsr","wrmsr","hlt","in","out"},
    "nop":        {"nop"},
    "interrupt":  {"int","int3","iret"},
    "io":         {"in","out","ins","outs"},
    "prefix":     {"lock","rep","repz","repnz","cs","ds","es","fs","gs","ss"},
}
# Flatten for lookup
_CAT_LOOKUP = {}
for cat, mnemonics in INSN_CATEGORIES.items():
    for m in mnemonics:
        _CAT_LOOKUP[m] = cat
_CAT_NAMES = list(INSN_CATEGORIES.keys()) + ["other"]  # 15 categories


# ═══════════════════════════════════════
#  Main Extractor
# ═══════════════════════════════════════

class BinjaExtractor:
    """
    Extract all 48 features from a PE binary using BinaryNinja.
    
    两阶段架构:
      阶段1: PE → .bndb (BinaryNinja 分析, ~60s, 只做一次)
      阶段2: .bndb → features (秒开, 可反复重跑)
    
    BinaryNinja replaces:
      - LIEF/pefile  → sections, symbols
      - capstone     → disassembly_text
      - IDA/Ghidra   → functions, basic_blocks, callgraph
    """

    def __init__(self, headless=True, require_bn=False):
        # 延迟加载: 不在构造时 import binaryninja
        # （BN 专用的 .bndb 批量缓存路径已删除：D/E 统一走 ProgramIR / IR 缓存）
        # 这些方法通过子进程使用 BN, 不需要 Master 自身加载 BN C 核心
        # 在 Master 中加载 BN 会导致 Windows 上 ACCESS_VIOLATION (0xC0000005)
        self.bn = None
        self._headless = headless
        self._require_bn = require_bn

    def _ensure_bn(self):
        """按需加载 BinaryNinja — 只在真正需要直接调用 BN API 时使用。"""
        if self.bn is None:
            try:
                self.bn = _get_bn()
            except Exception:
                if self._require_bn:
                    raise

    # ─── 快速提取: 纯 Python, 不需要 BinaryNinja ──────
    #
    # 覆盖 11/16 视角, 24/33 模型:
    #   B01-B07 (V1_byte, V2_byte_stat), F01-F04 (V8_*),
    #   A01-A08 (V3_pe_struct, V4_import), C01-C04 (V5_string),
    #   G01-G04 (V9_hash), H01-H03 (V10_metadata)
    #
    # 不覆盖 (需要 BinaryNinja 反汇编):
    #   D01-D07 (V6_opcode_seq, V6_opcode_stat, V6_func_embed)
    #   E01-E04 (V7_graph)

    def extract_fast(self, pe_path: str) -> Dict[str, np.ndarray]:
        """纯 Python 特征提取 (不需要 BinaryNinja), 毫秒级。"""
        with open(pe_path, "rb") as f:
            raw = f.read()
        # 解析 pefile 一次, 所有需要的特征共用
        pe_obj = None
        try:
            import pefile
            pe_obj = pefile.PE(data=raw, fast_load=True)
            pe_obj.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            ])
        except Exception:
            pass
        features = {}
        for stage_fn in [
            lambda: self._extract_pe_structure_fast(raw, pe_obj),
            lambda: self._extract_byte_stats(raw),
            lambda: self._extract_strings_fast(raw),
            lambda: self._extract_visualization(raw),
            lambda: self._extract_hashes_fast(raw, pe_obj),
            lambda: self._extract_metadata_fast(raw),
        ]:
            try:
                features.update(stage_fn())
            except Exception:
                pass
        if pe_obj:
            try: pe_obj.close()
            except: pass
        return features

    def _extract_pe_structure_fast(self, raw, pe_obj=None):
        """A01-A08: PE 结构特征, 纯 struct 解析 (不需要 BinaryNinja)。"""
        feats = {}

        # A01: DOS Header (15d)
        dos = np.zeros(15, dtype=np.float32)
        if len(raw) >= 64:
            dos[0] = struct.unpack_from("<H", raw, 0)[0]
            dos[1] = struct.unpack_from("<I", raw, 60)[0] if len(raw) > 63 else 0
            dos[2] = len(raw)
            for i in range(3, min(15, 30)):
                off = i * 2
                if off + 2 <= 64:
                    dos[i] = struct.unpack_from("<H", raw, off)[0]
        feats["A01"] = dos

        # A02: COFF Header (7d)
        coff = np.zeros(7, dtype=np.float32)
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0] if len(raw) > 0x3F else 0
        if pe_off + 24 <= len(raw) and raw[pe_off:pe_off+4] == b"PE\x00\x00":
            hdr = raw[pe_off+4:pe_off+24]
            if len(hdr) >= 20:
                coff[0] = struct.unpack_from("<H", hdr, 0)[0]   # Machine
                coff[1] = struct.unpack_from("<H", hdr, 2)[0]   # NumberOfSections
                coff[2] = struct.unpack_from("<I", hdr, 4)[0]   # TimeDateStamp
                coff[3] = struct.unpack_from("<I", hdr, 8)[0]   # PointerToSymbolTable
                coff[4] = struct.unpack_from("<I", hdr, 12)[0]  # NumberOfSymbols
                coff[5] = struct.unpack_from("<H", hdr, 16)[0]  # SizeOfOptionalHeader
                coff[6] = struct.unpack_from("<H", hdr, 18)[0]  # Characteristics
        feats["A02"] = coff

        # A03: Optional Header (30d)
        opt = np.zeros(30, dtype=np.float32)
        opt_off = pe_off + 24
        if opt_off + 96 <= len(raw):
            opt[0] = struct.unpack_from("<H", raw, opt_off)[0]  # Magic
            if opt[0] == 0x20B:  # PE32+
                if opt_off + 112 <= len(raw):
                    opt[1] = struct.unpack_from("<Q", raw, opt_off + 24)[0]  # ImageBase
                    opt[2] = struct.unpack_from("<I", raw, opt_off + 32)[0]  # SectionAlignment
                    opt[3] = struct.unpack_from("<I", raw, opt_off + 36)[0]  # FileAlignment
                    opt[4] = struct.unpack_from("<I", raw, opt_off + 56)[0]  # SizeOfImage
                    opt[5] = struct.unpack_from("<I", raw, opt_off + 60)[0]  # SizeOfHeaders
                    opt[6] = struct.unpack_from("<Q", raw, opt_off + 64)[0]  # SizeOfStackReserve
                    opt[7] = struct.unpack_from("<I", raw, opt_off + 84)[0]  # NumberOfRvaAndSizes
                    opt[8] = struct.unpack_from("<I", raw, opt_off + 16)[0]  # AddressOfEntryPoint
            else:  # PE32
                opt[1] = struct.unpack_from("<I", raw, opt_off + 28)[0]  # ImageBase
                opt[2] = struct.unpack_from("<I", raw, opt_off + 32)[0]
                opt[3] = struct.unpack_from("<I", raw, opt_off + 36)[0]
                opt[4] = struct.unpack_from("<I", raw, opt_off + 56)[0]
                opt[5] = struct.unpack_from("<I", raw, opt_off + 60)[0]
                opt[6] = struct.unpack_from("<I", raw, opt_off + 72)[0]
                opt[7] = struct.unpack_from("<I", raw, opt_off + 76)[0]
                opt[8] = struct.unpack_from("<I", raw, opt_off + 16)[0]
        feats["A03"] = opt

        # A04: Section Features (MAX_SECTIONS × 4 = 192d)
        n_sec = int(coff[1])
        opt_hdr_size = int(coff[5])
        sec_off = pe_off + 24 + opt_hdr_size
        sec_feats = np.zeros(MAX_SECTIONS * 4, dtype=np.float32)
        for i in range(min(n_sec, MAX_SECTIONS)):
            s = sec_off + i * 40
            if s + 40 > len(raw):
                break
            base = i * 4
            sec_feats[base] = struct.unpack_from("<I", raw, s + 8)[0]   # VirtualSize
            sec_feats[base+1] = struct.unpack_from("<I", raw, s + 16)[0]  # SizeOfRawData
            raw_ptr = struct.unpack_from("<I", raw, s + 20)[0]
            raw_sz = struct.unpack_from("<I", raw, s + 16)[0]
            if raw_ptr < len(raw) and raw_sz > 0:
                sec_data = raw[raw_ptr:raw_ptr + min(raw_sz, 65536)]
                sec_feats[base+2] = self._entropy(sec_data)
            sec_feats[base+3] = struct.unpack_from("<I", raw, s + 36)[0]  # Characteristics
        feats["A04"] = sec_feats

        # A05: Section Anomaly (20d)
        anom = np.zeros(20, dtype=np.float32)
        for i in range(min(n_sec, 10)):
            s = sec_off + i * 40
            if s + 40 > len(raw):
                break
            vsize = struct.unpack_from("<I", raw, s + 8)[0]
            anom[i*2] = 1.0 if vsize == 0 else 0.0
            anom[i*2+1] = 1.0 if vsize > 10*1024*1024 else 0.0
        feats["A05"] = anom

        # A06: Import Table (256d hash-bucketed)
        imp = np.zeros(IMPORT_BUCKETS, dtype=np.float32)
        try:
            if pe_obj and hasattr(pe_obj, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        name = (func.name or b"").decode("ascii", errors="ignore")
                        if name:
                            imp[stable_hash(name) % IMPORT_BUCKETS] += 1
                if imp.sum() > 0:
                    imp /= imp.sum()
        except Exception:
            pass
        feats["A06"] = imp

        # A07: Export Table (32d)
        exp = np.zeros(32, dtype=np.float32)
        try:
            if pe_obj and hasattr(pe_obj, 'DIRECTORY_ENTRY_EXPORT'):
                exp[0] = len(pe_obj.DIRECTORY_ENTRY_EXPORT.symbols)
                exp[1] = sum(1 for s in pe_obj.DIRECTORY_ENTRY_EXPORT.symbols if s.name)
        except Exception:
            pass
        feats["A07"] = exp

        # A08_A15: Security metadata (51d)
        sec_meta = np.zeros(51, dtype=np.float32)
        sec_meta[0] = 1.0 if b"Rich" in raw[:1024] else 0.0
        sec_meta[1] = float(len(raw))
        feats["A08_A15"] = sec_meta

        return feats

    # ─── C01-C04: 字符串特征（唯一实现）────────────────────────
    #
    # ⚠ 2026-11-05 统一：此前存在两套口径互不一致的实现 ——
    #   _extract_strings_fast（纯 regex，生产路径，train/ 与 engine/ 都用它）
    #   _extract_strings    （BinaryNinja 全量路径，目前仅离线/调试使用）
    #   差异：· C02[4] fast = URL 字符串「个数」；BN 版 = 含大写字母字符串「比例」
    #         · C01    fast 无 log1p；BN 版有 log1p
    #         · 截断   fast 只取 2000 条；BN 版不截断
    #   现统一到 _string_features()，两条路径共用 → 同一字符串集合必得同一向量。

    def _string_features(self, strings):
        """C01-C04: 由字符串列表算出 4 组字符串特征。

        口径（训练侧 extract_fast 与推理侧 extract 共用，勿单方面改）：
          · 字符串最多取 STR_MAX_STRINGS (5000) 条
          · C01 只用前 STR_C01_STRINGS (2000) 条
          · C04 只用前 STR_C04_STRINGS (200) 条
          · C02[4] = URL 类字符串的**个数**（含 "http" / "www"）
          · C01/C04 计数后统一 log1p → 归一化
        """
        feats = {}
        strings = list(strings)[:STR_MAX_STRINGS]

        # C01: String embedding (256d hash trick)
        c01 = np.zeros(256, dtype=np.float32)
        for s in strings[:STR_C01_STRINGS]:
            c01[stable_hash(s) % 256] += 1
        if c01.sum() > 0:
            c01 = np.log1p(c01)
            c01 /= c01.max() + 1e-8
        feats["C01"] = c01

        # C02: String statistics (10d)
        c02 = np.zeros(10, dtype=np.float32)
        c02[0] = len(strings)
        if strings:
            lens = [len(s) for s in strings]
            c02[1] = np.mean(lens)
            c02[2] = np.max(lens)
            c02[3] = np.std(lens)
            c02[4] = sum(1 for s in strings if "http" in s.lower() or "www" in s.lower())
            c02[5] = sum(1 for s in strings if s.startswith("http")) / max(len(strings), 1)
            c02[6] = sum(1 for s in strings if "\\" in s or "/" in s) / max(len(strings), 1)
            c02[7] = sum(1 for s in strings if ".dll" in s.lower()) / max(len(strings), 1)
            c02[8] = sum(1 for s in strings if ".exe" in s.lower()) / max(len(strings), 1)
            c02[9] = sum(1 for s in strings if any(c.isdigit() for c in s)) / max(len(strings), 1)
        feats["C02"] = c02

        # C03: Sensitive pattern matching (31d)
        patterns = [
            "cmd", "powershell", "reg", "net ", "http", "ftp",
            "encrypt", "decrypt", "password", "admin", "root",
            "kernel32", "ntdll", "ws2_32", "advapi32", "shell32",
            "create", "write", "delete", "execute", "inject",
            "mutex", "pipe", "socket", "connect", "download",
            "registry", "service", "process", "thread", "hook",
        ]
        c03 = np.zeros(len(patterns), dtype=np.float32)
        all_text = " ".join(strings).lower()
        for i, p in enumerate(patterns):
            c03[i] = float(p in all_text)
        feats["C03"] = c03

        # C04: String n-gram embedding (256d)
        c04 = np.zeros(256, dtype=np.float32)
        for s in strings[:STR_C04_STRINGS]:
            for i in range(len(s) - 2):
                c04[stable_hash(s[i:i+3]) % 256] += 1
        if c04.sum() > 0:
            c04 = np.log1p(c04)
            c04 /= np.linalg.norm(c04) + 1e-8
        feats["C04"] = c04

        return feats

    def _extract_strings_fast(self, raw):
        """C01-C04: 字符串特征, 纯 regex (不需要 BinaryNinja)。"""
        import re
        strings = [s.decode("ascii", errors="ignore")
                   for s in re.findall(rb'[\x20-\x7e]{4,}', raw[:2*1024*1024])]
        return self._string_features(strings)

    def _extract_hashes_fast(self, raw, pe_obj=None):
        """G01-G04: 哈希特征, 纯 Python。"""
        feats = {}

        # G01: Import hash (128d) — 用共享 pe_obj
        g01 = np.zeros(128, dtype=np.float32)
        try:
            imports = []
            if pe_obj and hasattr(pe_obj, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        name = (func.name or b"").decode("ascii", errors="ignore")
                        if name:
                            imports.append(name)
            imphash_str = ",".join(sorted(imports)).lower()
            h = hashlib.md5(imphash_str.encode()).digest()
            for i, b in enumerate(h):
                g01[i*8:(i+1)*8] = [(b >> j) & 1 for j in range(8)]
        except Exception:
            pass
        feats["G01"] = g01

        # G02: ssdeep-like (128d)
        g02 = np.zeros(128, dtype=np.float32)
        chunk_size = max(len(raw) // 128, 64)
        for i in range(128):
            off = i * chunk_size
            blk = raw[off:off+chunk_size] if off < len(raw) else b"\x00"
            g02[i] = int(hashlib.md5(blk).hexdigest()[:4], 16) / 65536.0
        feats["G02"] = g02

        # G03: TLSH-like (128d)
        g03 = np.zeros(128, dtype=np.float32)
        for i in range(min(128, len(raw) // 64)):
            blk = raw[i*64:(i+1)*64]
            g03[i] = sum(blk) / (64 * 255)
        feats["G03"] = g03

        # G04: Rich header hash (128d)
        g04 = np.zeros(128, dtype=np.float32)
        rich_start = raw.find(b"Rich")
        if rich_start > 0:
            rich_data = raw[:rich_start+4]
            h = hashlib.sha256(rich_data).digest()
            for i in range(min(128, len(h)*4)):
                g04[i] = ((h[i//4] >> (i%4*2)) & 3) / 3.0
        feats["G04"] = g04

        return feats

    def _extract_metadata_fast(self, raw):
        """H01-H03: 元数据特征, 纯 Python。"""
        feats = {}
        h01 = np.zeros(20, dtype=np.float32)
        vi_off = raw.find(b"VS_VERSION_INFO")
        h01[0] = 1.0 if vi_off >= 0 else 0.0
        h01[1] = float(vi_off) / max(len(raw), 1) if vi_off >= 0 else 0
        feats["H01"] = h01

        h02 = np.zeros(20, dtype=np.float32)
        h02[0] = 1.0 if b".rsrc" in raw else 0.0
        feats["H02"] = h02

        h03 = np.zeros(20, dtype=np.float32)
        h03[0] = 1.0 if b"<?xml" in raw else 0.0
        h03[1] = 1.0 if b"requestedExecutionLevel" in raw else 0.0
        h03[2] = 1.0 if b"requireAdministrator" in raw else 0.0
        h03[3] = 1.0 if b"asInvoker" in raw else 0.0
        feats["H03"] = h03

        return feats

    # ─── 仅提取 D+E (需要 BinaryNinja 反汇编) ──────

    def extract_de_only(self, pe_path: str) -> Dict[str, np.ndarray]:
        """只提取 D01-D07 + E03-E04。

        ⚠ 已切到 **ProgramIR**（2026-11-07）：**不再直接依赖 BinaryNinja**。
           反汇编后端由 feature_extraction.backend 按
           CODEFENDER_DISASM_BACKEND 选（bn / smda），
           特征计算在 feature_extraction/features_from_ir.py。

           旧实现（_extract_disassembly(bv) / _extract_graphs(bv)）已删除 ——
           它们与 features_from_ir.py 是同一套算法的两份实现，留着必然漂移。

           ⚠ **口径变化（重要）**：旧实现取 tokens[0].text 当助记符，而 BN 5.x
              的 tokens[0] 是**空的地址分隔符** → D01-D07 实际装的是
              "{ Does not return }" 这类**注解文本**，不是助记符。
              IR 路径装的是真正的助记符。
              → **D01-D07 的语义变了**，依赖它们的 V6 系列模型
                （opcode_seq / func_embed / opcode_stat）**必须重训**，
                否则推理输入与训练分布错位。
              详见 docs/IR_CONTRACT.md 第 11 / 13 节。
        """
        if not os.path.exists(pe_path):
            raise FileNotFoundError(pe_path)
        from feature_extraction.backend import build_ir_for_features
        from feature_extraction.features_from_ir import all_features
        ir = build_ir_for_features(pe_path)
        return all_features(ir)
    def _extract_byte_stats(self, raw):
        feats = {}

        # B01: Raw byte sequence (truncated/padded to MAX_BYTES)
        # 存储为整数 [0, 255]: V1 字节模型的 Embedding 层需要整数索引
        # B01 用 uint8 存储（B01-fix 2026-09-15）：原 int64 使单样本 npz 膨胀到
        # ~18MB（10k 样本 ≈ 180GB，超出磁盘容量）。两个消费方均显式转型——
        # data_loader.py:826 `.astype(np.int32)`、engine/app.py:636
        # `_to_numpy_1d(..., np.int32)`，uint8 → int32 无损。
        b01 = np.zeros(MAX_BYTES, dtype=np.uint8)
        n = min(len(raw), MAX_BYTES)
        b01[:n] = np.frombuffer(raw[:n], dtype=np.uint8)
        feats["B01"] = b01

        # B02: 1-gram histogram (256d)
        counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
        feats["B02"] = (counts / max(len(raw), 1)).astype(np.float32)

        # B03: 2-gram histogram (256d, XOR-folded from 65536 pairs)
        arr = np.frombuffer(raw, dtype=np.uint8)
        if len(arr) >= 2:
            bigram_full = arr[:-1].astype(np.int32) * 256 + arr[1:].astype(np.int32)
            # XOR fold: 高字节 XOR 低字节, 保留两个字节的信息
            bigrams = np.bincount((bigram_full >> 8) ^ (bigram_full & 0xFF),
                                  minlength=256).astype(np.float32)
            if bigrams.sum() > 0:
                bigrams /= bigrams.sum()
        else:
            bigrams = np.zeros(256, dtype=np.float32)
        feats["B03"] = bigrams

        # B04: Entropy histogram (256d) — vectorized
        block_ents = self._block_entropies(raw, BLOCK_SIZE)
        ent_hist = np.zeros(ENTROPY_BINS, dtype=np.float32)
        bin_indices = np.clip((block_ents / 8.0 * ENTROPY_BINS).astype(int), 0, ENTROPY_BINS - 1)
        np.add.at(ent_hist, bin_indices, 1)
        if ent_hist.sum() > 0:
            ent_hist /= ent_hist.sum()
        feats["B04"] = ent_hist

        # B05: Global entropy statistics (8d) — using precomputed block entropies
        ent_stat = np.zeros(8, dtype=np.float32)
        ent_stat[0] = self._entropy(raw)
        split = min(1024, len(raw))
        ent_stat[1] = self._entropy(raw[:split])
        ent_stat[2] = self._entropy(raw[split:]) if len(raw) > split else 0
        if len(block_ents) > 0:
            ent_stat[3] = float(block_ents.max())
            ent_stat[4] = float(block_ents.min())
            ent_stat[5] = float(block_ents.mean())
            ent_stat[6] = float(block_ents.std())
        ent_stat[7] = len(raw) / (MAX_BYTES + 1)
        feats["B05"] = ent_stat

        # B06: Markov transition matrix (256d row-entropy summary)
        arr = np.frombuffer(raw, dtype=np.uint8)
        if len(arr) >= 2:
            # Vectorized: build 256×256 transition count matrix
            pairs = arr[:-1].astype(np.int32) * 256 + arr[1:].astype(np.int32)
            flat_counts = np.bincount(pairs, minlength=65536)
            markov = flat_counts.reshape(256, 256).astype(np.float64)
            row_sums = markov.sum(axis=1, keepdims=True)
            row_sums[row_sums == 0] = 1
            markov /= row_sums
            # Row entropy
            with np.errstate(divide='ignore', invalid='ignore'):
                log_m = np.where(markov > 0, np.log2(markov), 0.0)
            row_entropy = -np.sum(markov * log_m, axis=1)
        else:
            row_entropy = np.zeros(256, dtype=np.float64)
        feats["B06"] = row_entropy.astype(np.float32)

        # B07: File size features (6d)
        fsz = np.zeros(6, dtype=np.float32)
        fsz[0] = len(raw)
        fsz[1] = np.log1p(len(raw))
        fsz[2] = len(raw) % 512
        fsz[3] = 1.0 if len(raw) % 512 == 0 else 0.0
        fsz[4] = len(raw) / MAX_BYTES
        fsz[5] = 1.0 if len(raw) > MAX_BYTES else 0.0
        feats["B07"] = fsz

        return feats

    # ═══════════════════════════════════════
    #  C: Strings (Appendix C.1)
    # ═══════════════════════════════════════

    def _extract_visualization(self, raw):
        feats = {}

        # F01: Grayscale image (256×256)
        feats["F01"] = self._bytes_to_image(raw, channels=1)

        # F02: Color image via Hilbert-style mapping (256×256×3)
        feats["F02"] = self._bytes_to_color_image(raw)

        # F03: Markov transition image (256×256) — vectorized
        arr = np.frombuffer(raw, dtype=np.uint8)
        if len(arr) >= 2:
            pairs = arr[:-1].astype(np.int32) * 256 + arr[1:].astype(np.int32)
            flat_counts = np.bincount(pairs, minlength=65536)
            markov_img = flat_counts.reshape(256, 256).astype(np.float32)
            row_max = markov_img.max(axis=1, keepdims=True)
            row_max[row_max == 0] = 1
            feats["F03"] = markov_img / row_max
        else:
            feats["F03"] = np.zeros((256, 256), dtype=np.float32)

        # F04: Entropy heatmap (256×256) — bincount 偏移技巧
        grid = IMG_SIZE
        total_cells = grid * grid
        chunk = max(len(raw) // total_cells, 1)
        if len(raw) >= total_cells and chunk >= 4:
            usable = total_cells * chunk
            cells = np.frombuffer(raw[:usable], dtype=np.uint8).reshape(total_cells, chunk)
            offsets = np.arange(total_cells, dtype=np.int32).repeat(chunk) * 256
            flat_idx = offsets + cells.ravel().astype(np.int32)
            counts = np.bincount(flat_idx, minlength=total_cells * 256).reshape(total_cells, 256)
            probs = counts.astype(np.float32) / chunk
            with np.errstate(divide='ignore', invalid='ignore'):
                log_p = np.where(probs > 0, np.log2(probs), 0.0)
            cell_ent = -np.sum(probs * log_p, axis=1) / 8.0
            feats["F04"] = cell_ent.reshape(grid, grid).astype(np.float32)
        else:
            feats["F04"] = np.zeros((grid, grid), dtype=np.float32)

        return feats

    def _bytes_to_image(self, raw, channels=1):
        """Reshape bytes to 256×256 grayscale (Nataraj et al. 2011)."""
        arr = np.frombuffer(raw[:IMG_SIZE*IMG_SIZE], dtype=np.uint8).astype(np.float32) / 255.0
        if len(arr) < IMG_SIZE * IMG_SIZE:
            arr = np.pad(arr, (0, IMG_SIZE*IMG_SIZE - len(arr)))
        return arr.reshape(IMG_SIZE, IMG_SIZE)

    def _bytes_to_color_image(self, raw):
        """RGB image from byte triplets."""
        n = min(len(raw), IMG_SIZE*IMG_SIZE*3)
        arr = np.frombuffer(raw[:n], dtype=np.uint8).astype(np.float32) / 255.0
        needed = IMG_SIZE * IMG_SIZE * 3
        if len(arr) < needed:
            arr = np.pad(arr, (0, needed - len(arr)))
        return arr.reshape(IMG_SIZE, IMG_SIZE, 3)

    # ═══════════════════════════════════════
    #  G: Hashes (Appendix C.6)
    # ═══════════════════════════════════════

    @staticmethod
    def _entropy(data):
        """Shannon entropy in bits — vectorized."""
        if not data or len(data) == 0:
            return 0.0
        arr = np.frombuffer(data if isinstance(data, bytes) else bytes(data), dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts / len(arr)
        mask = probs > 0
        return float(-np.dot(probs[mask], np.log2(probs[mask])))

    @staticmethod
    def _block_entropies(raw, block_size=1024):
        """Block entropy — 单次 bincount, O(n)。"""
        n = len(raw)
        if n == 0:
            return np.array([0.0])
        arr = np.frombuffer(raw, dtype=np.uint8)
        n_blocks = max(1, n // block_size)
        trimmed = arr[:n_blocks * block_size].reshape(n_blocks, block_size)
        # 偏移技巧: 每个 block 的字节值偏移 block_id * 256
        offsets = np.arange(n_blocks, dtype=np.int32).repeat(block_size) * 256
        flat_idx = offsets + trimmed.ravel().astype(np.int32)
        counts = np.bincount(flat_idx, minlength=n_blocks * 256).reshape(n_blocks, 256)
        probs = counts.astype(np.float32) / block_size
        with np.errstate(divide='ignore', invalid='ignore'):
            log_probs = np.where(probs > 0, np.log2(probs), 0.0)
        return -np.sum(probs * log_probs, axis=1)

    @staticmethod
    def feature_dims():
        """Return dict of {feature_id: dimension} for all 48 features."""
        return {
            "A01": 15, "A02": 7, "A03": 30, "A04": 192, "A05": 20,
            "A06": 256, "A07": 32, "A08_A15": 51,
            "B01": MAX_BYTES, "B02": 256, "B03": 256, "B04": 256,
            "B05": 8, "B06": 256, "B07": 6,
            "C01": 256, "C02": 10, "C03": 31, "C04": 256,
            "D01": MAX_OPCODES, "D02": NGRAM_DIM, "D03": NGRAM_DIM,
            "D04": 15, "D05": 12, "D06": 10, "D07": MAX_FUNCTIONS * 128,
            "E03": 12, "E04": 10,
            "F01": IMG_SIZE*IMG_SIZE, "F02": IMG_SIZE*IMG_SIZE*3,
            "F03": 256*256, "F04": IMG_SIZE*IMG_SIZE,
            "G01": 128, "G02": 128, "G03": 128, "G04": 128,
            "H01": 20, "H02": 20, "H03": 20,
        }

# ═══════════════════════════════════════
#  样本扫描工具 (run脚本使用)
# ═══════════════════════════════════════

def scan_load_samples(data_root):
    """
    扫描数据目录, 返回 [(文件路径, 标签)] 列表

    支持目录结构:
      data_root/malware/*.exe  → label=1
      data_root/benign/*.exe   → label=0
    """
    samples = []
    label_dirs = {
        1: ["malware", "malicious", "positive", "mal", "1"],
        0: ["benign", "clean", "negative", "ben", "goodware", "0"],
    }
    for label, dirnames in label_dirs.items():
        for dirname in dirnames:
            d = os.path.join(data_root, dirname)
            if not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.path.isfile(fp):
                    samples.append((fp, label))
    if samples:
        print(f"[scan] {data_root}: {len(samples)} samples "
              f"({sum(1 for _,y in samples if y==1)} mal, "
              f"{sum(1 for _,y in samples if y==0)} ben)")
    return samples


def scan_load_prediction_samples(predict_dir):
    """
    扫描预测目录, 返回 [(文件路径, -1)] 列表 (标签未知)
    """
    samples = []
    if not os.path.isdir(predict_dir):
        return samples
    for f in os.listdir(predict_dir):
        fp = os.path.join(predict_dir, f)
        if os.path.isfile(fp):
            samples.append((fp, -1))
    print(f"[scan] {predict_dir}: {len(samples)} prediction samples")
    return samples
