# -*- coding: utf-8 -*-
"""IR worker：把一批 PE 转成 .ir.json.gz。

⚠ 2026-11-07：不再硬编码 BinaryNinja —— 走 feature_extraction.backend 的
   后端调度（CODEFENDER_DISASM_BACKEND=bn|smda）。BN 只是**一种**后端。
"""
import sys, os, gc

# Windows: 禁止 crash 弹出 WER 对话框（与 _bndb_worker.py 一致）
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x0002 | 0x8000)
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from backend import build_ir_for_features
except ImportError as e:
    print("FAIL\tNO_FILE\tno_backend: %s" % e, flush=True)
    sys.exit(0)

# 参数文件: 每行 pe_path\tir_path
with open(sys.argv[1], "r", encoding="utf-8") as f:
    lines = f.read().strip().split("\n")

for line in lines:
    parts = line.strip().split("\t")
    if len(parts) != 2:
        continue
    pe_path, ir_path = parts
    ok = False
    try:
        ir = build_ir_for_features(pe_path)
        ir.save(ir_path)
        ok = True
        print("OK\t%s" % pe_path, flush=True)
    except Exception as e:
        print("FAIL\t%s\t%s" % (pe_path, str(e)[:120]), flush=True)
    if not ok and os.path.exists(ir_path) \
            and os.environ.get("CODEFENDER_KEEP_IR") != "1":
        try:
            os.remove(ir_path)
        except Exception:
            pass
    gc.collect()
