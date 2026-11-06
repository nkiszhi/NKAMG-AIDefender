# -*- coding: utf-8 -*-
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
    import binaryninja as bn
    try: bn.log.log_to_stderr(bn.LogLevel.ErrorLog)
    except Exception: pass
    try: bn.disable_default_log()
    except Exception: pass
    from backend_bn import build_ir
except ImportError as e:
    print("FAIL\tNO_FILE\tno_binaryninja: %s" % e, flush=True)
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
        bv = bn.load(pe_path, options={
            "analysis.mode": "basic",
            "analysis.linearSweep.autorun": True,
            "analysis.limits.maxFunctionSize": 262144,
        })
        if bv is not None:
            bv.update_analysis_and_wait()
            ir = build_ir(bv)
            try:
                bv.file.close()
            except Exception:
                pass
            ir.save(ir_path)
            ok = True
            print("OK\t%s" % pe_path, flush=True)
        else:
            print("FAIL\t%s\tload_returned_None" % pe_path, flush=True)
    except Exception as e:
        print("FAIL\t%s\t%s" % (pe_path, str(e)[:120]), flush=True)
    if not ok and os.path.exists(ir_path) \
            and os.environ.get("CODEFENDER_KEEP_IR") != "1":
        try: os.remove(ir_path)
        except Exception: pass
    gc.collect()
