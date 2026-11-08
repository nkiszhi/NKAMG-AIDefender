"""Disposable analysis feature process (ProgramIR backend).

一次分析同时产出 **D/E 特征** 与 **MalGraph 输入**。

⚠ 2026-11-07：不再按后端分叉。
   原来这里是两条路：
     · BN 路：开一个 BinaryView，直接调 extractor._extract_disassembly /
             _extract_graphs，再把 binary_view 传给 MalGraph；
     · SMDA 路：feature_extraction/smda_extract.py 的 SmdaExtractor（另一条
             并行实现，与 features_from_ir.py 重复 —— 已删除）。
   现在两条路都走 **ProgramIR**：
     PE → feature_extraction.backend（按 CODEFENDER_DISASM_BACKEND 选 bn/smda）
        → feature_extraction.features_from_ir 算 D/E 特征
        → models/MalGraph_2022.utils 算 CFG/FCG
   → 同一份 IR 供给两路（SMDA 后端只分析一次，BN 需要 basic + full 两档）。

No model service imports or license rewriting.
"""
import pickle
import sys
import os
import signal
import threading
import time
from engine.staged_scan import analysis_timeout


def main():
    # A second watchdog prevents an orphaned native-analysis process if its parent exits.
    def hard_stop():
        if os.name == 'posix' and os.getpgrp() == os.getpid():
            os.killpg(os.getpgrp(), signal.SIGKILL)
        os._exit(124)
    timeout = analysis_timeout()
    watchdog = threading.Timer(timeout + 5, hard_stop)
    watchdog.daemon = True
    watchdog.start()
    sample_path, output_path = sys.argv[1:3]

    result = {'features': {}, 'malgraph': None, 'errors': {}, 'timing': {}}

    # ── 一次分析，两个用途 ──────────────────────────────────────────
    started = time.monotonic()
    features_ir = None
    graph_ir = None
    try:
        from feature_extraction.backend import build_ir_pair
        features_ir, graph_ir = build_ir_pair(sample_path)
    except Exception as error:
        result['errors']['analysis'] = str(error)
    result['timing']['analysis_seconds'] = round(time.monotonic() - started, 3)

    # ① D/E 特征（D01-D07 / E03-E04）
    started = time.monotonic()
    try:
        from feature_extraction.features_from_ir import all_features
        result['features'] = all_features(features_ir)
    except Exception as error:
        result['errors']['disassembly'] = str(error)
    finally:
        result['timing']['disassembly_features_seconds'] = round(time.monotonic() - started, 3)

    # ② MalGraph 输入（CFG / FCG）—— 直接用上面那份 IR，不再分析一遍
    started = time.monotonic()
    try:
        from models.MalGraph_2022.graph_from_ir import extract_cfg_and_fcg_from_ir
        malgraph = extract_cfg_and_fcg_from_ir(graph_ir, {})
        if malgraph:
            # 与 extract_cfg_and_fcg 的返回结构保持一致（含文件 hash）
            import hashlib
            h = hashlib.sha256()
            with open(sample_path, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            malgraph['hash'] = h.hexdigest()
        result['malgraph'] = malgraph
        if not malgraph:
            result['errors']['malgraph'] = 'No valid MalGraph features'
    except Exception as error:
        result['errors']['malgraph'] = str(error)
    finally:
        result['timing']['malgraph_features_seconds'] = round(time.monotonic() - started, 3)

    with open(output_path, 'wb') as handle:
        pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)


if __name__ == '__main__':
    main()
