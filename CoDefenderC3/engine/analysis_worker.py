"""Disposable analysis feature process (BinaryNinja or SMDA).

No model service imports or license rewriting.
后端由 CODEFENDER_DISASM_BACKEND 决定：smda（默认，无需商业授权、不挂死）或 bn。
"""
import pickle
import sys
import os
import signal
import threading
import time
from engine.staged_scan import analysis_timeout


def load_analysis_view(bn, sample_path):
    # MalGraph reads func.mlil: basic analysis only provides LLIL.
    # intermediate produces MLIL without requesting full HLIL analysis.
    bv = bn.load(sample_path, options={
        'analysis.mode': 'intermediate', 'analysis.linearSweep.autorun': True,
        'analysis.limits.maxFunctionSize': 262144,
    })
    if bv is None:
        raise RuntimeError('BinaryNinja could not open the PE')
    return bv


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
    backend = os.environ.get('CODEFENDER_DISASM_BACKEND', 'smda').strip().lower() or 'smda'
    if backend == 'smda':
        _run_smda(sample_path, output_path, timeout)
        return

    import binaryninja as bn
    from feature_extraction.extract_feature import BinjaExtractor

    try:
        bn.disable_default_log()
        bn.log.log_to_stderr(bn.LogLevel.ErrorLog)
    except Exception:
        pass

    result = {'features': {}, 'malgraph': None, 'errors': {}, 'timing': {}}
    started = time.monotonic()
    bv = load_analysis_view(bn, sample_path)
    result['timing']['binaryninja_load_seconds'] = round(time.monotonic() - started, 3)
    try:
        extractor = BinjaExtractor()
        extractor.bn = bn
        for name, operation in [('disassembly', extractor._extract_disassembly),
                                ('graphs', extractor._extract_graphs)]:
            started = time.monotonic()
            try:
                result['features'].update(operation(bv))
            except Exception as error:
                result['errors'][name] = str(error)
            finally:
                result['timing'][name + '_features_seconds'] = round(time.monotonic() - started, 3)
        started = time.monotonic()
        try:
            from models.MalGraph_2022.utils import extract_cfg_and_fcg
            result['malgraph'] = extract_cfg_and_fcg(sample_path, {}, binary_view=bv)
            if not result['malgraph']:
                result['errors']['malgraph'] = 'No valid MalGraph features'
        except Exception as error:
            result['errors']['malgraph'] = str(error)
        finally:
            result['timing']['malgraph_features_seconds'] = round(time.monotonic() - started, 3)
    finally:
        bv.file.close()
    with open(output_path, 'wb') as handle:
        pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)


def _run_smda(sample_path, output_path, timeout):
    """SMDA 后端：一次分析同时产出 D/E 特征与 MalGraph 输入。

    与 BN 版不同，SMDA 在同一进程里完成函数/基本块/调用关系的提取，
    因此不再需要把 binary_view 传给 MalGraph。
    """
    from feature_extraction.smda_extract import SmdaExtractor
    result = {'features': {}, 'malgraph': None, 'errors': {}, 'timing': {}}
    started = time.monotonic()
    extractor = SmdaExtractor(timeout=max(30, timeout))
    try:
        result['features'] = extractor.extract_de(sample_path)
    except Exception as error:
        result['errors']['disassembly'] = str(error)
    finally:
        result['timing']['disassembly_features_seconds'] = round(time.monotonic() - started, 3)
    started = time.monotonic()
    try:
        from models.MalGraph_2022.utils import extract_cfg_and_fcg
        result['malgraph'] = extract_cfg_and_fcg(sample_path, {})
        if not result['malgraph']:
            result['errors']['malgraph'] = 'No valid MalGraph features'
    except Exception as error:
        result['errors']['malgraph'] = str(error)
    finally:
        result['timing']['malgraph_features_seconds'] = round(time.monotonic() - started, 3)
    with open(output_path, 'wb') as handle:
        pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)


if __name__ == '__main__':
    main()
