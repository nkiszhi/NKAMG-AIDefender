"""Disposable BinaryNinja feature process. No model service imports or license rewriting."""
import pickle
import sys
import os
import signal
import threading


def main():
    # A second watchdog prevents an orphaned native-analysis process if its parent exits.
    def hard_stop():
        if os.name == 'posix' and os.getpgrp() == os.getpid():
            os.killpg(os.getpgrp(), signal.SIGKILL)
        os._exit(124)
    timeout = max(1, min(120, int(os.environ.get('CODEFENDER_ANALYSIS_TIMEOUT', '90'))))
    watchdog = threading.Timer(timeout + 5, hard_stop)
    watchdog.daemon = True
    watchdog.start()
    import binaryninja as bn
    from feature_extraction.extract_feature import BinjaExtractor

    try:
        bn.disable_default_log()
        bn.log.log_to_stderr(bn.LogLevel.ErrorLog)
    except Exception:
        pass

    sample_path, output_path = sys.argv[1:3]
    result = {'features': {}, 'malgraph': None, 'errors': {}}
    bv = bn.load(sample_path, options={
        'analysis.mode': 'basic', 'analysis.linearSweep.autorun': True,
        'analysis.limits.maxFunctionSize': 262144,
    })
    if bv is None:
        raise RuntimeError('BinaryNinja could not open the PE')
    try:
        extractor = BinjaExtractor()
        extractor.bn = bn
        for name, operation in [('disassembly', extractor._extract_disassembly),
                                ('graphs', extractor._extract_graphs)]:
            try:
                result['features'].update(operation(bv))
            except Exception as error:
                result['errors'][name] = str(error)
        try:
            from models.MalGraph_2022.utils import extract_cfg_and_fcg
            result['malgraph'] = extract_cfg_and_fcg(sample_path, {}, binary_view=bv)
            if not result['malgraph']:
                result['errors']['malgraph'] = 'No valid MalGraph features'
        except Exception as error:
            result['errors']['malgraph'] = str(error)
    finally:
        bv.file.close()
    with open(output_path, 'wb') as handle:
        pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)


if __name__ == '__main__':
    main()
