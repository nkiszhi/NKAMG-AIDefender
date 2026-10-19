"""Fast models first, then one bounded, disposable BinaryNinja extraction."""
import logging
import os
from pathlib import Path
import pickle
import signal
import subprocess
import sys
import tempfile
import time

log = logging.getLogger('codefender.stages')


def analysis_timeout():
    return max(1, min(600, int(os.environ.get('CODEFENDER_ANALYSIS_TIMEOUT', '180'))))


def runtime_limits():
    # Leave room for fast/slow models and report formatting around analysis.
    request = max(analysis_timeout() + 180, int(os.environ.get('CODEFENDER_REQUEST_TIMEOUT', '360')))
    hard = max(request + 60, int(os.environ.get('CODEFENDER_HARD_TIMEOUT', '420')))
    return request, hard


def isolated_analysis(path, timeout=180, on_slow=None):
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='aidefender-analysis-') as directory:
        output = str(Path(directory) / 'features.pkl')
        command = [sys.executable, '-m', 'engine.analysis_worker', str(Path(path).resolve()), output]
        started = time.monotonic()
        with open(Path(directory) / 'stderr.log', 'wb') as errors:
            process = subprocess.Popen(command, cwd=root, stdout=subprocess.DEVNULL, stderr=errors,
                                       start_new_session=os.name == 'posix')
            try:
                notice_after = min(90, timeout)
                try:
                    process.wait(timeout=notice_after)
                except subprocess.TimeoutExpired:
                    if timeout <= notice_after:
                        raise
                    if on_slow:
                        on_slow()
                    # Notice is informational: continue the SAME process.
                    process.wait(timeout=timeout - notice_after)
            except BaseException:
                if os.name == 'posix':
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                raise
        elapsed = round(time.monotonic() - started, 3)
        log.info('BinaryNinja process finished seconds=%.3f returncode=%s', elapsed, process.returncode)
        if process.returncode:
            # Do not return raw stderr, which can contain private runtime paths/license data.
            raise RuntimeError('BinaryNinja extraction process failed; inspect model runtime configuration')
        # The pickle is generated only by our own local child in a private temporary directory.
        with open(output, 'rb') as handle:
            result = pickle.load(handle)
        result['seconds'] = elapsed
        return result


def run_staged(ns, path, filename, size, ens, expected, include_de, on_progress=None):
    groups = ens.view_groups
    all_names = [name for names in groups.values() for name in names]
    slow_names = set()
    for view, names in groups.items():
        ids = ns['config'].VIEW_GROUPS.get(view, {}).get('binja_features', [])
        if any(feature.startswith(('D', 'E')) for feature in ids):
            slow_names.update(names)
    slow_names.add('MalGraph')
    fast_names = set(all_names) - slow_names
    states = {name: {'model': name, 'status': 'waiting'} for name in all_names}
    timings = {}
    started = time.monotonic()

    def publish(stage):
        if on_progress:
            on_progress({'stage': stage, 'models': list(states.values()),
                         'elapsed_seconds': round(time.monotonic() - started, 3),
                         'timing': dict(timings)})

    def completed(item):
        states[item['model']] = dict(item)
        publish('models')

    def predict(names, features, de, sample=None):
        selected_views = [view for view, models in groups.items() if set(models) & names]
        views, meta = ns['_extract_views_for_single_sample'](
            path, selected_views, de, expected, extracted_features=features)
        for name in names & states.keys():
            states[name] = {'model': name, 'status': 'running'}
        publish('fast_models' if names == fast_names else 'slow_models')
        return ns['_predict_per_model'](ens, views, view_meta=meta, pe_path=path,
                                       include_de=de, selected_models=names,
                                       malgraph_sample=sample, on_result=completed)

    publish('fast_features')
    stage_start = time.monotonic()
    features = ns['_get_extractor']().extract_fast(path)
    timings['fast_features_seconds'] = round(time.monotonic() - stage_start, 3)
    stage_start = time.monotonic()
    results = predict(fast_names, features, False)
    timings['fast_models_seconds'] = round(time.monotonic() - stage_start, 3)
    if include_de and (set(all_names) & slow_names):
        for name in set(all_names) & slow_names:
            states[name] = {'model': name, 'status': 'running'}
        publish('binaryninja')
        analysis_start = time.monotonic()
        try:
            timeout = analysis_timeout()
            analysis = isolated_analysis(path, timeout, on_slow=lambda: publish('binaryninja_slow'))
            timings['binaryninja_seconds'] = analysis['seconds']
            timings.update(analysis.get('timing', {}))
            combined = dict(features, **analysis['features'])
            # An empty dict prevents MalGraph from opening BinaryNinja again on failure.
            stage_start = time.monotonic()
            results += predict(slow_names, combined, True, analysis.get('malgraph') or {})
            timings['slow_models_seconds'] = round(time.monotonic() - stage_start, 3)
        except Exception as error:
            timings['binaryninja_seconds'] = round(time.monotonic() - analysis_start, 3)
            status = 'timeout' if isinstance(error, subprocess.TimeoutExpired) else 'error'
            for name in all_names:
                if name in slow_names:
                    item = {'model': name, 'status': status,
                            'reason': 'BinaryNinja analysis timed out' if status == 'timeout' else str(error)}
                    results.append(item)
                    completed(item)
    else:
        for name in all_names:
            if name in slow_names:
                item = {'model': name, 'status': 'skipped', 'reason': 'D/E analysis disabled'}
                results.append(item)
                completed(item)
    timings['total_model_seconds'] = round(time.monotonic() - started, 3)
    log.info('Scan stage timing seconds=%s', timings)
    publish('finalizing')
    report = ns['_scan_single_pe'](path, filename, size, ens, expected, include_de,
                                   per_model_override=results)
    report.setdefault('ScanResult', {})['PerModelDetails'] = results
    report['ScanResult']['StageTiming'] = timings
    return report
