"""Real local PE validation; never execute samples or download weights.

Run from the engine root with its configured Python. Every attempted sample is
reported, including unsupported/failed files. Existing main extractors and
MalGraph are deliberately not patched by this verifier.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
DE_SHAPES = {'D01': 4096, 'D02': 256, 'D03': 256, 'D04': 15, 'D05': 12,
             'D06': 10, 'D07': 6144, 'E03': 12, 'E04': 10}


def artifact(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def check_edges(edges, count, np):
    array = np.asarray(edges)
    if array.ndim != 2 or array.shape[0] != 2:
        raise ValueError('edge index must have shape [2, E]')
    if array.size and (not np.isfinite(array).all() or not np.equal(array, array.astype(int)).all()
                       or array.min() < 0 or array.max() >= count):
        raise ValueError('edge index out of range or not integral')
    return int(array.shape[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample-dir', required=True, type=Path)
    parser.add_argument('--pattern', default='*.bin')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--ensemble-source', type=Path)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--full-models', type=int, default=1,
                        help='Run every model on this many successfully analyzed PEs; remaining PEs run D/E models and MalGraph.')
    args = parser.parse_args()
    files = sorted(args.sample_dir.glob(args.pattern))
    if not files:
        parser.error('no PE inputs matched')
    if args.timeout <= 0 or args.full_models < 0:
        parser.error('timeout must be positive and full-models nonnegative')
    os.chdir(ROOT)
    # Intentionally exercise the engine's DEFAULT, not a test-forced smda value.
    previous_backend = os.environ.pop('CODEFENDER_DISASM_BACKEND', None)
    os.environ.update(PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8',
                      CODEFENDER_NON_MALGRAPH_IR='0', CODEFENDER_HASH_DB_ENABLED='0',
                      CODEFENDER_FUZZY_DB_ENABLED='0', CODEFENDER_REQUIRE_HASH_DB='0',
                      CODEFENDER_RUNTIME_CFG_DISABLE='1', CODEFENDER_MODEL_DEVICE='cpu',
                      CODEFENDER_MALGRAPH_DEVICE='cpu', CODEFENDER_ENABLE_MALGRAPH='1',
                      CODEFENDER_MASK_VIEWS='', CODEFENDER_ANALYSIS_TIMEOUT=str(args.timeout), CODEFENDER_ANALYSIS_TIMEOUT_MAX=str(args.timeout))
    report = {'timestamp': datetime.now(timezone.utc).isoformat(),
              'scope': 'Real local PE static analysis + main weights CPU forward; not accuracy, BN parity, GPU, hash DB or Docker certification.',
              'python': sys.version, 'executable': sys.executable, 'base_prefix': sys.base_prefix,
              'previous_backend_removed_for_default_test': previous_backend,
              'versions': {}, 'artifacts': {}, 'samples': [], 'passed': False}
    for name in ['smda', 'dnfile', 'dncil', 'capstone', 'lief', 'pefile', 'numpy',
                 'scipy', 'scikit-learn', 'torch', 'torchvision', 'torch-geometric',
                 'fastapi', 'starlette', 'httpx', 'uvicorn', 'python-multipart', 'safetensors', 'ppdeep', 'yara-python']:
        try:
            report['versions'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            report['versions'][name] = None
    output = args.report.resolve()

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')

    try:
        import numpy as np
        import pefile
        import torch
        torch.set_num_threads(2)
        import engine.app as app
        from engine.staged_scan import isolated_analysis
        report['backend'] = app.DISASM_BACKEND
        report['non_malgraph_ir'] = os.environ['CODEFENDER_NON_MALGRAPH_IR']
        if app.DISASM_BACKEND != 'smda':
            raise RuntimeError('engine default did not select smda')
        report['artifacts']['ensemble'] = artifact(app.MODEL_PATH)
        if args.ensemble_source:
            source = artifact(args.ensemble_source)
            report['artifacts']['ensemble_source'] = source
            if source['sha256'] != report['artifacts']['ensemble']['sha256']:
                raise RuntimeError('ensemble copy does not match source')
        ens = app._load_ensemble()
        runtime = app._load_malgraph_runtime()
        report['artifacts']['malgraph'] = artifact(runtime['checkpoint_path'])
        report['artifacts']['malgraph_vocab'] = artifact(runtime['vocab_path'])
        missing = [name for name in ens._model_names if ens._model_types.get(name) != 'special'
                   and ens._models.get(name) is None]
        report['model_load'] = {'registered': ens._model_names, 'registered_count': len(ens._model_names),
                                'ordinary_loaded_count': sum(value is not None for value in ens._models.values()),
                                'missing_ordinary_models': missing, 'malgraph_missing_keys': runtime['missing_keys'],
                                'malgraph_unexpected_keys': runtime['unexpected_keys'], 'device': str(runtime['device'])}
        if missing or runtime['missing_keys'] or runtime['unexpected_keys']:
            raise RuntimeError('weights incomplete or incompatible')
        expected = app._infer_expected_view_dims(ens)
        report['expected_view_dims'] = expected
        if expected.get('V1_byte') != 32768 or expected.get('V8_color') != 196608:
            raise RuntimeError('protected main byte/color dimensions changed')
        slow_views = [view for view in ens.view_groups
                      if any(fid.startswith(('D', 'E')) for fid in app.config.VIEW_GROUPS.get(view, {}).get('binja_features', []))]
        slow_names = {name for view in slow_views for name in ens.view_groups[view]} | {'MalGraph'}
        full_remaining = args.full_models
        for file in files:
            start = time.monotonic()
            item = {'input': artifact(file), 'passed': False}
            try:
                pe = pefile.PE(str(file), fast_load=True)
                item['pe'] = {'machine': hex(pe.FILE_HEADER.Machine),
                              'bitness': 64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32,
                              'entrypoint_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                              'clr_header': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)}
                pe.close()
                analysis = isolated_analysis(str(file), timeout=args.timeout)
                item['analysis_errors'] = analysis.get('errors', {})
                item['timing'] = analysis.get('timing', {})
                item['analysis_seconds'] = analysis['seconds']
                features = analysis['features']
                item['de'] = {}
                for key, length in DE_SHAPES.items():
                    array = np.asarray(features.get(key, []))
                    item['de'][key] = {'shape': list(array.shape), 'finite': bool(np.isfinite(array).all()),
                                       'nonzero': int(np.count_nonzero(array)),
                                       'sha256': hashlib.sha256(array.tobytes()).hexdigest()}
                    if array.shape != (length,) or not np.isfinite(array).all():
                        raise ValueError('missing/invalid D/E feature: ' + key)
                if item['analysis_errors'] or not np.any(features['D01']) or features['D05'][0] <= 0:
                    raise ValueError('analysis error or empty disassembly')
                sample = analysis.get('malgraph') or {}
                graphs = sample.get('acfg_list', [])
                if not graphs:
                    raise ValueError('empty MalGraph ACFGs')
                blocks, edges = 0, 0
                for graph in graphs:
                    matrix = np.asarray(graph['block_features'])
                    if matrix.ndim != 2 or matrix.shape[1] != 11 or not len(matrix) or not np.isfinite(matrix).all():
                        raise ValueError('invalid MalGraph block features')
                    blocks += len(matrix)
                    edges += check_edges(graph['block_edges'], len(matrix), np)
                names = sample.get('function_names', [])
                if len(names) < len(graphs):
                    raise ValueError('MalGraph function names missing')
                fcg_edges = check_edges(sample['function_edges'], len(names), np)
                item['graph'] = {'local_functions': len(graphs), 'external_functions': len(names)-len(graphs),
                                 'blocks': blocks, 'cfg_edges': edges, 'fcg_edges': fcg_edges}
                full = full_remaining > 0
                selected = set(ens._model_names) if full else slow_names
                required = list(ens.view_groups) if full else slow_views
                combined = dict(app._get_extractor().extract_fast(str(file)), **features) if full else features
                views, meta = app._extract_views_for_single_sample(str(file), required, True, expected, extracted_features=combined)
                item['view_shapes'] = {key: list(value.shape) for key,value in views.items()}
                item['view_meta'] = meta
                item['model_scope'] = 'all_models' if full else 'D/E_models_and_MalGraph'
                item['model_results'] = app._predict_per_model(ens, views, view_meta=meta, pe_path=str(file),
                                                              include_de=True, selected_models=selected, malgraph_sample=sample)
                actual = {result['model'] for result in item['model_results']}
                bad = [result for result in item['model_results'] if result.get('status') != 'ok'
                       or not math.isfinite(result.get('score', float('nan')))]
                # JSON evidence remains writable even if a model emits NaN/Inf.
                for result in item['model_results']:
                    if 'score' in result and not math.isfinite(result['score']):
                        result['score'] = None
                if bad or actual != selected:
                    raise ValueError('model forward incomplete/failed: ' + ','.join(result['model'] for result in bad))
                if full:
                    if views['V1_byte'].shape != (1, 32768) or views['V8_color'].shape != (1, 196608):
                        raise ValueError('protected input dimensions changed')
                    full_remaining -= 1
                item['passed'] = True
            except Exception as error:
                item['error'] = str(error)
                item['traceback'] = traceback.format_exc()
            item['seconds'] = round(time.monotonic() - start, 3)
            report['samples'].append(item)
            print(('PASS' if item['passed'] else 'FAIL'), file.name, item.get('error', ''), flush=True)
            save()
        report['summary'] = {'attempted': len(files), 'passed': sum(item['passed'] for item in report['samples']),
                             'failed': sum(not item['passed'] for item in report['samples']),
                             'full_model_samples': sum(item['passed'] and item.get('model_scope') == 'all_models' for item in report['samples'])}
        report['passed'] = report['summary']['failed'] == 0 and full_remaining == 0
    except Exception as error:
        report['fatal_error'] = str(error)
        report['traceback'] = traceback.format_exc()
        print('FATAL', str(error), flush=True)
    finally:
        save()
        print('Evidence:', output, flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
