"""Run the production and development directory APIs against the same local PE subset.
Never execute samples, mutate source datasets, or touch existing services.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
from tools.verify_smda_http import stop_server_tree


def save_json(path, payload):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def available_port(preferred):
    sock = socket.socket()
    try:
        if os.name == 'nt':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            sock.bind(('127.0.0.1', preferred))
        except OSError:
            sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def select_samples(source, destination, count):
    import pefile
    selected, rejected = [], []
    for label in ['benign', 'malicious']:
        candidates = sorted((source / label).iterdir(), key=lambda p: p.name.casefold())
        found = 0
        for file in candidates:
            if not file.is_file() or file.is_symlink():
                continue
            try:
                pe = pefile.PE(str(file), fast_load=True)
                bitness = 64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32
                clr = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
                pe.close()
            except Exception as error:
                rejected.append({'source': str(file), 'reason': str(error)})
                continue
            target = destination / label / file.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as out, file.open('rb') as inp:
                shutil.copyfileobj(inp, out, length=1024 * 1024)
            digest = sha256(file)
            if sha256(target) != digest:
                raise RuntimeError('source/copy SHA256 mismatch: ' + str(file))
            selected.append({'label': label, 'source': str(file), 'scan_path': str(target),
                             'file_name': file.name, 'bytes': file.stat().st_size,
                             'sha256': digest, 'bitness': bitness, 'clr': clr})
            found += 1
            if found == count:
                break
        if found != count:
            raise RuntimeError(f'{label}: expected {count} valid PE files, found {found}')
    return {'policy': 'First valid PE files in case-insensitive filename order per class; no filtering by size, CLR, scan result or label correctness.',
            'source_root': str(source), 'scan_root': str(destination), 'per_class': count,
            'samples': selected, 'rejected_before_selection': rejected}


def summarize(payload, manifest):
    by_path = {os.path.normcase(row.get('FilePath', '')): row for row in payload.get('Results', [])}
    rows, counts = [], {}
    for label in ['benign', 'malicious']:
        counts[label] = {'selected': 0, 'scanned': 0, 'predicted_benign': 0, 'predicted_malicious': 0,
                         'errors': 0, 'matches_folder_label': 0, 'samples_with_model_details': 0, 'samples_with_model_diagnostics': 0, 'partial_model_samples': None}
    for sample in manifest['samples']:
        result = by_path.get(os.path.normcase(sample['scan_path']))
        label = sample['label']
        stats = counts[label]
        stats['selected'] += 1
        row = {'label': label, 'source': sample['source'], 'file_name': sample['file_name'], 'sha256': sample['sha256']}
        if result is None or result.get('Error') or result.get('Status') == -1:
            stats['errors'] += 1
            row['error'] = 'missing result' if result is None else result.get('Error', 'scan failed')
        else:
            if result.get('SHA256', '').lower() != sample['sha256']:
                raise AssertionError('response hash does not match selected sample')
            predicted = 'malicious' if result['IsMalicious'] else 'benign'
            stats['scanned'] += 1
            stats['predicted_' + predicted] += 1
            stats['matches_folder_label'] += int(predicted == label)
            row.update(predicted=predicted, matches_folder_label=predicted == label,
                       virus_name=result.get('ScanResult', {}).get('VirusName'), score=result.get('Score'))
            scan = result.get('ScanResult', {})
            details = scan.get('PerModelDetails')
            if details is not None:
                row['ok_models'] = sum(model.get('status') == 'ok' for model in details)
                row['total_models'] = len(details)
                row['non_ok_models'] = [{key: model[key] for key in ['model', 'status', 'reason'] if key in model}
                                        for model in details if model.get('status') != 'ok']
                mg = next((model for model in details if model['model'] == 'MalGraph'), {})
                row['malgraph'] = mg
                stats['samples_with_model_details'] += 1
            elif isinstance(scan.get('ModelStats'), dict):
                model_stats = scan['ModelStats']
                scores = scan.get('PerModelScores', {})
                excluded = model_stats.get('ExcludedModels', {})
                row['ok_models'] = model_stats['OkModels']
                row['total_models'] = model_stats['TotalModels']
                if len(scores) != row['ok_models']:
                    raise AssertionError('PerModelScores/OkModels disagree')
                # Specific per-model failure status is no longer public. Do not
                # invent error/timeout/skipped distinctions from free-text reasons.
                row['non_ok_models'] = [{'model': model, 'status': 'excluded', 'reason': reason}
                                        for model, reason in excluded.items()]
                if 'MalGraph' in scores:
                    row['malgraph'] = {'model': 'MalGraph', 'status': 'ok', 'score': scores['MalGraph']}
                elif 'MalGraph' in excluded:
                    row['malgraph'] = {'model': 'MalGraph', 'status': 'excluded', 'reason': excluded['MalGraph']}
                else:
                    row['malgraph'] = {'model': 'MalGraph', 'status': 'unknown'}
                row['model_diagnostics_source'] = 'PerModelScores+ModelStats'
            if 'ok_models' in row:
                stats['samples_with_model_diagnostics'] += 1
                stats['partial_model_samples'] = (stats['partial_model_samples'] or 0) + int(row['ok_models'] != row['total_models'])
        rows.append(row)
    return {'api_summary': payload.get('Summary'), 'counts_by_folder_label': counts, 'rows': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--per-class', type=int, default=10)
    parser.add_argument('--analysis-timeout', type=int, default=120)
    args = parser.parse_args()
    if args.per_class < 1 or args.analysis_timeout < 1:
        parser.error('counts/timeouts must be positive')
    import httpx
    import psutil  # Check the owned-process cleanup dependency before launching.
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    scan_root = ROOT / '.feature_cache' / output.name / 'inputs'
    scan_root.mkdir(parents=True, exist_ok=False)
    manifest = select_samples(args.source.resolve(), scan_root, args.per_class)
    manifest['timestamp'] = datetime.now().astimezone().isoformat()
    save_json(output / 'sample_manifest.json', manifest)
    print('OUTPUT', output, flush=True)
    print('SELECTED', len(manifest['samples']), 'samples; bytes=', sum(row['bytes'] for row in manifest['samples']), flush=True)
    request_timeout = max(3600, 2 * args.per_class * (args.analysis_timeout + 30))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8', PYTHONHASHSEED='0',
               CODEFENDER_ENV='dev', CODEFENDER_HASH_DB_ENABLED='0', CODEFENDER_FUZZY_DB_ENABLED='0',
               CODEFENDER_REQUIRE_HASH_DB='0', CODEFENDER_RUNTIME_CFG_DISABLE='1', CODEFENDER_NON_MALGRAPH_IR='0',
               CODEFENDER_MODEL_DEVICE='cpu', CODEFENDER_MALGRAPH_DEVICE='cpu', CODEFENDER_ENABLE_MALGRAPH='1',
               CODEFENDER_MODEL_PATH=str(ROOT / 'ensemble.pkl'),
               CODEFENDER_MALGRAPH_CKPT=str(ROOT / 'models/MalGraph_2022/best_model.pt'),
               CODEFENDER_MALGRAPH_VOCAB=str(ROOT / 'models/MalGraph_2022/saved/train_external_function_name_vocab.jsonl'),
               CODEFENDER_MASK_VIEWS='', CODEFENDER_ANALYSIS_TIMEOUT=str(args.analysis_timeout),
               CODEFENDER_ANALYSIS_TIMEOUT_MAX=str(args.analysis_timeout), CODEFENDER_REQUEST_TIMEOUT=str(request_timeout),
               CODEFENDER_HARD_TIMEOUT=str(request_timeout + 60), CODEFENDER_BATCH_SIZE='4',
               CODEFENDER_BATCH_EXTRACT_WORKERS='1', CODEFENDER_MAX_CONCURRENT='1',
               OMP_NUM_THREADS='2', MKL_NUM_THREADS='2', OPENBLAS_NUM_THREADS='1')
    env.pop('CODEFENDER_DISASM_BACKEND', None)
    runs = {'timestamp': datetime.now().astimezone().isoformat(), 'python': sys.executable,
            'mode': 'CPU/model-only/SMDA default; two separate uvicorn processes; sources read only; samples never executed',
            'settings': {key: value for key, value in env.items() if key.startswith('CODEFENDER_') and not any(word in key for word in ['KEY', 'TOKEN', 'SECRET', 'PASSWORD'])},
            'sample_count': len(manifest['samples']), 'runs': {}}
    for name, module, preferred in [('app', 'engine.app:app', 18001), ('dev_app', 'engine.dev.app:app', 18002)]:
        port = available_port(preferred)
        command = [sys.executable, '-B', '-X', 'utf8', '-m', 'uvicorn', module, '--host', '127.0.0.1', '--port', str(port), '--workers', '1']
        info = {'entrypoint': module, 'command': command, 'port': port, 'response_file': str(output / (name + '_predict_directory.json'))}
        runs['runs'][name] = info
        process = None
        with (output / (name + '_server.log')).open('wb') as log:
            try:
                process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                with httpx.Client(timeout=request_timeout + 120, trust_env=False) as client:
                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError('server exited during startup')
                        try:
                            response = client.get(f'http://127.0.0.1:{port}/readyz', timeout=2)
                            if response.status_code == 200:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(0.25)
                    else:
                        raise TimeoutError('engine did not become ready')
                    health = client.get(f'http://127.0.0.1:{port}/health', timeout=120)
                    health.raise_for_status()
                    info['health'] = health.json()
                    save_json(output / (name + '_health.json'), info['health'])
                    if info['health'].get('disasm_backend') != 'smda' or info['health'].get('model_count') != 33:
                        raise AssertionError('unexpected backend/model registry')
                    params = {'directory': str(scan_root), 'recursive': 'true', 'include_de': 'true'}
                    info['request'] = {'method': 'POST', 'url': f'http://127.0.0.1:{port}/predict-directory', 'params': params}
                    save_json(output / 'run_metadata.json', runs)
                    print('SCANNING', module, 'port=', port, 'samples=', len(manifest['samples']), flush=True)
                    start = time.monotonic()
                    response = client.post(info['request']['url'], params=params)
                    info['seconds'] = round(time.monotonic() - start, 3)
                    info['http_status'] = response.status_code
                    # Preserve exactly the received JSON body, without adding/changing API fields.
                    Path(info['response_file']).write_bytes(response.content)
                    response.raise_for_status()
                    payload = response.json()
                    info['result'] = summarize(payload, manifest)
                    info['request_completed'] = len(payload.get('Results', [])) == len(manifest['samples'])
                    print('FINISHED', module, 'HTTP', response.status_code, 'seconds=', info['seconds'],
                          'summary=', json.dumps(payload.get('Summary'), ensure_ascii=False), flush=True)
            except Exception as error:
                info['error'] = str(error)
                info['traceback'] = traceback.format_exc()
                print('FAILED', module, error, flush=True)
            finally:
                if process is not None:
                    stop_server_tree(process)
                save_json(output / 'run_metadata.json', runs)
    prod = runs['runs']['app']
    dev = runs['runs']['dev_app']
    if 'result' in prod and 'result' in dev:
        left = {row['sha256']: row for row in prod['result']['rows']}
        right = {row['sha256']: row for row in dev['result']['rows']}
        runs['comparison'] = {'same_predictions': all(left[key].get('predicted') == right[key].get('predicted') for key in left),
                              'disagreements': [key for key in left if left[key].get('predicted') != right[key].get('predicted')]}
        from engine.projection import project_directory
        prod_body = json.loads(Path(prod['response_file']).read_text(encoding='utf-8'))
        dev_body = json.loads(Path(dev['response_file']).read_text(encoding='utf-8'))
        runs['comparison']['production_equals_projected_development'] = prod_body == project_directory(dev_body)
    runs['all_requests_completed'] = all(info.get('request_completed', False) for info in runs['runs'].values())
    save_json(output / 'run_metadata.json', runs)
    lines = ['# DataSet_test 目录接口扫描结果', '',
             f'同一批 benign/malicious 各 {args.per_class} 个 PE，按文件名排序固定选样；源目录未修改，未执行样本。',
             '两个入口分别启动；CPU、SMDA、include_de=true、哈希预检关闭。标签仅来自文件夹，不代表经过独立核验的真值。', '',
             '| 入口 | 文件夹标签 | 扫描成功 | 判为恶意 | 判为良性 | 错误 | 与文件夹标签一致 |',
             '|---|---|---:|---:|---:|---:|---:|']
    for name, info in runs['runs'].items():
        for label, count in info.get('result', {}).get('counts_by_folder_label', {}).items():
            lines.append(f'| {name} | {label} | {count["scanned"]} | {count["predicted_malicious"]} | {count["predicted_benign"]} | {count["errors"]} | {count["matches_folder_label"]}/{count["selected"]} |')
    lines += ['', '## 每个样本（开发入口完整结果）', '',
              '| 标签 | 文件名 | 判定 | Score | 成功模型数 | MalGraph |', '|---|---|---|---:|---:|---|']
    for row in dev.get('result', {}).get('rows', []):
        score = f'{row["score"]:.6f}' if row.get('score') is not None else '—'
        lines.append(f'| {row["label"]} | {row["file_name"]} | {row.get("predicted", row.get("error"))} | {score} | {row.get("ok_models", "—")}/{row.get("total_models", "—")} | {row.get("malgraph", {}).get("status", "—")} |')
    lines += ['', '## 文件', '', '- app_predict_directory.json：生产接口原始响应。',
              '- dev_app_predict_directory.json：开发接口原始响应，保留各模型分数、模型计数和排除原因。',
              '- sample_manifest.json：源路径、扫描副本路径、SHA256、PE 位数与 CLR 信息。',
              '- run_metadata.json：启动命令、端口、参数、耗时、分组统计、每模型失败原因与双入口比较。',
              '- app_health.json / dev_app_health.json：实际启动后的后端与权重状态。', '',
              '接口扫描成功不等于所有模型全部成功；请查看成功模型数及 non_ok_models。开发裁剪后逐模型非成功状态统一记为 excluded，不推断 error/timeout/skipped 细分。生产接口按契约隐藏分数和模型明细，未对原始响应补写这些字段。',
              f'这是 {args.per_class * 2} 个固定选样的运行测试，不是完整数据集准确率验收。', '']
    (output / 'SUMMARY.md').write_text('\n'.join(lines), encoding='utf-8')
    print('RESULTS', output, flush=True)
    return 0 if runs['all_requests_completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
