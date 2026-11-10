"""Real loopback listeners, real weights and a local PE; no mocks or sample execution."""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
from tools.verify_smda_runtime import artifact


def free_ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def stop_server_tree(process):
    # Windows venv python.exe redirects to a child interpreter. Terminating only
    # the redirector leaves the real service/log handle alive. Touch only this
    # verifier's owned descendants, never unrelated Python services.
    import psutil
    try:
        parent = psutil.Process(process.pid)
        owned = parent.children(recursive=True) + [parent]
    except psutil.NoSuchProcess:
        process.wait()
        return
    for child in reversed(owned[:-1]):
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(owned[:-1], timeout=30)
    for child in alive:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(alive, timeout=10)
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=10)


def verify_development_diagnostics(result, expected_models=33):
    """Validate successful forwards without relying on hidden detail records."""
    scan = result.get('ScanResult', {})
    stats = scan.get('ModelStats', {})
    if 'PerModelPreds' in scan or 'PerModelDetails' in scan or 'AggregatedModels' in stats:
        raise AssertionError('redundant development diagnostics leaked')
    scores = scan.get('PerModelScores', {})
    if (len(scores) != expected_models or stats.get('TotalModels') != expected_models
            or stats.get('OkModels') != expected_models or stats.get('SkippedModels') != 0
            or stats.get('ErrorModels') != 0 or stats.get('ExcludedModels') != {}
            or any(not math.isfinite(score) for score in scores.values())):
        raise AssertionError('not all expected development model forwards succeeded')
    if 'MalGraph' not in scores:
        raise AssertionError('successful MalGraph score missing')
    return len(scores)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    import httpx
    import psutil  # Validate cleanup dependency before starting a service.
    web, production, development = free_ports()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8',
               CODEFENDER_WEB_COMPAT_HOST='127.0.0.1', CODEFENDER_WEB_COMPAT_PORT=str(web),
               CODEFENDER_PRODUCTION_HOST='127.0.0.1', CODEFENDER_PRODUCTION_PORT=str(production),
               CODEFENDER_ENABLE_DEV_API='1', CODEFENDER_DEV_PORT=str(development),
               CODEFENDER_HASH_DB_ENABLED='0', CODEFENDER_FUZZY_DB_ENABLED='0',
               CODEFENDER_REQUIRE_HASH_DB='0', CODEFENDER_RUNTIME_CFG_DISABLE='1',
               CODEFENDER_MODEL_DEVICE='cpu', CODEFENDER_MALGRAPH_DEVICE='cpu',
               CODEFENDER_NON_MALGRAPH_IR='0', CODEFENDER_ENABLE_MALGRAPH='1', CODEFENDER_MASK_VIEWS='',
               OMP_NUM_THREADS='2', MKL_NUM_THREADS='2', CODEFENDER_ANALYSIS_TIMEOUT='120')
    env.pop('CODEFENDER_DISASM_BACKEND', None)
    record = {'timestamp': datetime.now(timezone.utc).isoformat(), 'python': sys.executable,
              'psutil_version': psutil.__version__,
              'scope': 'Local Windows model-only shared engine HTTP; not production signature DB or Docker deployment.',
              'sample': artifact(args.sample), 'ports': {'web': web, 'production': production, 'development': development},
              'health': {}, 'requests': [], 'passed': False}
    process = None
    with tempfile.TemporaryDirectory(prefix='codefender-smda-http-') as tmp:
        root = Path(tmp)
        sampledir = root / 'samples'
        sampledir.mkdir()
        content = args.sample.read_bytes()
        (sampledir / 'sample.bin').write_bytes(content)
        with (root / 'server.log').open('wb') as logs:
            try:
                process = subprocess.Popen([sys.executable, '-B', '-X', 'utf8', '-m', 'engine.serve'],
                                           cwd=ROOT, env=env, stdout=logs, stderr=subprocess.STDOUT)
                with httpx.Client(timeout=180, trust_env=False) as client:
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            raise RuntimeError('server exited during startup')
                        try:
                            ready = [client.get(f'http://127.0.0.1:{port}/readyz', timeout=2) for port in [web, production, development]]
                            if all(response.status_code == 200 for response in ready):
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(0.2)
                    else:
                        raise TimeoutError('shared listeners not ready')
                    for name, port in record['ports'].items():
                        response = client.get(f'http://127.0.0.1:{port}/health')
                        response.raise_for_status()
                        health = response.json()
                        record['health'][name] = health
                        if health.get('disasm_backend') != 'smda':
                            raise AssertionError('default backend not exposed as smda')
                        for endpoint in ['predict-single', 'predict-directory']:
                            start = time.monotonic()
                            if endpoint == 'predict-single':
                                response = client.post(f'http://127.0.0.1:{port}/{endpoint}', params={'include_de': 'true'},
                                                       files={'file': ('sample.bin', content, 'application/octet-stream')})
                            else:
                                response = client.post(f'http://127.0.0.1:{port}/{endpoint}',
                                                       params={'directory': str(sampledir), 'include_de': 'true'})
                            response.raise_for_status()
                            body = response.json()
                            item = {'listener': name, 'endpoint': endpoint, 'http_status': response.status_code,
                                    'seconds': round(time.monotonic()-start, 3), 'response': body}
                            record['requests'].append(item)
                            result = body['Results'][0] if endpoint == 'predict-directory' else body
                            if endpoint == 'predict-directory' and len(body['Results']) != 1:
                                raise AssertionError('directory must contain exactly one result')
                            if ('Score' in result) != (name != 'production'):
                                raise AssertionError('production/development/Web projection changed')
                            # Production omits model diagnostics by contract; compare its
                            # projection to the full development response after all requests.
                            if result.get('SHA256') != record['sample']['sha256'] or result.get('Error'):
                                raise AssertionError('incorrect sample or failed prediction')
                            if endpoint == 'predict-directory' and body['Summary'].get('ErrorCount') != 0:
                                raise AssertionError('directory returned scan errors')
                            details = result.get('ScanResult', {}).get('PerModelDetails')
                            if name == 'development':
                                item['verified_model_count'] = verify_development_diagnostics(result)
                                item['model_evidence'] = 'PerModelScores+ModelStats; graph internals verified on Web only'
                            elif details is not None:
                                if len(details) != 33 or any(x.get('status') != 'ok' or not math.isfinite(x.get('score', float('nan'))) for x in details):
                                    raise AssertionError('not all 33 model forwards succeeded')
                                mg = next(x for x in details if x['model'] == 'MalGraph')
                                if mg['malgraph_meta']['local_functions'] <= 0:
                                    raise AssertionError('empty MalGraph analysis')
                                item['verified_model_count'] = len(details)
                            elif name != 'production':
                                raise AssertionError('diagnostic models missing')
                            print('PASS', name, endpoint, flush=True)
                    from engine.projection import project_single, project_directory
                    for endpoint, project in [('predict-single', project_single), ('predict-directory', project_directory)]:
                        prod = next(x['response'] for x in record['requests'] if x['listener'] == 'production' and x['endpoint'] == endpoint)
                        dev = next(x['response'] for x in record['requests'] if x['listener'] == 'development' and x['endpoint'] == endpoint)
                        if prod != project(dev):
                            raise AssertionError('production projection disagrees with actual development result')
                    record['passed'] = True
            except Exception as error:
                record['error'] = str(error)
                record['traceback'] = traceback.format_exc()
                print('FAIL', error, flush=True)
            finally:
                if process is not None:
                    stop_server_tree(process)
        record['server_log'] = (root / 'server.log').read_text(encoding='utf-8', errors='replace')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Evidence:', args.report.resolve(), flush=True)
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
