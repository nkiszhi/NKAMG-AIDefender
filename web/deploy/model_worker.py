"""Preview/create a second model container, or enable its private Web config.

Default is read-only preview. Never prints environment values or deletes containers.
"""
import argparse
import configparser
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError('Docker command failed: ' + args[0] + '; inspect container locally')
    return result.stdout.strip()


def build_args(source, target):
    config, host = source['Config'], source['HostConfig']
    if host.get('NetworkMode', 'default') not in ('default', 'bridge'):
        raise ValueError('Custom network needs deployment-specific configuration')
    if host.get('Privileged') or host.get('Devices') or host.get('CapAdd'):
        raise ValueError('Custom device/privilege configuration requires review')
    if host.get('IpcMode') not in (None, '', 'private') or host.get('PidMode'):
        raise ValueError('Shared IPC/PID configuration requires review')
    if host.get('Ulimits') or host.get('SecurityOpt') or host.get('ReadonlyRootfs'):
        raise ValueError('Custom host restrictions require deployment-specific configuration')
    args = ['create', '--name', target, '--restart', 'unless-stopped',
            '-p', '127.0.0.1:8002:8000', '--cpus', '3', '--memory', '10g',
            '--memory-swap', '10g', '--log-driver', 'json-file',
            '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3']
    if host.get('ShmSize'):
        args += ['--shm-size', str(host['ShmSize'])]
    for mount in source.get('Mounts', []):
        destination = mount['Destination']
        if mount.get('RW', True) and destination != '/root/.cache/torch':
            raise ValueError('Review writable mount before cloning: ' + destination)
        if mount['Type'] not in ('bind', 'volume'):
            raise ValueError('Unsupported mount type: ' + mount['Type'])
        src = mount.get('Name') if mount['Type'] == 'volume' else mount['Source']
        if any(',' in value for value in (src, destination)):
            raise ValueError('Mount paths with commas need manual configuration')
        spec = f'type={mount["Type"]},source={src},target={destination}'
        if not mount.get('RW', True):
            spec += ',readonly'
        args += ['--mount', spec]
    if config.get('WorkingDir'):
        args += ['--workdir', config['WorkingDir']]
    if config.get('User'):
        args += ['--user', config['User']]
    entrypoint = config.get('Entrypoint') or []
    if isinstance(entrypoint, str):
        entrypoint = [entrypoint]
    if entrypoint:
        args += ['--entrypoint', entrypoint[0]]
    command = config.get('Cmd') or []
    if isinstance(command, str):
        raise ValueError('String command requires deployment-specific configuration')
    args += [source['Image']] + entrypoint[1:] + command
    return args


def enable_pool(config_path):
    for port in (8001, 8002):
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/readyz', timeout=5) as response:
            if json.load(response).get('ready') is not True:
                raise RuntimeError(f'Worker {port} is not ready; configuration unchanged')
    path = Path(config_path).resolve()
    if not path.is_file():
        raise ValueError('Private configuration must already exist')
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding='utf-8')
    for section in ('server', 'codefender'):
        if not parser.has_section(section):
            parser.add_section(section)
    parser.set('server', 'max_concurrent_scans', '2')
    parser.set('codefender', 'api_bases', 'http://127.0.0.1:8001,http://127.0.0.1:8002')
    parser.set('codefender', 'scan_endpoint', '')
    backup = path.with_name(path.name + f'.before-dual-{time.time_ns()}.bak')
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(path.read_bytes())
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as output:
            temp_name = output.name
            parser.write(output)
        shutil.copystat(path, temp_name)
        original = path.stat()
        if hasattr(os, 'chown'):
            os.chown(temp_name, original.st_uid, original.st_gid)
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    print('Enabled two workers; private config backup: ' + str(backup))
    print('Restart the existing Web backend after current tasks finish.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default='codefender-c3-v8')
    parser.add_argument('--target', default='codefender-c3-v8-worker2')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--enable-pool', action='store_true')
    parser.add_argument('--config', default='web/config.ini')
    args = parser.parse_args()
    if args.enable_pool:
        enable_pool(args.config)
        return
    source = json.loads(docker('inspect', '--type', 'container', args.source))[0]
    if not source['State']['Running']:
        raise ValueError('Source worker must be running')
    command = build_args(source, args.target)
    print('Source: ' + args.source + '; target: ' + args.target)
    print('Image ID: ' + source['Image'])
    print('Second worker: 127.0.0.1:8002, 3 CPU budget, 10 GiB cap, single scan.')
    print('Inherits environment and supported mounts; environment values are hidden.')
    print('Copies current engine app/runtime patches before start; other container-layer changes are NOT copied.')
    print('Validate model/license readiness before enabling the pool.')
    if not args.apply:
        print('Preview only. Use --apply to create and start. Existing objects are never removed.')
        return
    existing = docker('container', 'ls', '-a', '--format', '{{.Names}}').splitlines()
    if args.target in existing:
        raise ValueError('Target already exists; inspect instead of recreating')
    docker('exec', args.source, 'test', '-f', '/app/engine/scan_runtime.py')
    env = dict(item.split('=', 1) for item in source['Config'].get('Env') or [])
    env.update(CODEFENDER_MAX_CONCURRENT='1', OMP_NUM_THREADS='2',
               MKL_NUM_THREADS='2', OPENBLAS_NUM_THREADS='2')
    if any('\n' in value or '\r' in value for value in env.values()):
        raise ValueError('Multiline environment requires deployment-specific configuration')
    env_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as output:
            env_path = output.name
            for key, value in env.items():
                output.write(f'{key}={value}\n')
        command[1:1] = ['--env-file', env_path]
        docker(*command)
        with tempfile.TemporaryDirectory(prefix='aidefender-engine-') as directory:
            for filename in ('app.py', 'scan_runtime.py'):
                local = str(Path(directory) / filename)
                docker('cp', f'{args.source}:/app/engine/{filename}', local)
                docker('cp', local, f'{args.target}:/app/engine/{filename}')
        docker('start', args.target)
    finally:
        if env_path:
            os.unlink(env_path)
    print('Started. Check /readyz and a real PE before enabling the pool.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Stopped: ' + str(error))
        raise SystemExit(1)
