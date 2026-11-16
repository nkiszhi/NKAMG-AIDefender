"""Check the two txy Web listeners; --apply stops only verified Web processes."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import urllib.request


def model_health():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:5006/model-health', timeout=15) as response:
        return json.load(response)


def listener_pids(port):
    result = subprocess.check_output(['ss', '-ltnp', 'sport = :'+str(port)], text=True)
    return set(map(int, re.findall(r'pid=(\d+)', result)))


def process_info(pid):
    proc = Path('/proc')/str(pid)
    try:
        stat = (proc/'stat').read_text()
        fields = stat[stat.rfind(')')+2:].split()
        if fields[0] == 'Z':
            return None
        return {'cwd':(proc/'cwd').resolve(),
                'args':(proc/'cmdline').read_bytes().decode(errors='replace').split('\0'),
                'start':fields[19]}
    except FileNotFoundError:
        return None


def inspect(repo):
    health = model_health()
    if health.get('active_tasks') != 0:
        raise RuntimeError('Cannot confirm zero active model tasks. Web was not stopped.')
    targets = []
    for port, relative, kind in [(9528, 'web/Vue', 'preview'), (5006, 'web/FastAPI', 'backend')]:
        pids = listener_pids(port)
        if len(pids) != 1:
            raise RuntimeError('Cannot uniquely identify Web listener on port %s. No processes stopped.' % port)
        pid = pids.pop()
        info = process_info(pid)
        args = info['args'] if info else []
        correct_command = (any(Path(arg).name == 'main.py' for arg in args)
                           if kind == 'backend' else
                           'preview' in args and any(Path(arg).name in ('vite', 'vite.js') for arg in args))
        if not info or info['cwd'] != (repo/relative).resolve() or not correct_command:
            raise RuntimeError('Listener on port %s is not the expected Web process. No processes stopped.' % port)
        targets.append({'port':port, 'pid':pid, 'start':info['start']})
    return targets


def stop(repo, apply=False):
    targets = inspect(repo)
    for target in targets:
        print('Verified Web listener:', target['port'], 'PID', target['pid'])
    if not apply:
        print('Check only. Add --apply to stop verified Web processes. Docker is untouched.')
        return
    # Validate every target again before sending any signals.
    for target in targets:
        info = process_info(target['pid'])
        if not info or info['start'] != target['start']:
            raise RuntimeError('Process changed during check. No processes stopped.')
    for target in targets:
        os.kill(target['pid'], signal.SIGTERM)
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        alive = [target for target in targets
                 if (info := process_info(target['pid'])) and info['start'] == target['start']]
        if not alive:
            if any(listener_pids(target['port']) for target in targets):
                raise RuntimeError('A service manager restarted a Web listener. Use that manager; do not start a second copy.')
            print('Web processes exited and ports released. Ready to start Web. Docker is untouched.')
            return
        time.sleep(0.2)
    raise RuntimeError('Web is still shutting down; no force kill was used. Wait/check processes before starting another copy.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if os.name != 'posix' or not Path('/proc').is_dir():
        parser.error('This helper is for the txy Linux server only')
    stop(args.repo.resolve(), args.apply)


if __name__ == '__main__':
    main()
