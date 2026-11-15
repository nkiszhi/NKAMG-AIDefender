#!/usr/bin/env python3
"""Read Docker lifecycle evidence; never start/stop/update a container.

Run separately from Web. Only the JSON snapshot needs to be readable by Web.
The container identity and precise OOM timestamp are retained across restarts.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.request import urlopen


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:200] or 'Docker read failed')
    return result.stdout


def memory_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('MemAvailable is unavailable')


def merge_events(previous, lines, now):
    events = {(e['container_id'], e['kind'], e['time']): e for e in previous
              if e.get('time', 0) >= now - 86400}
    for line in lines.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        kind = item.get('Action', item.get('status'))
        identity = item.get('id') or item.get('Actor', {}).get('ID')
        stamp = item.get('timeNano', 0) / 1e9 or item.get('time', 0)
        if kind in ('oom', 'start', 'die') and identity and stamp:
            events[(identity, kind, stamp)] = {'kind': kind, 'time': stamp, 'container_id': identity}
    return sorted(events.values(), key=lambda e: e['time'])[-200:]


def inspect_node(endpoint, name, previous, since, until):
    # Filter by name as well as ID, retaining history across container replacement.
    lines = docker('events', '--since', str(int(since)), '--until', str(int(until)),
                   '--filter', 'type=container', '--filter', 'container=' + name,
                   '--filter', 'event=oom', '--filter', 'event=start', '--filter', 'event=die',
                   '--format', '{{json .}}')
    history = merge_events(previous.get('events', []), lines, until)
    # Only inspect the whitelisted fields; never return container environment/secrets.
    result = subprocess.run(['docker', 'inspect', '--format',
                             '{{json .Id}}\t{{json .State}}\t{{json .RestartCount}}', name],
                            capture_output=True, text=True, timeout=8)
    if result.returncode:
        if 'No such' in result.stderr:
            return {'name': name, 'running': False, 'ready': False, 'events': history}
        raise RuntimeError('Docker inspect unavailable')
    identity, state, restarts = [json.loads(v) for v in result.stdout.strip().split('\t')]
    ready = False
    if state.get('Running'):
        try:
            with urlopen(endpoint + '/readyz', timeout=1) as response:
                ready = json.load(response).get('ready') is True
        except Exception:
            pass
    return {'name': name, 'id': identity, 'started_at': state.get('StartedAt'),
            'running': bool(state.get('Running')), 'ready': ready,
            'restarts': restarts, 'events': history}


def atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    with temp.open('w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp, 0o644)
    temp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', action='append', required=True, metavar='URL=CONTAINER')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interval', type=float, default=2)
    args = parser.parse_args()
    nodes = dict(item.rsplit('=', 1) for item in args.node)
    for endpoint, name in nodes.items():
        if not endpoint.startswith(('http://127.0.0.1:', 'http://localhost:')) or not name:
            parser.error('Only explicit localhost model endpoints are accepted')
    previous = {}
    try:
        previous = json.loads(args.output.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        pass
    since = max(time.time() - 86400, float(previous.get('updated_at', time.time() - 60)) - 3)
    with ThreadPoolExecutor(max_workers=len(nodes)) as executor:
        while True:
            now = time.time()
            try:
                futures = {url: executor.submit(inspect_node, url, name,
                           previous.get('nodes', {}).get(url, {}), since, now)
                           for url, name in nodes.items()}
                snapshot = {'updated_at': now, 'memory_available_bytes': memory_available(),
                            'nodes': {url: future.result() for url, future in futures.items()}}
                atomic_write(args.output, snapshot)
                previous, since = snapshot, now - 3  # overlap avoids fractional-boundary gaps
            except Exception as error:
                # Never freshen stale evidence when Docker cannot be observed.
                print('Monitor read failed; dispatch will pause:', error, flush=True)
            time.sleep(max(1, args.interval))


if __name__ == '__main__':
    main()
