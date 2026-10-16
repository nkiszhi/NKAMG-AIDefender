import configparser
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'model_worker', Path(__file__).resolve().parents[2] / 'deploy' / 'model_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class ModelWorkerTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            'Image': 'sha256:actual-image',
            'Config': {'WorkingDir': '/app', 'User': '1000',
                       'Entrypoint': ['/usr/bin/tini', '--'], 'Cmd': ['supervisord']},
            'HostConfig': {'NetworkMode': 'bridge', 'ShmSize': 67108864},
            'Mounts': [
                {'Type': 'bind', 'Source': '/srv/license', 'Destination': '/license', 'RW': False},
                {'Type': 'volume', 'Name': 'torch', 'Destination': '/root/.cache/torch', 'RW': True},
            ],
        }

    def test_clone_uses_image_identity_and_local_bounded_worker(self):
        args = worker.build_args(self.source, 'worker2')
        self.assertIn('127.0.0.1:8002:8000', args)
        self.assertEqual(args[args.index('--cpus') + 1], '3')
        self.assertEqual(args[args.index('--memory') + 1], '10g')
        self.assertIn('type=bind,source=/srv/license,target=/license,readonly', args)
        self.assertIn('type=volume,source=torch,target=/root/.cache/torch', args)
        self.assertEqual(args[-3:], ['sha256:actual-image', '--', 'supervisord'])

    def test_unknown_shared_writable_data_is_rejected(self):
        self.source['Mounts'][0]['RW'] = True
        with self.assertRaisesRegex(ValueError, 'writable mount'):
            worker.build_args(self.source, 'worker2')

    def test_custom_host_settings_are_not_silently_dropped(self):
        for key, value in [('NetworkMode', 'host'), ('Devices', ['/dev/gpu']),
                           ('IpcMode', 'host'), ('Ulimits', [{'Name': 'nofile'}])]:
            source = copy.deepcopy(self.source)
            source['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.build_args(source, 'worker2')

    def test_enable_pool_preserves_private_values_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            original = '[mysql]\npasswd = secret%value\n[server]\nmax_queued_scans = 5\n'
            path.write_text(original, encoding='utf-8')
            with patch.object(worker.urllib.request, 'urlopen',
                              side_effect=lambda *a, **k: io.BytesIO(json.dumps({'ready': True}).encode())), patch('builtins.print'):
                worker.enable_pool(path)
            config = configparser.ConfigParser(interpolation=None)
            config.read(path, encoding='utf-8')
            self.assertEqual(config['mysql']['passwd'], 'secret%value')
            self.assertEqual(config['server']['max_queued_scans'], '5')
            self.assertEqual(config['server']['max_concurrent_scans'], '2')
            self.assertEqual(config['codefender']['scan_endpoint'], '')
            backups = list(Path(directory).glob('config.ini.before-dual-*.bak'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding='utf-8'), original)
            if os.name != 'nt':
                self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_unready_worker_leaves_config_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_text('[server]\nmax_concurrent_scans = 1\n', encoding='utf-8')
            original = path.read_bytes()
            with patch.object(worker.urllib.request, 'urlopen',
                              side_effect=lambda *a, **k: io.BytesIO(b'{"ready":false}')):
                with self.assertRaises(RuntimeError):
                    worker.enable_pool(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(list(Path(directory).glob('*.bak'))), 0)

    def test_engine_patches_are_copied_before_start(self):
        self.source['State'] = {'Running': True}
        self.source['Config']['Env'] = ['PRIVATE_VALUE=secret']
        calls = []

        def docker(*args):
            calls.append(args)
            return json.dumps([self.source]) if args[0] == 'inspect' else ''

        with patch.object(worker, 'docker', side_effect=docker), patch('builtins.print'), patch('sys.argv', ['model_worker.py', '--apply']):
            worker.main()
        self.assertEqual(calls[-1], ('start', 'codefender-c3-v8-worker2'))
        copies = [call for call in calls if call[0] == 'cp']
        self.assertEqual(len(copies), 4)
        self.assertEqual(copies[0][1], 'codefender-c3-v8:/app/engine/app.py')
        self.assertEqual(copies[-1][-1], 'codefender-c3-v8-worker2:/app/engine/scan_runtime.py')
        creation = next(call for call in calls if call[0] == 'create')
        self.assertNotIn('PRIVATE_VALUE=secret', creation)
        self.assertFalse(Path(creation[creation.index('--env-file') + 1]).exists())
