"""Startup defaults without changing the frozen main worker fallback or models."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
from engine.startup import configure_disassembly_backend


class StartupTests(unittest.TestCase):
    def test_missing_defaults_to_smda(self):
        env = {}
        self.assertEqual(configure_disassembly_backend(env), 'smda')
        self.assertEqual(env, {'CODEFENDER_DISASM_BACKEND': 'smda'})

    def test_empty_or_whitespace_defaults_to_smda(self):
        for value in ['', ' ', '\t']:
            with self.subTest(value=value):
                env = {'CODEFENDER_DISASM_BACKEND': value}
                self.assertEqual(configure_disassembly_backend(env), 'smda')

    def test_explicit_bn_preserved_and_normalized(self):
        for value in ['bn', 'BN', ' Bn ']:
            with self.subTest(value=value):
                env = {'CODEFENDER_DISASM_BACKEND': value}
                self.assertEqual(configure_disassembly_backend(env), 'bn')
                self.assertEqual(env['CODEFENDER_DISASM_BACKEND'], 'bn')

    def test_smda_normalized_and_idempotent(self):
        env = {'CODEFENDER_DISASM_BACKEND': ' SMDA '}
        self.assertEqual(configure_disassembly_backend(env), 'smda')
        self.assertEqual(configure_disassembly_backend(env), 'smda')

    def test_invalid_backend_fails_without_mutating_environment(self):
        for value in ['smd', 'binaryninja', 'auto', 'bn;exit']:
            with self.subTest(value=value):
                env = {'CODEFENDER_DISASM_BACKEND': value}
                with self.assertRaisesRegex(ValueError, 'must be smda or bn'):
                    configure_disassembly_backend(env)
                self.assertEqual(env['CODEFENDER_DISASM_BACKEND'], value)

    def test_unrelated_settings_preserved(self):
        env = {'CODEFENDER_NON_MALGRAPH_IR': '0', 'OTHER': 'keep'}
        configure_disassembly_backend(env)
        self.assertEqual(env['CODEFENDER_NON_MALGRAPH_IR'], '0')
        self.assertEqual(env['OTHER'], 'keep')

    def test_workers_inherit_engine_choice(self):
        for value, expected in [(None, 'smda'), (' BN ', 'bn')]:
            with self.subTest(value=value), patch.dict(os.environ, {}, clear=False):
                if value is None:
                    os.environ.pop('CODEFENDER_DISASM_BACKEND', None)
                else:
                    os.environ['CODEFENDER_DISASM_BACKEND'] = value
                configure_disassembly_backend()
                result = subprocess.run([sys.executable, '-B', '-c',
                                         'from engine.analysis_worker import selected_backend; print(selected_backend())'],
                                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_standalone_worker_legacy_default_unchanged(self):
        from engine.analysis_worker import selected_backend
        self.assertEqual(selected_backend({}), 'bn')

    def test_shared_server_configures_before_loading_listeners(self):
        import engine.serve as server
        for value, expected in [(None, 'smda'), (' BN ', 'bn')]:
            with self.subTest(value=value), patch.dict(os.environ, {}, clear=False):
                if value is None:
                    os.environ.pop('CODEFENDER_DISASM_BACKEND', None)
                else:
                    os.environ['CODEFENDER_DISASM_BACKEND'] = value
                with patch.object(server, 'listeners', side_effect=RuntimeError('stop-before-bind')):
                    with self.assertRaisesRegex(RuntimeError, 'stop-before-bind'):
                        asyncio.run(server.serve())
                self.assertEqual(os.environ['CODEFENDER_DISASM_BACKEND'], expected)

    def test_all_direct_asgi_imports_select_default_and_preserve_bn(self):
        # Fresh processes avoid cached imports hiding missing startup initialization.
        for module in ['engine.app', 'engine.dev.app', 'engine.web_compat']:
            for value, expected in [(None, 'smda'), (' BN ', 'bn')]:
                with self.subTest(module=module, value=value):
                    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', CODEFENDER_HASH_DB_ENABLED='0',
                               CODEFENDER_FUZZY_DB_ENABLED='0', CODEFENDER_REQUIRE_HASH_DB='0',
                               CODEFENDER_RUNTIME_CFG_DISABLE='1', CODEFENDER_NON_MALGRAPH_IR='0')
                    if value is None:
                        env.pop('CODEFENDER_DISASM_BACKEND', None)
                    else:
                        env['CODEFENDER_DISASM_BACKEND'] = value
                    code = ('import importlib, json, os; importlib.import_module(' + repr(module) + '); '
                            'import engine.app as core; '
                            'print(json.dumps([core.DISASM_BACKEND, os.environ["CODEFENDER_DISASM_BACKEND"], '
                            'core._ENSEMBLE is None, core._MALGRAPH_RUNTIME is None]))')
                    result = subprocess.run([sys.executable, '-B', '-X', 'utf8', '-c', code], cwd=ROOT,
                                            env=env, capture_output=True, text=True, encoding='utf-8', timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]), [expected, expected, True, True])

    def test_supervisor_does_not_override_explicit_backend(self):
        import configparser
        for name in ['codefender.ini', 'codefender.smda.ini', 'codefender.smda.gpu-serve.ini', 'codefender.smda.gpu-train.ini']:
            with self.subTest(name=name):
                parser = configparser.RawConfigParser()
                parser.read(ROOT / name, encoding='utf-8')
                for section in parser.sections():
                    self.assertNotIn('CODEFENDER_DISASM_BACKEND=', parser.get(section, 'environment', fallback=''))

    def test_startup_cli(self):
        env = dict(os.environ)
        env.pop('CODEFENDER_DISASM_BACKEND', None)
        result = subprocess.run([sys.executable, '-B', '-m', 'engine.startup'], cwd=ROOT,
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'smda')
        env['CODEFENDER_DISASM_BACKEND'] = 'typo'
        result = subprocess.run([sys.executable, '-B', '-m', 'engine.startup'], cwd=ROOT,
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
