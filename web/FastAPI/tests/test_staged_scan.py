import ast
import importlib.util
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


staged = load_module('staged', 'CoDefenderC3/engine/staged_scan.py')
upgrade = load_module('upgrade', 'CoDefenderC3/docker/patch_progress.py')


class StagedScanTests(unittest.TestCase):
    def analysis_loader(self):
        # Exercise the production loader without importing native BinaryNinja.
        tree = ast.parse((ROOT / 'CoDefenderC3/engine/analysis_worker.py').read_text(encoding='utf-8'))
        function = next(node for node in tree.body if getattr(node, 'name', '') == 'load_analysis_view')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'analysis-loader', 'exec'), namespace)
        return namespace['load_analysis_view']

    def test_analysis_load_generates_mlil_and_reuses_one_view(self):
        from unittest.mock import Mock
        view = object()
        bn = SimpleNamespace(load=Mock(return_value=view))
        self.assertIs(self.analysis_loader()(bn, 'sample.pe'), view)
        bn.load.assert_called_once_with('sample.pe', options={
            'analysis.mode': 'intermediate', 'analysis.linearSweep.autorun': True,
            'analysis.limits.maxFunctionSize': 262144,
        })

    def test_analysis_load_rejects_missing_binary_view(self):
        from unittest.mock import Mock
        bn = SimpleNamespace(load=Mock(return_value=None))
        with self.assertRaisesRegex(RuntimeError, 'could not open'):
            self.analysis_loader()(bn, 'sample.pe')

    def test_timeout_chain_reserves_model_time_even_with_old_container_values(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(staged.analysis_timeout(), 180)
            self.assertEqual(staged.runtime_limits(), (360, 420))
        with patch.dict(os.environ, {'CODEFENDER_ANALYSIS_TIMEOUT': '180', 'CODEFENDER_REQUEST_TIMEOUT': '240', 'CODEFENDER_HARD_TIMEOUT': '300'}, clear=True):
            self.assertEqual(staged.runtime_limits(), (360, 420))
        with patch.dict(os.environ, {'CODEFENDER_ANALYSIS_TIMEOUT': '300'}, clear=True):
            self.assertEqual(staged.runtime_limits(), (480, 540))

    def test_ninety_second_notice_continues_same_process_to_success(self):
        from unittest.mock import Mock
        import pickle
        process = SimpleNamespace(pid=999999, returncode=0, kill=Mock())
        process.wait = Mock(side_effect=[subprocess.TimeoutExpired('worker', 90), 0])
        def start(command, **kwargs):
            Path(command[-1]).write_bytes(pickle.dumps({'features': {}, 'malgraph': {}}))
            return process
        notice = Mock()
        with patch.object(staged.subprocess, 'Popen', side_effect=start) as spawn:
            result = staged.isolated_analysis('sample.exe', timeout=180, on_slow=notice)
        notice.assert_called_once()
        spawn.assert_called_once()
        process.kill.assert_not_called()
        self.assertEqual([call.kwargs['timeout'] for call in process.wait.call_args_list], [90, 90])
        self.assertIn('seconds', result)

    def namespace(self, calls):
        def predict(ens, views, **kwargs):
            items = [{'model': name, 'status': 'ok', 'score': .8, 'prediction': 1}
                     for name in sorted(kwargs['selected_models']) if name in ('fast', 'slow', 'MalGraph')]
            for item in items:
                kwargs['on_result'](item)
            calls.append(('predict', kwargs['include_de']))
            return items
        return {
            'config': SimpleNamespace(VIEW_GROUPS={'fast_view': {'binja_features': ['B01']},
                                                 'slow_view': {'binja_features': ['D01']}}),
            '_get_extractor': lambda: SimpleNamespace(extract_fast=lambda path: {'B01': [1]}),
            '_extract_views_for_single_sample': lambda *a, **k: ({}, {}),
            '_predict_per_model': predict,
            '_scan_single_pe': lambda *a, **k: {'ScanResult': {}, 'original_formatter': True},
        }

    def test_fast_results_publish_before_binaryninja_and_no_model_runs_twice(self):
        calls, updates = [], []
        ns = self.namespace(calls)
        ens = SimpleNamespace(view_groups={'fast_view': ['fast'], 'slow_view': ['slow', 'MalGraph']})
        def analyze(*args, **kwargs):
            self.assertTrue(any(any(item['model'] == 'fast' and item['status'] == 'ok' for item in update['models']) for update in updates))
            self.assertEqual(calls, [('predict', False)])
            return {'features': {}, 'malgraph': {}, 'seconds': 1}
        with patch.object(staged, 'isolated_analysis', side_effect=analyze) as analysis:
            report = staged.run_staged(ns, 'a', 'a.exe', 1, ens, {}, True, updates.append)
        self.assertEqual(analysis.call_count, 1)
        self.assertEqual(calls, [('predict', False), ('predict', True)])
        self.assertEqual(len(report['ScanResult']['PerModelDetails']), 3)
        self.assertTrue(report['original_formatter'])

    def test_binaryninja_timeout_preserves_fast_result_and_marks_missing_models(self):
        calls = []
        ens = SimpleNamespace(view_groups={'fast_view': ['fast'], 'slow_view': ['slow', 'MalGraph']})
        with patch.object(staged, 'isolated_analysis', side_effect=subprocess.TimeoutExpired('worker', 90)):
            report = staged.run_staged(self.namespace(calls), 'a', 'a', 1, ens, {}, True)
        details = {item['model']: item for item in report['ScanResult']['PerModelDetails']}
        self.assertEqual(details['fast']['status'], 'ok')
        self.assertEqual(details['slow']['status'], 'timeout')
        self.assertEqual(details['MalGraph']['status'], 'timeout')
        self.assertEqual(calls, [('predict', False)])

    def test_analysis_timeout_kills_and_reaps_child_before_temp_cleanup(self):
        process = SimpleNamespace(pid=999999, returncode=-9)
        from unittest.mock import Mock
        process.wait = Mock(side_effect=[subprocess.TimeoutExpired('worker', 1), -9])
        process.kill = Mock()
        with patch.object(staged.subprocess, 'Popen', return_value=process), patch.object(staged.os, 'killpg', create=True) as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                staged.isolated_analysis('sample.exe', timeout=1)
            self.assertEqual(process.wait.call_count, 2)
            if os.name == 'posix':
                kill.assert_called_once()
            else:
                process.kill.assert_called_once()

    def test_upgrade_is_idempotent_and_preserves_model_code(self):
        source = (ROOT / 'CoDefenderC3/engine/app.py').read_text(encoding='utf-8')
        fragment = (ROOT / 'CoDefenderC3/docker/runtime_endpoints.py').read_text(encoding='utf-8')
        once = upgrade.upgrade_source(source, fragment)
        twice = upgrade.upgrade_source(once, fragment)
        self.assertEqual(once, twice)
        original = ast.parse(source)
        patched = ast.parse(twice)
        for name in ('_load_ensemble', '_load_malgraph_runtime'):
            before = next(node for node in original.body if getattr(node, 'name', '') == name)
            after = next(node for node in patched.body if getattr(node, 'name', '') == name)
            self.assertEqual(ast.dump(before), ast.dump(after))
        self.assertEqual(sum(getattr(node, 'name', '') == 'predict_stream' for node in patched.body), 1)

    def test_upgrade_original_v8_signatures_and_callbacks(self):
        import subprocess as sp
        source = sp.check_output(['git', 'show', 'f15ffa9:CoDefenderC3/engine/app.py'], cwd=ROOT, text=True, encoding='utf-8')
        fragment = (ROOT / 'CoDefenderC3/docker/runtime_endpoints.py').read_text(encoding='utf-8')
        upgraded = upgrade.upgrade_source(source, fragment)
        tree = ast.parse(upgraded)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertIn('selected_models', [arg.arg for arg in functions['_predict_per_model'].args.args])
        self.assertIn('per_model_override', [arg.arg for arg in functions['_scan_single_pe'].args.args])
        self.assertIn('on_result(dict(item))', upgraded)
        self.assertEqual(upgraded, upgrade.upgrade_source(upgraded, fragment))

    def test_transformed_v8_reuses_features_and_calls_each_model_once(self):
        import subprocess as sp
        source = sp.check_output(['git', 'show', 'f15ffa9:CoDefenderC3/engine/app.py'], cwd=ROOT, text=True, encoding='utf-8')
        fragment = (ROOT / 'CoDefenderC3/docker/runtime_endpoints.py').read_text(encoding='utf-8')
        tree = ast.parse(upgrade.upgrade_source(source, fragment))
        function = next(node for node in tree.body if getattr(node, 'name', '') == '_predict_per_model')
        function.decorator_list = []
        module = ast.Module(body=[ast.ImportFrom('__future__', [ast.alias('annotations')], 0), function], type_ignores=[])
        ast.fix_missing_locations(module)
        import numpy as np
        class Model:
            def predict_proba(self, value):
                return np.array([[.1, .9]])
        ens = SimpleNamespace(view_groups={'v': ['fast', 'other']}, _models={'fast': Model(), 'other': Model()},
                              _model_types={'fast': 'numpy', 'other': 'numpy'})
        ns = {'np': np, '_expected_dim_for_model': lambda *a: None}
        exec(compile(module, 'patched-v8-models', 'exec'), ns)
        updates = []
        results = ns['_predict_per_model'](ens, {'v': [[1]]}, selected_models={'fast'}, on_result=updates.append)
        self.assertEqual([item['model'] for item in results], ['fast'])
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]['status'], 'ok')
