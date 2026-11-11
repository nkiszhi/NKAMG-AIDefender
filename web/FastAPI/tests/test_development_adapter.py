import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from app.config import settings
from app.codefender_client import DEFAULT_MODEL_NAMES, parse_codefender_response, scan_file


def diagnostic_result(label='Generic.ML.Medium'):
    benign = label == 'Benign'
    return {
        'Status': 0 if benign else 1, 'IsMalicious': not benign,
        'Score': 0.2 if benign else 0.73,
        'ScanResult': {
            'VirusName': label,
            'PerModelScores': {name: (0.5 if index == 0 else 0.8)
                               for index, name in enumerate(DEFAULT_MODEL_NAMES)},
            'ModelStats': {'TotalModels': 33, 'OkModels': 33, 'ExcludedModels': {}},
        },
    }


class DevelopmentAdapterTests(unittest.TestCase):
    def test_forwards_each_engine_label_without_recomputing_tier(self):
        for label in ('Generic.ML.Low', 'Generic.ML.Medium', 'Generic.ML.High', 'Benign'):
            with self.subTest(label=label):
                result = parse_codefender_response(diagnostic_result(label))
                self.assertEqual(result['集成结果']['display_result'], label)
                self.assertEqual(result['集成结果']['result'], 'Benign' if label == 'Benign' else 'Malicious')
                self.assertEqual(result['集成结果']['total_models'], 33)
                self.assertEqual(result['集成结果']['ok_models'], 33)
                self.assertEqual(len(result) - 1, 33)

    def test_missing_preds_use_engine_threshold_even_if_web_threshold_differs(self):
        with patch.object(settings, 'threshold', 0.99):
            result = parse_codefender_response(diagnostic_result())
        self.assertEqual(result[DEFAULT_MODEL_NAMES[0]]['result'], 'Benign')
        self.assertEqual(result[DEFAULT_MODEL_NAMES[1]]['result'], 'Malicious')

    def test_exclusions_and_unreported_models_are_not_benign(self):
        data = diagnostic_result()
        del data['ScanResult']['PerModelScores']['MalGraph']
        del data['ScanResult']['PerModelScores']['CFGGAT']
        data['ScanResult']['ModelStats'].update(OkModels=31, ExcludedModels={'MalGraph': 'feature extraction failed'})
        result = parse_codefender_response(data)
        self.assertIsNone(result['MalGraph']['probability'])
        self.assertEqual(result['MalGraph']['status'], 'excluded')
        self.assertEqual(result['MalGraph']['reason'], 'feature extraction failed')
        self.assertEqual(result['CFGGAT']['status'], 'unreported')
        self.assertEqual(result['集成结果']['excluded_models'], 2)
        self.assertEqual(result['集成结果']['ok_models'], 31)
        self.assertEqual(len(result) - 1, 33)

    def test_inconsistent_engine_name_is_rejected(self):
        data = diagnostic_result()
        data['IsMalicious'] = False
        with self.assertRaises(ValueError):
            parse_codefender_response(data)

    def test_invalid_scores_and_counts_are_rejected(self):
        for value in (float('nan'), float('inf'), -0.1, 1.1, True, None):
            data = diagnostic_result()
            data['ScanResult']['PerModelScores']['MalGraph'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_codefender_response(data)
        data = diagnostic_result()
        data['ScanResult']['ModelStats']['OkModels'] = 32
        with self.assertRaises(ValueError):
            parse_codefender_response(data)

    def test_hash_precheck_never_claims_33_models_ran(self):
        result = parse_codefender_response({
            'Status': 1, 'IsMalicious': True, 'Score': 1,
            'ScanResult': {'VirusName': 'Malicious', 'PerModelScores': {}, 'HashMatch': {'sha256': 'a' * 64}},
        })
        self.assertEqual(list(result), ['签名库预检', '集成结果'])
        self.assertEqual(result['集成结果']['source'], 'signature')
        self.assertNotIn('ok_models', result['集成结果'])

    def scan_development(self, response_data, urls=None):
        response = Mock(status_code=200)
        response.json.return_value = response_data
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.exe'
            path.write_bytes(b'fixture')
            with patch.object(settings, 'codefender_response_contract', 'development'), \
                 patch.object(settings, 'codefender_api_bases', urls or ['http://127.0.0.1:18002']), \
                 patch('app.codefender_client.requests.post', return_value=response) as post, \
                 patch('app.codefender_client._scan_by_path') as by_path, \
                 patch('app.codefender_client._scan_by_stream') as stream:
                result = scan_file(path)
                by_path.assert_not_called()
                stream.assert_not_called()
                self.assertEqual(post.call_count, 1)
                self.assertTrue(post.call_args.args[0].endswith('/predict-single'))
                self.assertEqual(post.call_args.kwargs['params'], {'include_de': 'true'})
                return result

    def test_final_only_development_upload_bypasses_stream_and_path_for_one_or_many_workers(self):
        for urls in (None, ['http://first:18002', 'http://second:18002']):
            result = self.scan_development(diagnostic_result(), urls)
            self.assertEqual(result['集成结果']['display_result'], 'Generic.ML.Medium')

    def test_production_projection_and_unapproved_name_fail_in_development_mode(self):
        with self.assertRaises(RuntimeError):
            self.scan_development({'IsMalicious': True, 'ScanResult': {'VirusName': 'Malicious'}})
        with self.assertRaises(RuntimeError):
            self.scan_development(diagnostic_result('Invented.Family'))

    def test_web_development_uses_stream_and_forwards_progress_for_one_or_many_workers(self):
        progress_data = {'stage': 'models', 'models': [{'model': 'MalConv', 'status': 'ok', 'score': 0.8, 'prediction': 1}]}
        for urls in (['http://first'], ['http://first', 'http://second']):
            response = MagicMock(status_code=200)
            response.__enter__.return_value = response
            response.iter_lines.return_value = iter(json.dumps(event).encode() for event in [
                {'event': 'heartbeat'}, {'event': 'progress', 'data': progress_data},
                {'event': 'result', 'data': diagnostic_result()},
            ])
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'sample.exe'
                path.write_bytes(b'fixture')
                callback = Mock()
                with patch.object(settings, 'codefender_response_contract', 'development'), \
                     patch.object(settings, 'codefender_api_bases', urls), \
                     patch('app.codefender_client.requests.post', return_value=response) as post:
                    result = scan_file(path, on_progress=callback)
                callback.assert_called_once_with(progress_data)
                self.assertEqual(post.call_count, 1)
                self.assertTrue(post.call_args.args[0].endswith('/predict-stream'))
                self.assertTrue(post.call_args.kwargs['stream'])
                self.assertEqual(result['集成结果']['display_result'], 'Generic.ML.Medium')

    def test_stream_failure_or_truncation_does_not_resubmit_sample(self):
        for events in ([{'event': 'error', 'detail': 'model failed'}], [{'event': 'heartbeat'}]):
            response = MagicMock(status_code=200)
            response.__enter__.return_value = response
            response.iter_lines.return_value = iter(json.dumps(event).encode() for event in events)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'sample.exe'
                path.write_bytes(b'fixture')
                with patch.object(settings, 'codefender_response_contract', 'development'), \
                     patch.object(settings, 'codefender_api_bases', ['http://first', 'http://second']), \
                     patch('app.codefender_client.requests.post', return_value=response) as post:
                    with self.assertRaises(RuntimeError):
                        scan_file(path, on_progress=lambda _: None)
                self.assertEqual(post.call_count, 1)

    def test_missing_stream_route_falls_back_once_to_unchanged_single(self):
        missing = MagicMock(status_code=404)
        missing.__enter__.return_value = missing
        final = Mock(status_code=200)
        final.json.return_value = diagnostic_result()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.exe'
            path.write_bytes(b'fixture')
            with patch.object(settings, 'codefender_response_contract', 'development'), \
                 patch.object(settings, 'codefender_api_bases', ['http://first']), \
                 patch('app.codefender_client.requests.post', side_effect=[missing, final]) as post:
                result = scan_file(path, on_progress=lambda _: None)
            self.assertEqual([call.args[0] for call in post.call_args_list],
                             ['http://first/predict-stream', 'http://first/predict-single'])
            self.assertEqual(result['集成结果']['display_result'], 'Generic.ML.Medium')


if __name__ == '__main__':
    unittest.main()
