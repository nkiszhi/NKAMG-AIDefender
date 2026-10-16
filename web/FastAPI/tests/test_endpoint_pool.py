import threading
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from app.config import settings
from app.codefender_client import ModelEndpointPool, ModelServiceBusy, scan_file, _scan_by_stream


class EndpointPoolTests(unittest.TestCase):
    def test_stream_persists_progress_then_returns_one_final_result(self):
        from unittest.mock import MagicMock
        updates = []
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_lines.return_value = [json.dumps(item).encode() for item in [
            {'event': 'heartbeat'}, {'event': 'progress', 'data': {'models': [{'model': 'fast', 'status': 'ok'}]}},
            {'event': 'result', 'data': {'final': True}}]]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_bytes(b'pe')
            with patch('app.codefender_client.requests.post', return_value=response) as post, patch('app.codefender_client.parse_codefender_response', return_value={'ok': True}):
                self.assertEqual(_scan_by_stream(path, 'http://worker', updates.append), {'ok': True})
                self.assertEqual(post.call_count, 1)
        self.assertEqual(updates[0]['models'][0]['model'], 'fast')

    def test_stream_unknown_error_never_falls_back_to_full_scan(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = 200
        response.iter_lines.return_value = [b'{"event":"error","detail":"analysis failure"}']
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample'
            path.write_bytes(b'pe')
            with patch('app.codefender_client.requests.post', return_value=response), patch('app.codefender_client._scan_by_upload') as fallback:
                with self.assertRaises(RuntimeError):
                    _scan_by_stream(path, 'http://worker', lambda value: None)
                fallback.assert_not_called()
    def test_concurrent_requests_use_distinct_workers(self):
        barrier = threading.Barrier(2)
        urls = ['http://127.0.0.1:8001', 'http://127.0.0.1:8002']
        seen = []
        def request(path, api_base=None):
            seen.append(api_base)
            barrier.wait(timeout=5)
            return {'worker': api_base}
        with patch.object(settings, 'codefender_api_bases', urls), patch('app.codefender_client._endpoint_pool', ModelEndpointPool()), patch('app.codefender_client._scan_by_upload', side_effect=request):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(scan_file, [Path('a'), Path('b')]))
        self.assertEqual(set(seen), set(urls))
        self.assertEqual(len(results), 2)

    def test_third_request_does_not_enter_busy_workers(self):
        pool = ModelEndpointPool()
        urls = ['one', 'two']
        self.assertEqual(pool.acquire(urls), 'one')
        self.assertEqual(pool.acquire(urls), 'two')
        self.assertIsNone(pool.acquire(urls))
        pool.release('one')
        self.assertEqual(pool.acquire(urls), 'one')

    def test_explicit_busy_can_try_other_worker(self):
        with patch.object(settings, 'codefender_api_bases', ['one', 'two']), patch('app.codefender_client._endpoint_pool', ModelEndpointPool()), patch('app.codefender_client._scan_by_upload', side_effect=[ModelServiceBusy(), {'ok': True}]) as request:
            self.assertEqual(scan_file(Path('a')), {'ok': True})
            self.assertEqual(request.call_count, 2)

    def test_unknown_failure_is_not_replayed_on_other_worker(self):
        pool = ModelEndpointPool()
        with patch.object(settings, 'codefender_api_bases', ['one', 'two']), patch('app.codefender_client._endpoint_pool', pool), patch('app.codefender_client._scan_by_upload', return_value=None) as request:
            with self.assertRaises(RuntimeError):
                scan_file(Path('a'))
            self.assertEqual(request.call_count, 1)
        self.assertIsNotNone(pool.acquire(['one', 'two']))
