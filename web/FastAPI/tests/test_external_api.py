import asyncio
import tempfile
import unittest
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import requests

import main
from app.codefender_client import DEFAULT_MODEL_NAMES
from app.detection_queue import DetectionTaskStore
from app.multipart_upload import MultipartUpload
import test_http_guard
from app.http_guard import PublicAPIGuard
from test_pe_structure import make_pe


def model_result(label):
    verdict = 'Benign' if label == 'Benign' else 'Malicious'
    result = {name: {'result': verdict, 'probability': 0.2 if label == 'Benign' else 0.8}
              for name in DEFAULT_MODEL_NAMES}
    result['集成结果'] = {'result': verdict, 'display_result': label, 'source': 'models', 'probability': 0.8}
    return result


class ExternalAPITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.uploads = self.root / 'uploads'
        self.store = DetectionTaskStore(self.root / 'tasks.sqlite3', 3600)
        self.patches = [patch.object(main, 'task_store', self.store),
                        patch.object(main, 'task_wakeup', asyncio.Event()),
                        patch.object(main.settings, 'upload_dir', self.uploads)]
        for item in self.patches:
            item.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://test')

    async def asyncTearDown(self):
        await self.client.aclose()
        for item in reversed(self.patches):
            item.stop()
        self.folder.cleanup()

    async def process_one(self):
        for _ in range(200):
            row = await asyncio.to_thread(self.store.claim_next)
            if row:
                await main._process_detection_task(row['task_id'], Path(row['file_path']), row)
                return
            await asyncio.sleep(0.01)
        self.fail('No accepted task reached the worker')

    async def submit_and_process(self, label='Generic.ML.High', error=None):
        with patch.object(main, 'scan_file', return_value=model_result(label), side_effect=error) as scan, \
             patch.object(main.sample_repository, 'find_malicious', side_effect=AssertionError('API must use models')):
            worker = asyncio.create_task(self.process_one())
            try:
                response = await self.client.post('/api/v1/detect?wait_seconds=5',
                                                  files={'file': ('sample.bin', bytes(make_pe()))})
                await worker
            finally:
                if not worker.done():
                    worker.cancel()
                    await asyncio.gather(worker, return_exceptions=True)
            scan.assert_called_once()
            self.assertTrue(scan.call_args.kwargs['include_de'])
        self.assertEqual(list(self.uploads.iterdir()), [])
        return response

    async def test_each_success_is_one_final_verdict_and_one_persistent_count(self):
        for index, label in enumerate(main.API_ML_LABELS, 1):
            response = await self.submit_and_process(label)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {'result': label})
            self.assertEqual(self.store.detection_summary()['received_total'], index)
            self.assertEqual(self.store.detection_summary()['model_total'], index)
            task_id = response.headers['X-Detection-ID']
            result = await self.client.get(f'/api/v1/detect/tasks/{task_id}')
            self.assertEqual(result.json(), {'result': label})
            self.assertEqual(self.store.detection_summary()['received_total'], index)
        restarted = DetectionTaskStore(self.store.path, 3600)
        self.assertEqual(restarted.detection_summary()['received_total'], 4)
        self.assertEqual(restarted.detection_summary()['malicious_total'], 3)
        self.assertEqual(restarted.detection_summary()['benign_total'], 1)

    async def test_failure_deletes_sample_and_is_not_benign(self):
        response = await self.submit_and_process(error=RuntimeError('test model failure'))
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()['result'], 'Failed')
        stats = self.store.detection_summary()
        self.assertEqual(stats['received_total'], 1)
        self.assertEqual(stats['failed_total'], 1)
        self.assertEqual(stats['benign_total'], 0)

    async def test_old_binary_malicious_cannot_be_invented_into_a_generic_tier(self):
        response = await self.submit_and_process('Malicious')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()['result'], 'Failed')
        self.assertEqual(self.store.detection_summary()['failed_total'], 1)

    async def test_no_api_size_limit_even_if_browser_limit_is_small(self):
        with patch.object(main.settings, 'max_upload_size', 4):
            response = await self.submit_and_process()
        self.assertEqual(response.status_code, 200)

    async def test_rejects_multiple_file_parts_and_invalid_form_without_counting(self):
        for files in ([('file', ('a', b'a')), ('file', ('b', b'b'))],
                      [('file', ('a', b'a')), ('other', ('b', b'b'))],
                      [('other', ('a', b'a'))]):
            response = await self.client.post('/api/v1/detect', files=files)
            self.assertIn(response.status_code, (400, 422))
            self.assertEqual(response.json()['result'], 'Failed')
        self.assertEqual(self.store.detection_summary()['received_total'], 0)
        self.assertFalse(self.uploads.exists())

    async def test_non_pe_returns_failed_and_removes_upload(self):
        response = await self.client.post('/api/v1/detect', files={'file': ('text.exe', b'not a PE')})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()['result'], 'Failed')
        self.assertEqual(self.store.detection_summary()['received_total'], 1)
        self.assertEqual(list(self.uploads.iterdir()), [])

    async def test_retry_and_poll_do_not_rerun_or_increment(self):
        task_id = 'd' * 32
        for _ in range(2):
            response = await self.client.post('/api/v1/detect?wait_seconds=0', headers={'X-Detection-ID': task_id},
                                              files={'file': ('sample', bytes(make_pe()))})
            self.assertEqual(response.status_code, 202)
        self.assertEqual(self.store.detection_summary()['received_total'], 1)
        with patch.object(main, 'scan_file', return_value=model_result('Generic.ML.Low')) as scan:
            await self.process_one()
            for _ in range(2):
                response = await self.client.get(f'/api/v1/detect/tasks/{task_id}')
                self.assertEqual(response.json(), {'result': 'Generic.ML.Low'})
            response = await self.client.post('/api/v1/detect', headers={'X-Detection-ID': task_id},
                                              files={'file': ('sample', bytes(make_pe()))})
            self.assertEqual(response.json(), {'result': 'Generic.ML.Low'})
            scan.assert_called_once()
        self.assertEqual(self.store.detection_summary()['received_total'], 1)
        self.assertEqual(list(self.uploads.iterdir()), [])

    async def test_api_queue_survives_browser_absence_and_web_leave(self):
        response = await self.client.post('/api/v1/detect?wait_seconds=0', files={'file': ('sample', bytes(make_pe()))})
        task_id = response.json()['task_id']
        with self.store._connect() as connection:
            connection.execute("UPDATE detection_tasks SET client_seen_at='2000-01-01',client_left_at='2000-01-01'")
        self.store.leave(task_id)
        self.assertEqual(self.store.cancel_abandoned(), [])
        self.assertEqual(self.store.claim_next()['task_id'], task_id)

    async def test_full_queue_rejects_without_counting_and_removes_file(self):
        capacity = main.settings.max_queued_scans + main.settings.max_concurrent_scans
        for index in range(capacity):
            self.store.create(str(index), 'busy', self.root / str(index), capacity)
        response = await self.client.post('/api/v1/detect?wait_seconds=0', files={'file': ('sample', bytes(make_pe()))})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.store.detection_summary()['received_total'], capacity)
        self.assertEqual(list(self.uploads.iterdir()), [])

    async def test_low_disk_fails_without_retaining_upload_or_counting_detection(self):
        with patch('app.file_info.shutil.disk_usage', return_value=SimpleNamespace(free=0)):
            response = await self.client.post('/api/v1/detect', files={'file': ('sample', bytes(make_pe()))})
        self.assertEqual(response.status_code, 507)
        self.assertEqual(response.json()['result'], 'Failed')
        self.assertEqual(list(self.uploads.iterdir()), [])
        self.assertEqual(self.store.detection_summary()['received_total'], 0)

    async def test_expired_request_id_does_not_scan_without_incrementing(self):
        task_id = 'e' * 32
        self.store.create(task_id, 'sample', self.root / 'gone', 1, request_source='api')
        self.store.complete(task_id, {'detection_mode': 'models', 'exe_result': model_result('Benign')})
        with self.store._connect() as connection:
            connection.execute("UPDATE detection_tasks SET updated_at='2000-01-01'")
        self.store.cleanup()
        response = await self.client.post('/api/v1/detect?wait_seconds=0', headers={'X-Detection-ID': task_id},
                                          files={'file': ('sample', bytes(make_pe()))})
        self.assertEqual(response.status_code, 410)
        self.assertEqual(list(self.uploads.iterdir()), [])
        self.assertEqual(self.store.detection_summary()['received_total'], 1)


class APIUploadTransportTests(unittest.TestCase):
    def test_api_body_has_no_byte_cap_while_browser_retains_its_cap(self):
        check = test_http_guard.HTTPGuardTests()
        guard = PublicAPIGuard(check.consume, 10)
        response = check.request(guard, [b'a' * 30], [(b'content-length', b'2147483648')], path='/api/v1/detect')
        self.assertEqual(response[0]['status'], 200)
        response = check.request(guard, [b'a' * 30], path='/detect')
        self.assertEqual(response[0]['status'], 413)

    def test_model_upload_is_streamed_valid_multipart_with_exact_length(self):
        content = b'upload fixture' * 10000
        with tempfile.TemporaryFile() as handle:
            handle.write(content)
            handle.seek(0)
            body = MultipartUpload(handle)
            request = requests.Request('POST', 'http://model/predict-single', data=body, headers=body.headers).prepare()
            self.assertIs(request.body, body)
            chunks = list(request.body)
            self.assertLessEqual(max(map(len, chunks)), 64 * 1024)
            wire = b''.join(chunks)
            self.assertEqual(len(wire), int(request.headers['Content-Length']))
            parsed = BytesParser().parsebytes(('Content-Type: ' + request.headers['Content-Type'] + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + wire)
            self.assertEqual(len(parsed.get_payload()), 1)
            self.assertEqual(parsed.get_payload()[0].get_payload(decode=True), content)


if __name__ == '__main__':
    unittest.main()
