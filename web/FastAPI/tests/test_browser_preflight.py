"""Hash-only browser flow: no real database, model, or sample directory."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import Response
from pydantic import ValidationError
import main
from app.detection_queue import DetectionTaskStore

SHA = 'a' * 64
ID = 'b' * 32


class BrowserPreflightTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.store = DetectionTaskStore(self.root/'tasks.sqlite3', 3600)
        self.patch = patch.object(main, 'task_store', self.store)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.folder.cleanup()

    def preflight(self, sha=SHA, task_id=ID):
        return asyncio.run(main.upload_preflight(
            main.UploadPreflight(sha256=sha, filename='sample.exe', file_size=4), task_id))

    def test_hit_has_no_upload_or_model_and_retry_counts_once(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': SHA}) as find, \
             patch.object(main, 'save_upload') as save, patch.object(main, 'scan_file') as scan:
            result = self.preflight()
            repeat = self.preflight(sha=SHA.upper())
        self.assertEqual(result, repeat)
        self.assertFalse(result['upload_required'])
        self.assertFalse(result['result']['file_uploaded'])
        self.assertFalse(result['result']['pe_structure_checked'])
        self.assertEqual(result['result']['verdict'], 'Malicious')
        self.assertEqual(find.call_count, 1)
        save.assert_not_called(); scan.assert_not_called()
        stats = self.store.detection_summary()
        self.assertEqual((stats['received_total'], stats['malicious_total'], stats['query_total']), (1, 1, 0))

    def test_miss_prechecks_are_not_counted_twice_before_upload(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value=None):
            self.assertTrue(self.preflight()['upload_required'])
            self.assertTrue(self.preflight()['upload_required'])
            self.assertEqual(self.store.detection_summary()['received_total'], 0)
            sample = self.root/'upload'; sample.write_bytes(b'test')
            with patch.object(main, 'save_upload', AsyncMock(return_value=(sample, dict(
                    filename='sample.exe', sha256=SHA, is_pe=True, file_size=4)))), \
                 patch.object(main, 'task_wakeup', asyncio.Event()), patch.object(main, 'scan_file') as scan:
                result = asyncio.run(main.detect(Response(), object(), ID, SHA))
            scan.assert_not_called()
        self.assertEqual(result['status'], 'queued')
        stats = self.store.detection_summary()
        self.assertEqual((stats['received_total'],stats['in_progress_total'],stats['query_total']), (1,1,0))

    def test_mismatch_deletes_only_upload_and_never_queries_or_queues(self):
        sample = self.root/'upload'; sample.write_bytes(b'test')
        with patch.object(main, 'save_upload', AsyncMock(return_value=(sample, {'sha256': 'c'*64}))), \
             patch.object(main.sample_repository, 'find_malicious') as find, patch.object(main, 'scan_file') as scan:
            with self.assertRaises(main.HTTPException) as caught:
                asyncio.run(main.detect(Response(), object(), ID, SHA))
        self.assertEqual(caught.exception.status_code, 409)
        find.assert_not_called(); scan.assert_not_called()
        self.assertFalse(sample.exists())
        self.assertEqual(self.store.detection_summary()['received_total'], 0)

    def test_database_outage_never_requests_upload_or_records_a_miss(self):
        with patch.object(main.sample_repository, 'find_malicious', side_effect=RuntimeError('offline')):
            with self.assertRaises(main.HTTPException) as caught: self.preflight()
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(self.store.detection_summary()['received_total'], 0)

    def test_same_request_cannot_be_reused_for_another_hash(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': SHA}): self.preflight()
        with self.assertRaises(main.HTTPException) as caught: self.preflight('c'*64)
        self.assertEqual(caught.exception.status_code, 409)
        with self.assertRaises(main.HTTPException) as caught:
            asyncio.run(main.detect(Response(), object(), ID, 'c'*64))
        self.assertEqual(caught.exception.status_code, 409)

    def test_expired_result_cannot_be_recounted(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': SHA}): self.preflight()
        with self.store._connect() as cn:
            cn.execute("UPDATE detection_tasks SET updated_at='2000-01-01T00:00:00'")
        self.store.cleanup()
        with self.assertRaises(main.HTTPException) as caught: self.preflight()
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.store.detection_summary()['received_total'], 1)

    def test_invalid_metadata_is_rejected(self):
        for values in [dict(sha256='x'*64),dict(file_size=-1),dict(file_size=True),dict(filename='x'*256)]:
            with self.assertRaises(ValidationError):
                main.UploadPreflight(**(dict(sha256=SHA,filename='s.exe',file_size=4)|values))
        with self.assertRaises(main.HTTPException) as caught: self.preflight(task_id='bad')
        self.assertEqual(caught.exception.status_code, 400)

    def test_preflight_hit_survives_later_multipart_retry_without_saving(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': SHA}): self.preflight()
        with patch.object(main, 'save_upload') as save:
            result = asyncio.run(main.detect(Response(), object(), ID, SHA))
        save.assert_not_called()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(self.store.detection_summary()['received_total'], 1)

    def test_json_route_accepts_request_and_rejects_invalid_schema(self):
        async def request(values):
            sent = []
            payload = json.dumps(values).encode()
            scope = {'type':'http','http_version':'1.1','method':'POST','scheme':'http',
                     'path':'/detect/preflight','raw_path':b'/detect/preflight','query_string':b'',
                     'headers':[(b'content-type',b'application/json'),(b'x-detection-id',ID.encode()),
                                (b'content-length',str(len(payload)).encode())],
                     'client':('preflight-test',1),'server':('test',80)}
            async def receive(): return {'type':'http.request','body':payload,'more_body':False}
            async def send(message): sent.append(message)
            await main.app(scope,receive,send)
            status = next(m['status'] for m in sent if m['type']=='http.response.start')
            body = b''.join(m.get('body',b'') for m in sent if m['type']=='http.response.body')
            return status,json.loads(body)
        with patch.object(main.sample_repository,'find_malicious',return_value={'sha256':SHA}):
            status,body = asyncio.run(request(dict(sha256=SHA,filename='s.exe',file_size=4)))
        self.assertEqual(status,200)
        self.assertFalse(body['upload_required'])
        status,_ = asyncio.run(request(dict(sha256='invalid',filename='s.exe',file_size=4)))
        self.assertEqual(status,422)
