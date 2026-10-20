import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import Response

import main
from app.detection_queue import DetectionTaskStore


class DatabasePreflightTests(unittest.TestCase):
    def test_sha_lookup_does_not_access_model_queue(self):
        with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': 'a' * 64}), \
             patch.object(main, 'task_store') as store, \
             patch.object(main, 'scan_file') as scan:
            result = asyncio.run(main.sample_by_sha256('a' * 64))
        self.assertTrue(result['database_hit'])
        self.assertEqual(store.mock_calls, [])
        scan.assert_not_called()

    def run_upload(self, folder, record=None, error=None):
        root = Path(folder)
        sample = root / 'upload.pe'
        sample.write_bytes(b'test fixture')
        info = dict(filename='sample.exe', sha256='a' * 64, md5='b' * 32,
                    file_size=12, file_type='exe64', is_pe=True, pe_info={}, query_result={})
        store = DetectionTaskStore(root / 'tasks.sqlite3', 3600)
        # Fill every model queue slot. Database hits should still return.
        capacity = main.settings.max_queued_scans + main.settings.max_concurrent_scans
        for index in range(capacity):
            store.create(str(index), 'busy', root / str(index), capacity)
        response = Response()
        with patch.object(main, 'task_store', store), \
             patch.object(main, 'save_upload', AsyncMock(return_value=(sample, info))), \
             patch.object(main.sample_repository, 'find_malicious', return_value=record, side_effect=error) as lookup, \
             patch.object(main, 'scan_file') as scan:
            try:
                result = asyncio.run(main.detect(response, file=object(), x_detection_id='c' * 32))
            except main.HTTPException as exc:
                result = exc
            lookup.assert_called_once_with(info['sha256'])
            scan.assert_not_called()
        self.assertFalse(sample.exists())
        self.assertIsNone(store.get('c' * 32))
        return result, response

    def test_known_upload_returns_even_when_model_queue_is_full(self):
        with tempfile.TemporaryDirectory() as folder:
            result, response = self.run_upload(folder, record={'sha256': 'a' * 64, 'name': 'known.exe'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(result['database_hit'])
        self.assertTrue(result['model_skipped'])
        self.assertEqual(result['detection_mode'], 'sample_database')

    def test_unknown_upload_still_obeys_model_queue_capacity(self):
        with tempfile.TemporaryDirectory() as folder:
            result, _ = self.run_upload(folder)
        self.assertEqual(result.status_code, 429)

    def test_database_outage_does_not_claim_a_hit_or_bypass_queue(self):
        with tempfile.TemporaryDirectory() as folder:
            result, _ = self.run_upload(folder, error=RuntimeError('private database failure'))
        self.assertEqual(result.status_code, 429)

    def test_unknown_upload_is_queued_without_starting_models_in_request(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = root / 'upload.pe'
            sample.write_bytes(b'test')
            info = dict(filename='sample.exe', sha256='a' * 64, is_pe=True)
            store = DetectionTaskStore(root / 'tasks.sqlite3', 3600)
            response = Response()
            with patch.object(main, 'task_store', store), \
                 patch.object(main, 'save_upload', AsyncMock(return_value=(sample, info))), \
                 patch.object(main.sample_repository, 'find_malicious', return_value=None), \
                 patch.object(main, 'scan_file') as scan:
                result = asyncio.run(main.detect(response, file=object(), x_detection_id='c' * 32))
                scan.assert_not_called()
            self.assertEqual(response.status_code, 202)
            self.assertEqual(result['status'], 'queued')
            self.assertEqual(store.get('c' * 32)['status'], 'queued')
            self.assertTrue(sample.exists())
