import asyncio
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import UploadFile
from app.config import settings
from app.detection_queue import DetectionTaskStore, QueueFull
from app.file_info import save_upload, UploadStorageFull


class QueuePolicyTests(unittest.TestCase):
    def test_leaving_task_is_not_claimed_and_refresh_restores_it(self):
        with tempfile.TemporaryDirectory() as folder:
            store = DetectionTaskStore(Path(folder) / 'tasks.sqlite3', 3600)
            store.create('a', 'a', Path(folder) / 'a', 2)
            store.leave('a')
            self.assertIsNone(store.claim_next())
            self.assertEqual(store.cancel_abandoned(), [])
            store.heartbeat('a')
            self.assertEqual(store.claim_next()['task_id'], 'a')

    def test_abandoned_queue_cancels_but_running_job_keeps_its_file(self):
        with tempfile.TemporaryDirectory() as folder:
            store = DetectionTaskStore(Path(folder) / 'tasks.sqlite3', 3600)
            for task in ('a', 'b', 'c'):
                store.create(task, task, Path(folder) / task, 3)
            store.claim_next()
            store.leave('a')
            store.leave('b')
            with store._connect() as connection:
                connection.execute("UPDATE detection_tasks SET client_left_at='2000-01-01' WHERE task_id IN ('a','b')")
                connection.execute("UPDATE detection_tasks SET client_seen_at='2000-01-01' WHERE task_id='c'")
            self.assertEqual(set(store.cancel_abandoned()), {str(Path(folder) / 'b'), str(Path(folder) / 'c')})
            self.assertEqual(store.get('a')['status'], 'running')
            self.assertEqual(store.get('b')['status'], 'cancelled')
            store.heartbeat('b')
            self.assertIsNone(store.claim_next())
            self.assertEqual(store.public_status(store.get('b'))['status'], 'cancelled')

    def test_progress_survives_store_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'tasks.sqlite3'
            store = DetectionTaskStore(path, 3600)
            store.create('a', 'a', Path(folder) / 'a', 1)
            store.claim_next()
            store.update_progress('a', {'models': [{'model': 'fast', 'status': 'ok', 'score': .8}]})
            reopened = DetectionTaskStore(path, 3600)
            self.assertEqual(reopened.public_status(reopened.get('a'))['progress']['models'][0]['score'], .8)

    def test_queue_moves_after_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            store = DetectionTaskStore(Path(folder) / 'tasks.sqlite3', 3600)
            for task in ('a', 'b', 'c'):
                store.create(task, task, Path(folder) / task, 3)
            with self.assertRaises(QueueFull):
                store.create('d', 'd', Path(folder) / 'd', 3)
            self.assertEqual(store.claim_next()['task_id'], 'a')
            self.assertEqual(store.public_status(store.get('c'))['tasks_ahead'], 2)
            store.complete('a', {'ok': True})
            self.assertEqual(store.get('c')['tasks_ahead'], 1)
            self.assertEqual(store.claim_next()['task_id'], 'b')
            store.set_status('b', 'failed', 'timeout')
            self.assertEqual(store.get('c')['tasks_ahead'], 0)
            self.assertEqual(store.claim_next()['task_id'], 'c')

    def test_cleanup_protects_active_files_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store = DetectionTaskStore(root / 'tasks.sqlite3', 3600)
            files = [root / ('a' * 64 + '-' + char * 32) for char in ('a', 'b', 'c')]
            for path in files:
                path.write_bytes(b'pe')
                os.utime(path, (1, 1))
            store.create('a', 'a', files[0], 8)
            store.create('b', 'b', files[1], 8)
            store.claim_next()
            other = root / 'user-file.exe'
            other.write_bytes(b'other')
            os.utime(other, (1, 1))
            self.assertEqual(store.orphan_paths(root, time.time() - 3600), [files[2]])

    def test_oversize_removes_partial_and_closes_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            upload = UploadFile(filename='large.exe', file=io.BytesIO(b'12345'))
            with patch.object(settings, 'upload_dir', Path(folder)), patch.object(settings, 'max_upload_size', 4):
                with self.assertRaises(ValueError):
                    asyncio.run(save_upload(upload))
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertTrue(upload.file.closed)

    def test_low_disk_rejects_before_creating_file(self):
        with tempfile.TemporaryDirectory() as folder:
            upload = UploadFile(filename='sample.exe', file=io.BytesIO(b'123'))
            with patch.object(settings, 'upload_dir', Path(folder)), patch('app.file_info.shutil.disk_usage', return_value=SimpleNamespace(free=0)):
                with self.assertRaises(UploadStorageFull):
                    asyncio.run(save_upload(upload))
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertTrue(upload.file.closed)
