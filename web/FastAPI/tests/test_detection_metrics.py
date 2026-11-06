import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from app.detection_queue import DetectionTaskStore, QueueFull


class DetectionMetricsTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'tasks.sqlite3'
        self.store = DetectionTaskStore(self.path, 60)

    def result(self, label, sha='a' * 64):
        labels = {'恶意': 'Malicious', '安全': 'Benign'}
        return {'sha256': sha, 'detection_mode': 'models', 'exe_result': {'集成结果': {'result': labels.get(label, label)}}}

    def test_upload_results_and_duplicates_survive_report_cleanup_and_restart(self):
        for task_id, label in [('a', '恶意'), ('b', '安全'), ('c', '没有有效判定')]:
            self.store.create(task_id, 'test', Path(self.folder.name) / task_id, 8, 'a' * 64)
            self.store.complete(task_id, self.result(label))
            self.store.complete(task_id, self.result(label))
        self.store.record_direct_result('d', {'sha256': 'b' * 64, 'detection_mode': 'sample_database', 'database_hit': True})
        self.store.record_direct_result('d', {'detection_mode': 'sample_database', 'database_hit': True})
        with self.store._connect() as connection:
            connection.execute("UPDATE detection_tasks SET updated_at='2000-01-01T00:00:00'")
        self.store.cleanup()
        stats = DetectionTaskStore(self.path, 60).detection_summary()
        self.assertEqual(stats['received_total'], 4)
        self.assertEqual(stats['completed_total'], 4)
        self.assertEqual(stats['malicious_total'], 2)
        self.assertEqual(stats['benign_total'], 1)
        self.assertEqual(stats['inconclusive_total'], 1)
        self.assertEqual(stats['unique_completed_samples'], 2)
        self.assertEqual(stats['database_total'], 1)
        self.assertEqual(stats['model_total'], 3)
        self.assertEqual(sum(row['count'] for row in stats['monthly']), 4)

    def test_failure_cancel_and_unsupported_never_count_as_benign(self):
        self.store.record_direct_result('bad', {'detection_mode': 'rejected'})
        self.store.create('fail', 'x', self.path, 8)
        self.store.set_status('fail', 'failed')
        self.store.create('cancel', 'x', self.path, 8)
        self.store.leave('cancel')
        self.store.cancel_abandoned(leave_seconds=-1)
        self.store.create('pending', 'x', self.path, 8)
        stats = self.store.detection_summary()
        self.assertEqual(stats['received_total'], 4)
        for key in ('failed_total', 'cancelled_total', 'unsupported_total', 'pending_total'):
            self.assertEqual(stats[key], 1)
        self.assertEqual(stats['completed_total'], 0)
        self.assertEqual(stats['benign_total'], 0)

    def test_rejected_queue_does_not_increment_and_polling_does_not_increment(self):
        self.store.create('one', 'x', self.path, 1)
        with self.assertRaises(QueueFull):
            self.store.create('two', 'x', self.path, 1)
        for _ in range(3):
            self.store.get('one')
            self.store.heartbeat('one')
            self.store.detection_summary()
        self.assertEqual(self.store.detection_summary()['received_total'], 1)

    def test_queries_are_separate_from_uploaded_detections(self):
        with patch.object(main, 'task_store', self.store):
            with patch.object(main.sample_repository, 'find_malicious', return_value={'sha256': 'a' * 64}):
                asyncio.run(main.sample_by_sha256('a' * 64))
            with patch.object(main.sample_repository, 'find_malicious', return_value=None):
                with self.assertRaises(main.HTTPException):
                    asyncio.run(main.sample_by_sha256('b' * 64))
            with patch.object(main.sample_repository, 'find_malicious', side_effect=RuntimeError('offline')):
                with self.assertRaises(main.HTTPException):
                    asyncio.run(main.sample_by_sha256('c' * 64))
        stats = self.store.detection_summary()
        self.assertEqual(stats['received_total'], 0)
        self.assertEqual(stats['query_total'], 3)
        for key in ('query_hit_total', 'query_miss_total', 'query_failed_total'):
            self.assertEqual(stats[key], 1)

    def test_partial_model_outcome_remains_a_model_verdict(self):
        result = self.result('安全')
        result['exe_result']['slow'] = {'result': '超时', 'status': 'timeout'}
        self.store.record_direct_result('partial', result)
        stats = self.store.detection_summary()
        self.assertEqual(stats['partial_model_total'], 1)
        self.assertEqual(stats['benign_total'], 1)
        self.assertEqual(stats['inconclusive_total'], 0)

    def test_api_exposes_aggregate_only(self):
        self.store.record_direct_result('private-id', self.result('恶意'))
        with patch.object(main, 'task_store', self.store):
            stats = asyncio.run(main.detection_stats())
        self.assertEqual(stats['received_total'], 1)
        self.assertNotIn('private-id', str(stats))
        self.assertNotIn('a' * 64, str(stats))


if __name__ == '__main__':
    unittest.main()
