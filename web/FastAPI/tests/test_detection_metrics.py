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

    def test_failure_cancel_and_unsupported_distribution(self):
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
        self.assertEqual(stats['not_detected_total'], 1)
        self.assertEqual(stats['other_total'], 3)
        self.assertEqual(stats['received_total'], stats['malicious_total'] + stats['not_detected_total'] + stats['other_total'])

    def test_live_epoch_resets_once_and_preserves_history(self):
        self.store.record_direct_result('old', self.result('Malicious'))
        self.store.record_hash_query('hit')
        with self.store._connect() as connection:
            connection.execute("DELETE FROM metrics_metadata WHERE key='live_stats_started_at'")
            connection.execute("UPDATE detection_metrics SET created_at='2000-01-01T00:00:00+08:00'")
            connection.execute("UPDATE hash_query_metrics SET queried_at='2000-01-01T00:00:00+08:00'")
        store = DetectionTaskStore(self.path, 60)
        empty = store.detection_summary()
        for key, value in empty.items():
            if key.endswith('_total') or key == 'unique_completed_samples':
                self.assertEqual(value, 0, key)
        with store._connect() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM detection_metrics').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM hash_query_metrics').fetchone()[0], 1)
        for task_id, result in [('bad', {'detection_mode': 'rejected'}),
                                ('safe', self.result('Benign')), ('evil', self.result('Malicious'))]:
            store.record_direct_result(task_id, result)
            store.record_direct_result(task_id, result)
        for outcome in ('hit', 'miss', 'failed'):
            store.record_hash_query(outcome)
        stats = DetectionTaskStore(self.path, 60).detection_summary()
        self.assertEqual(stats['started_at'], empty['started_at'])
        self.assertEqual(stats['received_total'], 6)
        self.assertEqual(stats['malicious_total'], 1)
        self.assertEqual(stats['not_detected_total'], 3)
        self.assertEqual(stats['other_total'], 2)
        self.assertEqual(stats['query_total'], 3)
        self.assertEqual(stats['query_total'], sum(stats[key] for key in ('query_hit_total', 'query_miss_total', 'query_failed_total')))
        self.assertEqual(stats['received_total'], stats['malicious_total'] + stats['not_detected_total'] + stats['other_total'])

    def test_rejected_queue_does_not_increment_and_polling_does_not_increment(self):
        self.store.create('one', 'x', self.path, 1)
        with self.assertRaises(QueueFull):
            self.store.create('two', 'x', self.path, 1)
        for _ in range(3):
            self.store.get('one')
            self.store.heartbeat('one')
            self.store.detection_summary()
        self.assertEqual(self.store.detection_summary()['received_total'], 1)

    def test_queries_increase_cumulative_total_without_inventing_uploads(self):
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
        self.assertEqual(stats['received_total'], 3)
        self.assertEqual(stats['upload_total'], 0)
        self.assertEqual(stats['malicious_total'], 1)
        self.assertEqual(stats['not_detected_total'], 1)
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

    def test_uploads_and_each_hash_type_share_truthful_totals(self):
        self.store.record_direct_result('evil', self.result('Malicious', 'a' * 64))
        self.store.record_direct_result('safe', self.result('Benign', 'b' * 64))
        self.store.record_direct_result('bad', {'detection_mode': 'rejected', 'sha256': 'c' * 64})
        self.store.create('pending', 'test', self.path, 10, 'd' * 64)
        self.store.create('failed', 'test', self.path, 10, 'e' * 64)
        self.store.set_status('failed', 'failed')
        for outcome, kind, value, sha in [
            ('hit', 'sha256', 'a' * 64, 'a' * 64),
            ('hit', 'tlsh', 'T1' + 'A' * 70, 'a' * 64),
            ('hit', 'ssdeep', '3:abc:def', 'a' * 64),
            ('miss', 'sha256', 'f' * 64, None),
            ('miss', 'tlsh', 'T1' + 'B' * 70, None),
            ('failed', 'ssdeep', '3:ghi:jkl', None),
        ]:
            before = self.store.detection_summary()['received_total']
            self.store.record_hash_query(outcome, kind, value, sha)
            self.assertEqual(self.store.detection_summary()['received_total'], before + 1)
        self.store.begin_hash_query('sha256', 'f' * 64)
        stats = DetectionTaskStore(self.path, 60).detection_summary()
        expected = {'received_total': 12, 'upload_total': 5, 'query_total': 7,
                    'malicious_total': 2, 'not_detected_total': 4, 'suspicious_total': 2,
                    'classified_total': 8, 'other_total': 4, 'database_total': 3,
                    'query_hit_total': 3, 'query_miss_total': 2, 'query_failed_total': 1,
                    'query_pending_total': 1, 'unique_completed_samples': 4}
        for key, value in expected.items():
            self.assertEqual(stats[key], value, key)
        self.assertEqual(stats['received_total'], stats['upload_total'] + stats['query_total'])
        self.assertEqual(stats['classified_total'], sum(stats[key] for key in ('malicious_total', 'not_detected_total', 'suspicious_total')))

    def test_query_is_recorded_before_lookup_and_finishes_only_once(self):
        def lookup(value):
            stats = self.store.detection_summary()
            self.assertEqual(stats['received_total'], 1)
            self.assertEqual(stats['query_pending_total'], 1)
            return {'sha256': 'a' * 64}
        with patch.object(main, 'task_store', self.store), \
             patch.object(main.sample_repository, 'find_by_hash', side_effect=lookup):
            result = asyncio.run(main.search_sample_hash('T1' + 'A' * 70))
        self.assertEqual(result['verdict'], 'Suspicious')
        with self.store._connect() as connection:
            rows = connection.execute('SELECT * FROM hash_query_metrics').fetchall()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['hash_type'], 'tlsh')
        self.assertEqual(row['query_hash'], 'T1' + 'A' * 70)
        self.assertEqual(row['verdict'], 'suspicious')
        self.assertEqual(row['sample_sha256'], 'a' * 64)
        self.store.finish_hash_query(row['id'], 'miss')
        stats = DetectionTaskStore(self.path, 60).detection_summary()
        self.assertEqual(stats['received_total'], 1)
        self.assertEqual(stats['suspicious_total'], 1)
        self.assertEqual(stats['query_pending_total'], 0)
        self.assertEqual(stats['not_detected_total'], 0)

    def test_legacy_query_rows_are_kept_without_fabricating_hash_type(self):
        with self.store._connect() as connection:
            connection.execute('DROP TABLE hash_query_metrics')
            connection.execute('CREATE TABLE hash_query_metrics (id INTEGER PRIMARY KEY, queried_at TEXT NOT NULL, outcome TEXT NOT NULL)')
            for outcome in ('hit', 'miss'):
                connection.execute('INSERT INTO hash_query_metrics(queried_at,outcome) VALUES (?,?)',
                                   ('2099-01-01T00:00:00+08:00', outcome))
        stats = DetectionTaskStore(self.path, 60).detection_summary()
        self.assertEqual(stats['received_total'], 2)
        self.assertEqual(stats['database_total'], 1)
        self.assertEqual(stats['malicious_total'], 0)
        self.assertEqual(stats['suspicious_total'], 0)
        self.assertEqual(stats['not_detected_total'], 1)
        self.assertEqual(stats['other_total'], 1)


if __name__ == '__main__':
    unittest.main()
