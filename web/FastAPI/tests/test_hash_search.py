import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import main
from app.detection_queue import DetectionTaskStore
from app.sample_repository import SampleRepository, identify_hash

SHA = 'a' * 64
TLSH = 'T1' + 'b' * 70
SSDEEP = '3:AbC/+:DeF'


class HashSearchTests(unittest.TestCase):
    def test_identifies_hash_types_and_rejects_invalid_values(self):
        for value, kind in [(SHA, 'sha256'), (TLSH, 'tlsh'), ('c' * 70, 'tlsh'), (SSDEEP, 'ssdeep')]:
            self.assertEqual(identify_hash(value), kind)
        for value in ['', 'TNULL', 'a' * 63, '5:abc:def', '3::', "3:a:' OR 1=1", '3:' + 'a' * 65 + ':b']:
            with self.assertRaises(ValueError):
                identify_hash(value)

    def test_repository_uses_existing_shards_and_keeps_ssdeep_case(self):
        repo = SampleRepository(SimpleNamespace(mysql_host='test', mysql_user='test', malicious_dbs=['malicious_pe']))
        with patch.object(repo, 'find_malicious', return_value={'sha256': SHA}) as sha:
            self.assertEqual(repo.find_by_hash(SHA)['sha256'], SHA)
            sha.assert_called_once_with(SHA)
        for value, kind in [(TLSH, 'tlsh'), (SSDEEP, 'ssdeep')]:
            with patch.object(repo, '_query_fingerprint', return_value={'sha256': SHA}) as lookup:
                self.assertIsNotNone(repo.find_by_hash(value))
                lookup.assert_called_once_with('malicious_pe', kind, value)

    def test_query_verdicts_and_counters_without_model_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            store = DetectionTaskStore(Path(folder) / 'stats.sqlite3', 60)
            with patch.object(main, 'task_store', store), patch.object(main, 'scan_file') as scan:
                for value, label in [(SHA, 'Malicious'), (TLSH, 'Suspicious'), (SSDEEP, 'Suspicious')]:
                    with patch.object(main.sample_repository, 'find_by_hash', return_value={'sha256': SHA}) as lookup:
                        result = asyncio.run(main.search_sample_hash(value))
                    self.assertEqual(result['verdict'], label)
                    self.assertTrue(result['database_hit'])
                    self.assertTrue(result['model_skipped'])
                    expected = value.upper() if label == 'Suspicious' and value == TLSH else value
                    lookup.assert_called_once_with(expected)
                with patch.object(main.sample_repository, 'find_by_hash', return_value=None):
                    self.assertEqual(asyncio.run(main.search_sample_hash(SHA))['verdict'], 'Benign')
                with patch.object(main.sample_repository, 'find_by_hash', side_effect=RuntimeError('offline')):
                    with self.assertRaises(main.HTTPException) as caught:
                        asyncio.run(main.search_sample_hash(SSDEEP))
                    self.assertEqual(caught.exception.status_code, 503)
                with self.assertRaises(main.HTTPException) as caught:
                    asyncio.run(main.search_sample_hash('invalid'))
                self.assertEqual(caught.exception.status_code, 422)
                scan.assert_not_called()
            stats = store.detection_summary()
            self.assertEqual(stats['query_total'], 5)
            self.assertEqual(stats['query_hit_total'], 3)
            self.assertEqual(stats['query_miss_total'], 1)
            self.assertEqual(stats['query_failed_total'], 1)
            self.assertEqual(stats['received_total'], 5)
            self.assertEqual(stats['upload_total'], 0)
            self.assertEqual(stats['malicious_total'], 1)
            self.assertEqual(stats['suspicious_total'], 2)
            self.assertEqual(stats['not_detected_total'], 1)
            self.assertEqual(stats['classified_total'], 4)
            self.assertEqual(stats['database_total'], 3)
            self.assertEqual(stats['unique_completed_samples'], 1)

    def test_fingerprint_sql_binds_values_and_checks_all_valid_shards(self):
        import sys
        settings = SimpleNamespace(mysql_host='test', mysql_port=3306, mysql_user='test',
                                   mysql_passwd='', malicious_dbs=['malicious_pe'])
        repo = SampleRepository(settings)
        mysql = MagicMock()
        connection = mysql.connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [{'table_name': 'sample_00'}, {'table_name': 'other'},
                                        {'table_name': 'sample_ff'}]
        cursor.fetchone.side_effect = [None, {'sha256': SHA}]
        with patch.dict(sys.modules, {'pymysql': mysql}):
            record = repo._query_fingerprint('malicious_pe', 'ssdeep', SSDEEP)
        self.assertEqual(record['_source_table'], 'sample_ff')
        queries = cursor.execute.call_args_list
        self.assertEqual(len(queries), 3)
        self.assertIn('BINARY `ssdeep` = BINARY %s', queries[1].args[0])
        self.assertEqual(queries[1].args[1], (SSDEEP,))
        self.assertNotIn(SSDEEP, queries[1].args[0])
        connection.close.assert_called_once()
