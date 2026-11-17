import asyncio
import configparser
import json
import math
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main
from app.codefender_client import DEFAULT_MODEL_NAMES
from app.config import Settings
from app.detection_queue import DetectionTaskStore
from app.sample_repository import SampleRepository
from app.stored_results import saved_model_payload

SHA = 'a' * 64


def record(**values):
    return {'_source_db': 'AIDefender_PE', 'sha256': SHA, 'detection_status': 'pending', **values}


def payload(**values):
    return saved_model_payload(record(**values), DEFAULT_MODEL_NAMES)


class SavedModelResults(unittest.TestCase):
    def test_default_remains_legacy_and_only_approved_new_database_allowed(self):
        cfg = configparser.ConfigParser()
        with patch('app.config._load_config', return_value=cfg):
            self.assertEqual(Settings().pe_lookup_db, 'malicious_pe')
        cfg.read_dict({'mysql': {'pe_lookup_db': 'AIDefender_PE'}})
        with patch('app.config._load_config', return_value=cfg):
            self.assertEqual(Settings().pe_lookup_db, 'AIDefender_PE')
        cfg['mysql']['pe_lookup_db'] = 'malicious_elf'
        with patch('app.config._load_config', return_value=cfg), self.assertRaises(ValueError):
            Settings()

    def test_new_database_is_explicit_and_never_falls_back_to_old_kav_records(self):
        repo = SampleRepository(SimpleNamespace(mysql_host='fixture', mysql_user='fixture', pe_lookup_db='AIDefender_PE', malicious_dbs=[]))
        with patch.object(repo, '_query', return_value=None) as query:
            self.assertIsNone(repo.find_malicious(SHA))
        query.assert_called_once_with('AIDefender_PE', 'sample_aa', SHA)

    def test_new_database_has_no_fingerprint_columns(self):
        repo = SampleRepository(SimpleNamespace(pe_lookup_db='AIDefender_PE'))
        with patch.object(repo, '_query_fingerprint') as query, self.assertRaises(ValueError):
            repo.find_by_hash('3:abc:def')
        query.assert_not_called()

    def test_null_model_results_are_not_failed_or_completed_predictions(self):
        p = payload()
        self.assertEqual(p['results'], {})
        self.assertFalse(p['stored_model_report']['available'])
        self.assertEqual(p['stored_model_report']['missing_model_count'], 33)
        self.assertEqual(p['stored_model_report']['unavailable_model_count'], 0)
        self.assertEqual(p['stored_model_report']['collection_status'], 'pending')

    def test_partial_saved_json_preserves_explicit_zero_score(self):
        p = payload(MalConv=json.dumps({'result': 'Benign', 'probability': 0}))
        self.assertEqual(p['results']['MalConv']['probability'], 0)
        self.assertEqual(p['results']['MalConv']['result'], 'Benign')
        self.assertEqual(p['stored_model_report']['model_count'], 1)
        self.assertEqual(p['stored_model_report']['missing_model_count'], 32)

    def test_score_alone_does_not_invent_verdict(self):
        p = payload(MalConv={'probability': .99})
        self.assertEqual(p['stored_model_report']['valid_model_count'], 0)
        self.assertEqual(p['results']['MalConv']['result'], '未取得有效结果')

    def test_explicit_failure_is_retained_without_a_score(self):
        p = payload(MalConv={'status': 'failed', 'reason': 'feature unavailable'})
        self.assertEqual(p['results']['MalConv']['result'], '检测失败')
        self.assertIsNone(p['results']['MalConv']['probability'])
        self.assertEqual(p['stored_model_report']['unavailable_model_count'], 1)

    def test_corrupt_or_nested_json_is_not_a_server_failure(self):
        for value in ('bad JSON', '[1,2]', '9', {'result': []}, {'display_result': {}}, 'x' * 32769):
            with self.subTest(value_type=type(value).__name__):
                p = payload(MalConv=value)
                self.assertEqual(p['stored_model_report']['valid_model_count'], 0)
        self.assertEqual(payload(detection_status=[])['stored_model_report']['collection_status'], 'unknown')

    def test_nonfinite_and_out_of_range_scores_are_not_clamped_to_fake_confidence(self):
        for score in (math.nan, math.inf, -.1, 90, True, {}, 'NaN'):
            self.assertIsNone(payload(MalConv={'result': 'Malicious', 'probability': score})['results']['MalConv']['probability'])

    def test_saved_cofender_levels_preserved(self):
        p = payload(codefender_result={'result': 'Malicious', 'display_result': 'Generic.ML.High', 'probability': .8, 'ok_models': 30, 'total_models': 33})
        self.assertEqual(p['results']['集成结果']['display_result'], 'Generic.ML.High')
        self.assertTrue(p['stored_model_report']['codefender_available'])
        self.assertEqual(p['stored_model_report']['model_count'], 0)

    def test_conflicting_saved_ensemble_is_not_relabelled(self):
        p = payload(codefender_result={'result': 'Benign', 'display_result': 'Generic.ML.High'})
        self.assertFalse(p['stored_model_report']['codefender_available'])

    def test_old_database_and_unknown_columns_do_not_create_stored_models(self):
        self.assertEqual(saved_model_payload({'_source_db': 'malicious_pe', 'MalConv': {'result': 'Malicious'}}, DEFAULT_MODEL_NAMES), {})
        self.assertEqual(payload(unknown_model={'result': 'Malicious'})['results'], {})

    def test_all_lookup_entrypoints_return_available_saved_results_without_model_call(self):
        r = record(MalConv={'result': 'Malicious', 'probability': .9}, codefender_result={'result': 'Benign', 'probability': .1})
        with tempfile.TemporaryDirectory() as folder:
            store = DetectionTaskStore(Path(folder) / 'tasks.sqlite3', 60)
            with patch.object(main, 'task_store', store), patch.object(main, 'scan_file') as scan, \
                 patch.object(main.sample_repository, 'find_malicious', return_value=r), \
                 patch.object(main.sample_repository, 'find_by_hash', return_value=r):
                direct = asyncio.run(main.sample_by_sha256(SHA))
                search = asyncio.run(main.search_sample_hash(SHA))
                info = {'filename': 'fixture.exe', 'file_size': 1, 'file_type': 'exe64', 'is_pe': True, 'pe_info': {}, 'query_result': {}, 'sha256': SHA, 'md5': ''}
                uploaded, error = asyncio.run(main._lookup_uploaded_sample(info))
                preflight = asyncio.run(main.upload_preflight(main.UploadPreflight(sha256=SHA, filename='fixture.exe', file_size=1), '1' * 32))['result']
                for result in (direct, search, uploaded, preflight):
                    self.assertEqual(result['verdict'], 'Malicious')
                    self.assertEqual(result['exe_result']['MalConv']['probability'], .9)
                    self.assertEqual(result['exe_result']['集成结果']['result'], 'Benign')
                    self.assertTrue(result['stored_model_report']['available'])
                self.assertIsNone(error)
                scan.assert_not_called()
            self.assertEqual(store.detection_summary()['in_progress_total'], 0)

    def test_new_library_rejects_fingerprint_before_counting_query(self):
        repo = SampleRepository(SimpleNamespace(pe_lookup_db='AIDefender_PE'))
        with patch.object(main, 'sample_repository', repo), patch.object(main, 'task_store') as store:
            with self.assertRaises(main.HTTPException) as error:
                asyncio.run(main.search_sample_hash('3:abc:def'))
        self.assertEqual(error.exception.status_code, 422)
        store.begin_hash_query.assert_not_called()


if __name__ == '__main__': unittest.main()
