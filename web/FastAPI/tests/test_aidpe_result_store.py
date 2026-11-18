import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.aidpe_result_store import PrimaryResultWriter, ResultOutbox, archive_detected_sample
from app.codefender_client import DEFAULT_MODEL_NAMES
from main import _replicated_result_matches


SHA = "a" * 64


class ResultOutboxTests(unittest.TestCase):
    def test_enqueues_idempotently_and_keeps_results_until_replica_ack(self):
        with tempfile.TemporaryDirectory() as folder:
            outbox = ResultOutbox(Path(folder) / "outbox.sqlite3")
            result = {"sha256": SHA, "is_pe": True, "detection_status": "completed",
                      "exe_result": {DEFAULT_MODEL_NAMES[0]: {"result": "Malicious"},
                                     "集成结果": {"result": "Malicious"}}}
            self.assertTrue(outbox.enqueue(result, "revision-test"))
            self.assertTrue(outbox.enqueue(result, "revision-test"))
            self.assertEqual(outbox.due_count(), 1)
            item = outbox.claim_due()
            self.assertEqual(item["sha256"], SHA)
            self.assertEqual(item["payload"]["source"], "web_upload")
            self.assertEqual(item["payload"]["model_version"], "revision-test")
            self.assertEqual(item["payload"]["models"][DEFAULT_MODEL_NAMES[0]]["result"], "Malicious")
            outbox.mark_retry(SHA, item["attempts"], "temporary")
            self.assertEqual(outbox.due_count(), 1)
            with patch("app.aidpe_result_store.time.time", return_value=10**12):
                retry = outbox.claim_due()
            self.assertIsNotNone(retry)
            outbox.mark_replicated(SHA)
            self.assertEqual(outbox.due_count(), 0)

    def test_rejects_non_pe_and_invalid_sha(self):
        with tempfile.TemporaryDirectory() as folder:
            outbox = ResultOutbox(Path(folder) / "outbox.sqlite3")
            self.assertFalse(outbox.enqueue({"sha256": SHA, "is_pe": False}, "rev"))
            self.assertFalse(outbox.enqueue({"sha256": "invalid", "is_pe": True}, "rev"))
            self.assertEqual(outbox.due_count(), 0)


class PrimaryWriterTests(unittest.TestCase):
    def test_upserts_to_sha_shard_without_downgrading_malicious_source(self):
        import sys
        fake_mysql = SimpleNamespace()
        fake_mysql.cursors = SimpleNamespace(DictCursor=object())
        fake_mysql.connect = unittest.mock.MagicMock()
        connection = fake_mysql.connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        writer = PrimaryResultWriter(SimpleNamespace(
            aidpe_primary_host="127.0.0.1", aidpe_primary_port=13306,
            aidpe_primary_user="writer", aidpe_primary_passwd="secret", aidpe_db="AIDefender_PE"))
        payload = {"sha256": SHA, "source": "web_upload", "model_version": "r1",
                   "uploaded_at": "2026-11-18 10:00:00", "detection_status": "completed",
                   "models": {DEFAULT_MODEL_NAMES[0]: {"result": "Benign"}},
                   "codefender_result": {"result": "Benign"}}
        with patch.dict(sys.modules, {"pymysql": fake_mysql}):
            writer.write(payload)
        sql, values = cursor.execute.call_args.args
        self.assertIn("`AIDefender_PE`.`sample_aa`", sql)
        self.assertIn("IF(`source`='malicious_pe','malicious_pe',VALUES(`source`))", sql)
        self.assertEqual(values[0], SHA)
        self.assertEqual(json.loads(values[1]), {"result": "Benign"})
        self.assertEqual(tuple(values[-3:]), ("web_upload", "r1", "2026-11-18 10:00:00"))
        connection.close.assert_called_once()

    def test_replica_ack_requires_matching_status_version_and_result_values(self):
        model_name = DEFAULT_MODEL_NAMES[0]
        payload = {"sha256": SHA, "source": "web_upload", "model_version": "r2",
                   "detection_status": "failed", "models": {model_name: {"result": "timeout"}},
                   "codefender_result": None}
        record = {"sha256": SHA, "source": "malicious_pe", "model_version": "r2",
                  "detection_status": "failed", model_name: json.dumps({"result": "timeout"}),
                  "codefender_result": None}
        self.assertTrue(_replicated_result_matches(record, payload))
        self.assertFalse(_replicated_result_matches({**record, "model_version": "r1"}, payload))
        self.assertFalse(_replicated_result_matches({**record, model_name: None}, payload))


class SampleArchiveTests(unittest.TestCase):
    def test_verifies_hash_and_routes_final_categories(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "upload"
            source.write_bytes(b"sample")
            import hashlib
            sha = hashlib.sha256(b"sample").hexdigest()
            result = {"exe_result": {"集成结果": {"result": "Benign"}}}
            archived = archive_detected_sample(source, root / "archive", sha, result)
            self.assertEqual(archived.parent.name, "模型判断非恶意")
            self.assertEqual(archived.read_bytes(), b"sample")
            self.assertFalse(source.exists())
            wrong = root / "wrong"
            wrong.write_bytes(b"different")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                archive_detected_sample(wrong, root / "archive", sha, result)
            self.assertTrue(wrong.exists())

    def test_unknown_or_partial_result_goes_to_failure_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "upload"
            source.write_bytes(b"sample")
            import hashlib
            sha = hashlib.sha256(b"sample").hexdigest()
            archived = archive_detected_sample(source, root / "archive", sha, None)
            self.assertEqual(archived.parent.name, "检查失败")

