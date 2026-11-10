"""Candidate training orchestration; workers are mocked, not backend validation."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from train.data_loader import PELoader
from train.ir_candidate import extract_candidates
from feature_extraction.ir_cache import FEATURE_SCHEMA, digest, identity


class TrainingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "sample"
        self.path.write_bytes(b"content")
        self.meta = {"backend": "synthetic", "backend_version": "1", "profile": "features"}
        self.loader = SimpleNamespace(_ir_namespace=self.meta, cache_dir=self.temp.name,
                                      _load_log=lambda _: set(), _sample_cache_path=lambda _: str(self.path) + ".npz",
                                      _append_log=MagicMock())

    def tearDown(self):
        self.temp.cleanup()

    def process(self, status="ok"):
        proc = MagicMock()
        proc.__enter__.return_value = proc
        proc.returncode = 0 if status == "ok" else 1
        proc.communicate.return_value = (json.dumps({"status": status, "error": "test failure"}), "")
        return proc

    def test_default_loader_keeps_main_namespace(self):
        with patch.dict(os.environ, {"CODEFENDER_NON_MALGRAPH_IR": "0"}):
            loader = PELoader(self.temp.name)
            self.assertFalse(loader._ir_candidate)
            self.assertEqual(loader.cache_dir, str(Path(self.temp.name) / ".cache"))

    def test_candidate_cache_path_tracks_content_and_namespace(self):
        with patch.dict(os.environ, {"CODEFENDER_NON_MALGRAPH_IR": "1"}), patch("feature_extraction.ir_cache.namespace", return_value=self.meta):
            loader = PELoader(self.temp.name)
            first = loader._sample_cache_path(str(self.path))
            self.path.write_bytes(b"different-content")
            second = loader._sample_cache_path(str(self.path))
            self.assertNotEqual(first, second)
            self.assertIn("non-malgraph-ir-v1", second)
            self.assertFalse(loader._has_month_cache(1))

    def test_success_persists_immediately_with_content_token(self):
        proc = self.process()
        with patch("train.ir_candidate.read_arrays", side_effect=[FileNotFoundError(), {}]), patch("train.ir_candidate.subprocess.Popen", return_value=proc):
            extract_candidates(self.loader, [str(self.path)])
        expected = digest(identity(self.path, self.meta, feature_schema=FEATURE_SCHEMA)) + "\t" + str(self.path)
        self.loader._append_log.assert_called_once_with("de_done", [expected])

    def test_reported_timeout_is_retryable_not_permanent_failure(self):
        with patch("train.ir_candidate.read_arrays", side_effect=FileNotFoundError()), patch("train.ir_candidate.subprocess.Popen", return_value=self.process("timeout")):
            extract_candidates(self.loader, [str(self.path)])
        self.assertEqual(self.loader._append_log.call_args.args[0], "de_retry")

    def test_hard_parse_failure_is_separate_from_timeouts(self):
        with patch("train.ir_candidate.read_arrays", side_effect=FileNotFoundError()), patch("train.ir_candidate.subprocess.Popen", return_value=self.process("error")):
            extract_candidates(self.loader, [str(self.path)])
        self.assertEqual([call.args[0] for call in self.loader._append_log.call_args_list], ["de_fail", "de_fail_reason"])

    def test_worker_crash_remains_retryable(self):
        proc = self.process()
        proc.returncode = 70
        proc.communicate.return_value = ("", "crash")
        with patch("train.ir_candidate.read_arrays", side_effect=FileNotFoundError()), patch("train.ir_candidate.subprocess.Popen", return_value=proc):
            extract_candidates(self.loader, [str(self.path)])
        self.assertEqual(self.loader._append_log.call_args.args[0], "de_retry")


if __name__ == "__main__":
    unittest.main()
