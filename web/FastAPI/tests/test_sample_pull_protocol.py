import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess


PULLER_PATH = Path(__file__).parents[2] / "deploy" / "pull_web_upload_samples.py"
SPEC = importlib.util.spec_from_file_location("pull_web_upload_samples", PULLER_PATH)
puller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = puller
SPEC.loader.exec_module(puller)


class PullerProtocolTests(unittest.TestCase):
    def test_manifest_accepts_only_category_and_sha_named_samples(self):
        sha = hashlib.sha256(b"sample").hexdigest()
        samples = puller.parse_manifest(f"模型判断非恶意/{sha}.sample\t6\n")
        self.assertEqual(samples, [puller.Sample("模型判断非恶意", sha, 6)])
        for invalid in ("other/" + sha + ".sample\t6", "检查失败/not-a-hash.sample\t6",
                        "检查失败/" + sha + ".sample\t-1", "检查失败/" + sha + ".sample/extra\t6"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                puller.parse_manifest(invalid)

    def test_source_is_removed_only_after_verified_local_file_and_receipt(self):
        content = b"sample"
        sha = hashlib.sha256(content).hexdigest()
        sample = puller.Sample("模型判断非恶意", sha, len(content))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / sample.category).mkdir()
            source = root / "source.sample"
            source.write_bytes(content)
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if Path(command[0]).name == "scp.exe" or command[0] == "scp":
                    Path(command[-1]).write_bytes(source.read_bytes())
                return CompletedProcess(command, 0, "", "")

            destination = puller.transfer_sample(sample, "host", "user", "/samples", root, root / "key", fake_run)
            self.assertEqual(destination.read_bytes(), content)
            self.assertTrue((root / "transfer_receipts.jsonl").is_file())
            self.assertEqual(len(calls), 2)
            self.assertIn("rm --", calls[-1][-1])

    def test_hash_mismatch_never_runs_remote_delete(self):
        content = b"wrong"
        sha = hashlib.sha256(b"sample").hexdigest()
        sample = puller.Sample("检查失败", sha, len(content))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / sample.category).mkdir()
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[0] == "scp":
                    Path(command[-1]).write_bytes(content)
                return CompletedProcess(command, 0, "", "")

            with self.assertRaisesRegex(RuntimeError, "SHA256"):
                puller.transfer_sample(sample, "host", "user", "/samples", root, root / "key", fake_run)
            self.assertEqual(len(calls), 1)
            self.assertFalse((root / "transfer_receipts.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
