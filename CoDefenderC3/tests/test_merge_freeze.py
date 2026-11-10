"""Copied deployments must validate real protected files, not just Git metadata."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import verify_merge_freeze as freeze


class WorkingFileFreezeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "frozen").mkdir()
        (self.root / "frozen/a.py").write_bytes(b"original")
        self.digest = hashlib.sha1(b"original").hexdigest()
        self.root_patch = patch.object(freeze, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        def git(*args):
            if args[0] == "ls-tree":
                return "100644 blob " + self.digest + "\tfrozen/a.py"
            if args[0] == "hash-object":
                return hashlib.sha1(Path(args[-1]).read_bytes()).hexdigest()
            raise AssertionError(args)
        self.git_patch = patch.object(freeze, "git", side_effect=git)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)

    def test_exact_files_pass(self):
        freeze.check_working_files("base", "frozen")

    def test_changed_content_fails(self):
        (self.root / "frozen/a.py").write_bytes(b"changed")
        with self.assertRaises(AssertionError):
            freeze.check_working_files("base", "frozen")

    def test_untracked_extra_file_fails(self):
        (self.root / "frozen/old.py").write_bytes(b"legacy")
        with self.assertRaises(AssertionError):
            freeze.check_working_files("base", "frozen")

    def test_missing_file_fails(self):
        (self.root / "frozen/a.py").unlink()
        with self.assertRaises(AssertionError):
            freeze.check_working_files("base", "frozen")


if __name__ == "__main__":
    unittest.main()
