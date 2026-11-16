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


class MainlineFreezeTests(unittest.TestCase):
    """Main-owned paths follow the mainline tip; the frozen blob is historical."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "frozen").mkdir()
        self.root_patch = patch.object(freeze, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def run_with(self, git):
        patcher = patch.object(freeze, "git", side_effect=git)
        patcher.start()
        self.addCleanup(patcher.stop)
        return freeze.check_mainline("origin/main", "frozen")

    def test_matching_tip_passes(self):
        def git(*args):
            if args[0] == "rev-parse":
                return "same"
            if args[0] in {"diff", "ls-files"}:
                return ""
            raise AssertionError(args)
        self.assertEqual(self.run_with(git), "same")

    def test_diverged_head_fails(self):
        def git(*args):
            if args[0] == "rev-parse":
                return "tip" if args[1].startswith("origin/main:") else "head"
            raise AssertionError(args)
        with self.assertRaises(AssertionError):
            self.run_with(git)

    def test_unavailable_ref_falls_back(self):
        def git(*args):
            raise freeze.subprocess.CalledProcessError(128, args)
        self.assertIsNone(self.run_with(git))


if __name__ == "__main__":
    unittest.main()
