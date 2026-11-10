"""Run the UNMODIFIED main Web tests in a disposable mirror, never in web/."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True


def main():
    with tempfile.TemporaryDirectory(prefix="codefender-web-tests-") as directory:
        mirror = Path(directory)
        shutil.copytree(ROOT / "web", mirror / "web", ignore=shutil.ignore_patterns("__pycache__", "node_modules", "uploads", "*.db", "*.sqlite"))
        shutil.copytree(ROOT / "CoDefenderC3", mirror / "CoDefenderC3", ignore=shutil.ignore_patterns("__pycache__", ".cache", ".venv", "venv", ".feature_cache", "*.pt", "*.pkl", "test-records", "*.log"))
        # Two original Web tests read historical source via git show. A pointer
        # supplies read-only access to history, without copying/modifying .git.
        git_dir = subprocess.check_output(
            ["git", "rev-parse", "--absolute-git-dir"], cwd=ROOT, text=True, encoding="utf-8",
        ).strip()
        (mirror / ".git").write_text("gitdir: " + git_dir + "\n", encoding="utf-8")
        old_cwd = Path.cwd()
        sys.path.insert(0, str(mirror / "CoDefenderC3"))
        sys.path.insert(0, str(mirror / "web/FastAPI"))
        try:
            os.chdir(mirror / "web/FastAPI")
            # The sandbox may own the disposable mirror while the user owns
            # the linked git-dir. Trust only this exact temporary path, only
            # in child processes; never change global/repository Git config.
            count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
            git_env = {"GIT_CONFIG_COUNT": str(count + 1),
                       f"GIT_CONFIG_KEY_{count}": "safe.directory",
                       f"GIT_CONFIG_VALUE_{count}": mirror.as_posix()}
            with patch.dict(os.environ, git_env):
                suite = unittest.defaultTestLoader.discover(str(mirror / "web/FastAPI/tests"))
                result = unittest.TextTestRunner(verbosity=2).run(suite)
            return 0 if result.wasSuccessful() else 1
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    raise SystemExit(main())
