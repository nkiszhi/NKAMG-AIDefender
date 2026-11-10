"""Opt-in training path: separate namespace and content-specific failure log.

The default main BN/SMDA worker orchestration is intentionally unchanged.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from feature_extraction.ir_cache import FEATURE_SCHEMA, digest, identity, read_arrays


def extract_candidates(loader, paths):
    timeout = max(1, int(os.environ.get("CODEFENDER_DE_PER_FILE_TIMEOUT", "180")))
    hard_failures = loader._load_log("de_fail")
    for path in paths:
        expected = identity(path, loader._ir_namespace, feature_schema=FEATURE_SCHEMA)
        token = digest(expected) + "\t" + path
        destination = loader._sample_cache_path(path)
        try:
            read_arrays(destination, expected)
            continue
        except Exception:
            pass  # Missing/corrupt/unversioned entries cannot be treated as hits.
        if token in hard_failures:
            continue
        command = [sys.executable, "-m", "feature_extraction._ir_worker", path,
                   "--cache-root", str(Path(loader.cache_dir) / "shared"),
                   "--training-output", destination]
        with subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace",
                              start_new_session=os.name == "posix",
                              creationflags=0x08000000 if os.name == "nt" else 0) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.communicate()
                loader._append_log("de_retry", [token])
                continue
        try:
            response = json.loads(stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            response = {"status": "retry", "error": "worker exited without a valid response"}
        if process.returncode == 0 and response.get("status") == "ok":
            read_arrays(destination, expected)
            # Persist success immediately, not at the end of the whole batch.
            loader._append_log("de_done", [token])
        elif response.get("status") in {"timeout", "retry"}:
            loader._append_log("de_retry", [token])
        else:
            loader._append_log("de_fail", [token])
            loader._append_log("de_fail_reason", [token + "\t" + response.get("error", "unknown")])
