"""Reproducible local/CI regression; writes evidence outside frozen subtrees."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", default="docs/test-records/main_test_lm_merge_2026-11-10.json")
    parser.add_argument("--working-tree-only", action="store_true", help="Use file-content freeze checks for a copied deployment whose Git HEAD is unchanged.")
    args = parser.parse_args()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
               CODEFENDER_NON_MALGRAPH_IR="0", CODEFENDER_HASH_DB_ENABLED="0",
               CODEFENDER_FUZZY_DB_ENABLED="0", CODEFENDER_REQUIRE_HASH_DB="0",
               CODEFENDER_RUNTIME_CFG_DISABLE="1", CODEFENDER_DISASM_BACKEND="smda",
               CODEFENDER_MODEL_DEVICE="cpu")
    commands = [
        ("ir_contract", ["tests/test_ir_contract.py"]),
        ("stable_hash_and_main_c01", ["tests/test_stable_hash.py"]),
        ("merge_unit_and_http_contracts", ["-m", "unittest", "discover", "-s", "tests", "-p", "test_merge_*.py", "-v"]),
        ("unmodified_main_web_tests_in_mirror", ["tools/run_web_regression.py"]),
        ("shared_listener_real_http_synthetic_models", ["tools/run_shared_listener_smoke.py"]),
        ("freeze_and_main_function_provenance", ["tools/verify_merge_freeze.py", *(["--working-tree-only"] if args.working_tree_only else [])]),
    ]
    versions = {}
    for name in ["numpy", "torch", "fastapi", "starlette", "httpx", "uvicorn", "smda"]:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "not installed as a distribution"
    report = {"freeze_scope": "working_files" if args.working_tree_only else "commits_index_and_working_files", "timestamp": datetime.now(timezone.utc).isoformat(), "python": sys.version,
              "versions": versions, "sources": json.loads((ROOT / "docs/merge_main_test_lm_sources.json").read_text(encoding="utf-8")),
              "scope": "synthetic models/IR and original Web tests; not real-weights/BN/SMDA/CUDA/Docker certification",
              "stages": []}
    for name, command in commands:
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", *command], cwd=ROOT,
                                env=env, capture_output=True, text=True, encoding="utf-8", timeout=300)
        output = result.stdout + result.stderr
        unit = re.search(r"Ran (\d+) tests? in", output)
        script = re.search(r"(\d+)/(\d+) passed", output)
        count = int(unit.group(1)) if unit else int(script.group(2)) if script else None
        stage = {"name": name, "returncode": result.returncode, "test_count": count,
                 "stdout": result.stdout, "stderr": result.stderr}
        report["stages"].append(stage)
        print(("PASS" if result.returncode == 0 else "FAIL"), name, "tests=" + str(count), flush=True)
    report["passed"] = all(stage["returncode"] == 0 for stage in report["stages"])
    report["total_counted_tests"] = sum(stage["test_count"] or 0 for stage in report["stages"])
    path = ROOT / args.report
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Evidence:", path)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
