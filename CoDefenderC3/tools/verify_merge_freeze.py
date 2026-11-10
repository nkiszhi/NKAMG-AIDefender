"""Read-only merge gates. Never restore/reset/delete a protected path."""
import ast
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "CoDefenderC3/docs/merge_main_test_lm_sources.json"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode("utf-8").strip()


def functions(text):
    return {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(text.lstrip("\ufeff")).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def check():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    base = manifest["main_base"]
    git("merge-base", "--is-ancestor", base, "HEAD")
    commits = git("rev-list", base + "..HEAD").splitlines()
    for path, expected in manifest["protected_objects"].items():
        assert git("rev-parse", base + ":" + path) == expected, path
        for revision in ["HEAD", *commits]:
            assert git("rev-parse", revision + ":" + path) == expected, (revision, path)
        git("diff", "--no-ext-diff", "--exit-code", base, "--", path)
        git("diff", "--no-ext-diff", "--cached", "--exit-code", base, "--", path)
        assert not git("ls-files", "--others", "--", path), "extra files in " + path
        print("PASS frozen:", path, expected)
    main_functions = functions(git("show", base + ":CoDefenderC3/engine/app.py"))
    current_functions = functions((ROOT / "CoDefenderC3/engine/app.py").read_text(encoding="utf-8-sig"))
    for name in manifest["protected_app_functions"]:
        assert current_functions[name] == main_functions[name], "changed protected main helper: " + name
    print("PASS protected main helpers:", len(manifest["protected_app_functions"]))
    assert (ROOT / "CoDefenderC3/engine/web_result_formatter.py").read_text(encoding="utf-8-sig").strip() == git("show", base + ":CoDefenderC3/engine/result_formatter.py").strip()
    print("PASS original main Web formatter")
    return manifest


if __name__ == "__main__":
    check()
