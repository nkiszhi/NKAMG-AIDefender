"""Read-only merge gates. Never restore/reset/delete a protected path."""
import argparse
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


def check_working_files(base, protected_path):
    """Validate deployed files without requiring the destination Git HEAD to move."""
    entries = git("ls-tree", "-r", "--full-tree", base, "--", protected_path).splitlines()
    expected = {}
    for entry in entries:
        metadata, relative = entry.split("\t", 1)
        mode, kind, object_id = metadata.split()
        assert kind == "blob" and mode in {"100644", "100755"}, relative
        expected[relative] = object_id
    assert expected, "empty frozen source: " + protected_path
    target = ROOT / protected_path
    assert not target.is_symlink(), target
    actual = {target.relative_to(ROOT).as_posix()} if target.is_file() else {
        path.relative_to(ROOT).as_posix() for path in target.rglob("*") if path.is_file() or path.is_symlink()
    }
    assert actual == set(expected), (protected_path, "missing", set(expected) - actual, "extra", actual - set(expected))
    for relative, object_id in expected.items():
        path = ROOT / relative
        assert not path.is_symlink(), relative
        assert git("hash-object", "--path=" + relative, str(path)) == object_id, "changed frozen file: " + relative


def check(working_tree_only=False):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    base = manifest["main_base"]
    commits = []
    if not working_tree_only:
        git("merge-base", "--is-ancestor", base, "HEAD")
        commits = git("rev-list", base + "..HEAD").splitlines()
    for path, expected in manifest["protected_objects"].items():
        assert git("rev-parse", base + ":" + path) == expected, path
        if working_tree_only:
            check_working_files(base, path)
        else:
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--working-tree-only", action="store_true", help="Verify deployed files against frozen main blobs; do not require Git HEAD/index alignment.")
    check(working_tree_only=parser.parse_args().working_tree_only)
