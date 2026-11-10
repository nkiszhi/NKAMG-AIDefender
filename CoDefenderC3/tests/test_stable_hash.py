# -*- coding: utf-8 -*-
"""W0 回归测试：跨进程稳定的 feature hashing。

背景
────
CPython 的内置 hash(str) 每进程随机（PYTHONHASHSEED）。项目曾有 13 处用它
做 feature hashing，导致：
    训练（D/E 特征在子进程抽取） ≠ 推理（D/E 特征在主进程抽取）
同一个 PE 文件在两侧算出完全不同的桶号 → 模型吃噪声。

现在统一改用 feature_extraction/_stable_hash.py 的 zlib.crc32（纯函数）。
本文件是**守门测试**：防止将来有人又写回内置 hash()。

跑法（无需 pytest）：
    python tests/test_stable_hash.py
跑法（有 pytest）：
    pytest tests/test_stable_hash.py -v

注：本文件用 importlib 直接加载 .py 文件，绕开 feature_extraction/__init__.py
    （它会 import torch，没有 torch 的裸环境也能跑）。

2026-11-05
"""
import ast
import importlib.util
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _load(name, relpath):
    """按文件路径加载模块，绕开包的 __init__（避免强依赖 torch）。"""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# feature_extraction/extract_feature.py 里是 try 相对导入 / except 绝对导入，
# 这里把 "_stable_hash" 预注册进 sys.modules，两种导入方式都能命中。
_sh = _load("_stable_hash", os.path.join("feature_extraction", "_stable_hash.py"))
stable_hash = _sh.stable_hash
stable_bucket = _sh.stable_bucket
stable_seed = _sh.stable_seed

# 探针样本：覆盖 ASCII / 非 ASCII / 空串 / 超长串
PROBES = [
    "kernel32.dll",
    "CreateFileW",
    "mov",
    "push",
    "xor",
    "http://example.com/a",
    "中文样本",
    "",
    "x" * 4096,
]


CHILD_CODE = (
    "import importlib.util, os, sys\n"
    "ROOT = %r\n"
    "spec = importlib.util.spec_from_file_location('_stable_hash', os.path.join(ROOT, 'feature_extraction', '_stable_hash.py'))\n"
    "m = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(m)\n"
)


def _child_values(mode: str, items):
    """在**子进程**里算出 items 的哈希值，返回 list[int]。

    mode="stable" → 用 stable_hash；mode="builtin" → 用内置 hash（对照组）。
    """
    code = (CHILD_CODE % ROOT) + (
        "fn = m.stable_hash if %r == \"stable\" else hash\n"
        "print([fn(x) for x in %r])\n"
    ) % (mode, list(items))
    env = dict(os.environ)
    env.pop("PYTHONHASHSEED", None)      # 强制走"每进程随机"的默认行为
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=env, timeout=120)
    assert out.returncode == 0, "子进程失败: %s" % out.stderr
    return ast.literal_eval(out.stdout.strip())


def test_stable_hash_is_deterministic_in_process():
    """同进程内同一输入恒等。"""
    for p in PROBES:
        h1 = stable_hash(p)
        h2 = stable_hash(p)
        assert h1 == h2, "同进程内不稳定: %r" % p
        assert 0 <= h1 <= 0xFFFFFFFF, "hash 越界: %r" % h1


def test_stable_hash_is_identical_across_processes():
    """**核心回归**：不同进程算出的桶号必须完全一致。"""
    results = [tuple(_child_values("stable", PROBES)) for _ in range(3)]
    assert len(set(results)) == 1, "跨进程不一致:\n%s" % "\n".join(map(str, results))


def test_builtin_hash_would_have_been_broken():
    """canary：证明内置 hash() 确实是每进程随机的（本测试存在的意义）。"""
    if os.environ.get("PYTHONHASHSEED") is not None:
        return          # 显式固定了 seed，跳过（此时内置 hash 反而是稳定的）
    results = [tuple(_child_values("builtin", PROBES)) for _ in range(3)]
    assert len(set(results)) > 1, "内置 hash 竟然跨进程一致？本测试需要重新评估"


def test_stable_bucket_respects_dim():
    """桶号必须落在 [0, dim)。"""
    for p in PROBES:
        for dim in (128, 256, 511):
            b = stable_bucket(p, dim)
            assert 0 <= b < dim, "桶号越界: %r dim=%d -> %d" % (p, dim, b)
    try:
        stable_bucket("x", 0)
    except ValueError:
        pass
    else:
        raise AssertionError("dim=0 应当抛 ValueError")


def test_stable_seed_is_31bit():
    """stable_seed 供 np.random.RandomState 使用，必须是 31 位非负整数。"""
    for p in PROBES:
        s = stable_seed(p)
        assert 0 <= s <= 0x7FFFFFFF, "seed 越界: %r" % s


def test_d01_opcode_id_mapping_is_stable():
    """D01 的 opcode -> ID 映射跨进程一致（opcode 序列模型的命脉）。"""
    ops = ["mov", "push", "call", "xor", "jmp", "cmp", "lea", "ret", "add", "sub"]
    ids = [stable_hash(o) % 511 + 1 for o in ops]
    assert all(1 <= i <= 511 for i in ids)
    assert len(set(ids)) == len(ids), "opcode 映射发生碰撞: %r" % ids
    child_ids = [h % 511 + 1 for h in _child_values("stable", ops)]
    assert child_ids == ids, "D01 映射跨进程不一致: %r vs %r" % (child_ids, ids)


def test_feature_extraction_has_no_builtin_hash():
    """**静态守门**：feature_extraction/ 下不允许再出现裸用内置 hash()。"""
    fe_dir = os.path.join(ROOT, "feature_extraction")
    offenders = []
    for fn in sorted(os.listdir(fe_dir)):
        if not fn.endswith(".py"):
            continue
        path = os.path.join(fe_dir, fn)
        with open(path, "r", encoding="utf-8-sig") as f:
            tree = ast.parse(f.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "hash":
                offenders.append("%s:%d" % (fn, node.lineno))
    assert not offenders, "feature_extraction/ 又用回了内置 hash():\n%s" % "\n".join(offenders)


def test_string_features_are_deterministic():
    """Merged main fast C01 is count/max, NOT test_lm's log1p variant."""
    import numpy as np
    ef = _load("extract_feature", os.path.join("feature_extraction", "extract_feature.py"))
    ext = ef.BinjaExtractor.__new__(ef.BinjaExtractor)
    raw = b"CreateFileW\x00CreateFileW\x00CreateFileW\x00kernel32.dll\x00"
    first, second = ext._extract_strings_fast(raw), ext._extract_strings_fast(raw)
    assert set(first) == {"C01", "C02", "C03", "C04"}
    for key in first:
        assert np.array_equal(first[key], second[key]), key
    counts = np.zeros(256, dtype=np.float32)
    counts[stable_bucket("CreateFileW", 256)] += 3
    counts[stable_bucket("kernel32.dll", 256)] += 1
    counts /= counts.max() + 1e-8
    assert np.array_equal(first["C01"], counts)


def test_fast_path_features_match_across_processes():
    """**端到端**：训练子进程与推理主进程算出的 C01-C04 必须逐位一致。

    这正是 W0 要修的那个 bug 的现场：同一份 PE，两个进程，两套特征。
    """
    import base64
    import json

    raw = (b"\x00" * 64 + b"CreateFileW\x00" + b"kernel32.dll\x00" +
           b"http://malicious.example.com/payload\x00" +
           b"RegOpenKeyExA\x00" + b"some printable string with digits 12345\x00" +
           b"\x00" * 64)
    b64 = base64.b64encode(raw).decode()
    code = [
        "import importlib.util, os, sys, json, base64",
        "ROOT = %r" % ROOT,
        "spec_sh = importlib.util.spec_from_file_location('_stable_hash', os.path.join(ROOT, 'feature_extraction', '_stable_hash.py'))",
        "sh = importlib.util.module_from_spec(spec_sh)",
        "sys.modules['_stable_hash'] = sh",
        "spec_sh.loader.exec_module(sh)",
        "spec = importlib.util.spec_from_file_location('extract_feature', os.path.join(ROOT, 'feature_extraction', 'extract_feature.py'))",
        "m = importlib.util.module_from_spec(spec)",
        "sys.modules['extract_feature'] = m",
        "spec.loader.exec_module(m)",
        "ext = m.BinjaExtractor.__new__(m.BinjaExtractor)",
        "raw = base64.b64decode(%r)" % b64,
        "feats = ext._extract_strings_fast(raw)",
        "print(json.dumps({k: v.tolist() for k, v in feats.items()}))",
    ]
    env = dict(os.environ)
    env.pop("PYTHONHASHSEED", None)
    out = subprocess.run([sys.executable, "-c", "\n".join(code)], capture_output=True,
                         text=True, env=env, timeout=120)
    assert out.returncode == 0, "子进程失败: %s" % out.stderr
    child = json.loads(out.stdout.strip())

    ef = _load("extract_feature", os.path.join("feature_extraction", "extract_feature.py"))
    ext = ef.BinjaExtractor.__new__(ef.BinjaExtractor)
    mine = ext._extract_strings_fast(raw)
    assert set(child.keys()) == set(mine.keys())
    for k in mine:
        assert mine[k].tolist() == child[k], "特征 %s 跨进程不一致" % k

def test_data_loader_style_import_works():
    """复刻 train/data_loader.py::_extract_fast_chunk 的加载方式。

    它用 importlib 按**文件路径**加载 extract_feature.py（module name = "extract_feature"，
    不属于任何包），且 feature_extraction/ **不在** sys.path 上。
    这种加载方式下 stable_hash 必须仍能被找到（走三级导入的兜底分支）。
    """
    code = [
        "import importlib.util, os, sys",
        "ROOT = %r" % ROOT,
        "spec = importlib.util.spec_from_file_location('extract_feature', os.path.join(ROOT, 'feature_extraction', 'extract_feature.py'))",
        "mod = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(mod)",
        "print(mod.stable_hash('kernel32.dll'))",
    ]
    out = subprocess.run([sys.executable, "-c", "\n".join(code)], capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, "data_loader 式加载失败: %s" % out.stderr
    assert out.stdout.strip() == str(stable_hash("kernel32.dll"))

def test_package_import_works_when_torch_available():
    """有 torch 的环境（容器/训练机）下，包级导入必须正常。"""
    try:
        import torch  # noqa: F401
    except Exception:
        return          # 裸环境跳过
    import feature_extraction.extract_feature as ef
    assert hasattr(ef, "stable_hash"), "包级导入未取到 stable_hash"


def main() -> int:
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print("  PASS  %s" % name)
        except Exception as e:
            failed.append((name, e))
            print("  FAIL  %s :: %s" % (name, e))
    print("\n%d/%d passed" % (len(tests) - len(failed), len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
