"""test_lm import compatibility backed by main's public hashing module."""
try:
    from .hashing import stable_hash, stable_seed
except ImportError:
    # Standalone legacy workers/tests load this file without a package context.
    import importlib.util
    from pathlib import Path
    _spec = importlib.util.spec_from_file_location("codefender_hashing", Path(__file__).with_name("hashing.py"))
    _module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_module)
    stable_hash, stable_seed = _module.stable_hash, _module.stable_seed


def stable_bucket(value, dim):
    if dim <= 0:
        raise ValueError("dim must be positive")
    return stable_hash(value) % dim
