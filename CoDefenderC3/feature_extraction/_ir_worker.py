"""Disposable candidate worker; no engine/model/MalGraph imports."""
import argparse
import json
import sys
from pathlib import Path
from .ir_cache import (CandidateCache, FEATURE_SCHEMA, content_sha256, identity,
                       key_lock, read_arrays, write_arrays)


def process(path, cache_root=None, training_output=None):
    expected = identity(path, feature_schema=FEATURE_SCHEMA)
    if training_output:
        with key_lock(str(training_output) + ".lock"):
            try:
                read_arrays(training_output, expected)
                return
            except Exception:
                pass
    features = CandidateCache(cache_root).features(path)
    if training_output:
        from .extract_feature import BinjaExtractor
        fast = BinjaExtractor().extract_fast(path)
        if content_sha256(path) != expected["content_sha256"]:
            raise ValueError("sample changed during training extraction")
        with key_lock(str(training_output) + ".lock"):
            write_arrays(training_output, dict(fast, **features), expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--cache-root")
    parser.add_argument("--training-output")
    args = parser.parse_args()
    try:
        process(args.path, args.cache_root, args.training_output)
        print(json.dumps({"status": "ok"}))
    except Exception as exc:
        print(json.dumps({"status": "timeout" if isinstance(exc, TimeoutError) else "error", "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
