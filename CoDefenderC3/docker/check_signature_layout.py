#!/usr/bin/env python3
"""Read-only layout gate for images embedding SHA256, MD5 and fuzzy shards.

This checks files, not SQLite schemas, row counts or signature correctness.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

FAMILIES = ("sha256", "md5", "fuzzy")


def validate_signature_layout(sig_dir: Path) -> Dict[str, int]:
    root = Path(sig_dir)
    errors = []
    counts = {}
    for family in FAMILIES:
        directory = root / (family + ".db.shards")
        meta = directory / "_meta.db"
        if not directory.is_dir():
            errors.append("missing directory: %s" % directory)
            continue
        if not meta.is_file() or meta.stat().st_size == 0:
            errors.append("missing or empty metadata: %s" % meta)
        shards = [p for p in directory.glob("[0-9a-f][0-9a-f].db")
                  if p.is_file() and p.stat().st_size > 0]
        counts[family] = len(shards)
        if not shards:
            errors.append("no non-empty data shard: %s" % directory)
    if errors:
        raise ValueError("\n".join(errors))
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sig-dir", default=".docker_build/signatures")
    args = parser.parse_args(argv)
    try:
        counts = validate_signature_layout(Path(args.sig_dir))
    except (ValueError, OSError) as error:
        parser.exit(2, "[signatures] %s\n" % error)
    for family, count in counts.items():
        print("[signatures] %s: %d non-empty data shards" % (family, count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
