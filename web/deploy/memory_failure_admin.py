#!/usr/bin/env python3
"""Explicit operator-only unblock. Never exposed as an anonymous HTTP API."""
import argparse
from contextlib import closing
from datetime import datetime
from pathlib import Path
import re
import sqlite3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--unblock', action='store_true', help='Without this flag, only show the block')
    args = parser.parse_args()
    sha = args.sha256.lower()
    if not re.fullmatch('[0-9a-f]{64}', sha) or not args.db.is_file():
        parser.error('A valid SHA256 and an existing task database are required')
    with closing(sqlite3.connect(args.db, timeout=10)) as db:
        row = db.execute('SELECT * FROM model_memory_failures WHERE sha256=? AND revision=?', (sha,args.revision)).fetchone()
        print('Block:', row)
        if row and args.unblock:
            backup = args.db.with_name(args.db.name + '.before-unblock-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
            with closing(sqlite3.connect(backup)) as target:
                db.backup(target)
            with db:
                db.execute('DELETE FROM model_memory_failures WHERE sha256=? AND revision=?', (sha,args.revision))
            print('Unblocked. Database backup:',backup)


if __name__ == '__main__':
    main()
