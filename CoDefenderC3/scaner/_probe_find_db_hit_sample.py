# -*- coding: utf-8 -*-
"""找一个 sha256 确实在签名库里的本地样本（用于验证在线实例是否启用哈希预检）。

直接在 SQLite 分片上按 hex 布局点查（只读），命中即打印路径与哈希。
用法: PYTHONIOENCODING=utf-8 python -u scaner/_probe_find_db_hit_sample.py [候选目录...]
"""
import hashlib
import os
import sqlite3
import sys

SIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signatures")
SIG = os.path.abspath(SIG)

CANDIDATE_DIRS = sys.argv[1:] or [
    r"E:\nkproject\training_data0915\malicious",
    r"E:\nkproject\test_samples",
]


def in_db(sha256_hex: str, size: int) -> bool:
    """hex 布局：首字节即分片号，直接在对应分片点查"""
    sid = int(sha256_hex[:2], 16)
    p = os.path.join(SIG, "sha256.db.shards", "%02x.db" % sid)
    if not os.path.exists(p):
        return False
    con = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    try:
        row = con.execute(
            "SELECT sha256 FROM sigs WHERE sha256=?", (bytes.fromhex(sha256_hex),)
        ).fetchone()
        return row is not None
    finally:
        con.close()


found = []
for d in CANDIDATE_DIRS:
    if not os.path.isdir(d):
        print("[skip] 目录不存在: %s" % d)
        continue
    names = sorted(os.listdir(d))
    print("[scan] %s (%d 个条目)" % (d, len(names)))
    for i, n in enumerate(names):
        p = os.path.join(d, n)
        if not os.path.isfile(p):
            continue
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            digest = h.hexdigest()
            size = os.path.getsize(p)
        except OSError:
            continue
        if in_db(digest, size):
            found.append((p, digest, size))
            print("  ✅ 命中库: %s" % p)
            print("     sha256=%s size=%d" % (digest, size))
            if len(found) >= 3:
                break
        if i >= 200:
            print("  (已扫 200 个样本未命中，转下一个目录)")
            break
    if len(found) >= 3:
        break

print()
if found:
    print("找到 %d 个可直接触发哈希预检的样本:" % len(found))
    for p, dg, sz in found:
        print("  %s" % p)
else:
    print("未找到命中样本（可能样本集与当前库不同源）")
