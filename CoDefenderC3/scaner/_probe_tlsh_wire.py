"""临时探针: 验证 tlsh 第四级接入后的端到端可用性 (用完即删)"""
import os, sys, sqlite3, hashlib, random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import staticinfo as SI
import scanner as SC

DB = os.path.join(ROOT, "signatures", "fuzzy.db")

print("== 1. FUZZY_TYPES / 表定义 ==")
print("   FUZZY_TYPES     :", SC.FUZZY_TYPES)
print("   FUZZY_STR_TYPES :", SC.FUZZY_STR_TYPES)
print("   tlsh 表名       :", SC.FUZZY_TABLE_SPECS["tlsh"]["table"])

print("\n== 2. 归一化函数 ==")
for raw, expect in [("02655C01A7A28063E17628708976BB440678BFB12E23D56BFE54750AFE32BC1553377B", True),
                    ("t102655c01a7a28063e17628708976bb440678bfb12e23d56bfe54750afe32bc1553377b", True),
                    (None, False), ("", False), ("1234", False)]:
    out = SI.normalize_tlsh_db_key(raw)
    ok = bool(out) == expect
    print("   %-8s %s  -> %s" % ("OK" if ok else "FAIL", (raw or "None")[:20], (out or "None")[:20]))
    assert ok, "归一化断言失败"

print("\n== 3. 载入 FuzzySignatureDB (hex/256 片) ==")
db = SC.FuzzySignatureDB(DB, max_open_shards=16, layout="hex")
print("   counts:", {k: f"{v:,}" for k, v in db._counts.items()})
print("   bloom dirty(启动即需重建):", len(db._bloom_dirty))
st = db.stats()
print("   stats.tier:", st["tier"], "| types:", st.get("types"))

print("\n== 4. 真实样本端到端 (库内已有 sha256 的 3 个样本) ==")
VALID = [r"D:\VM_Share\CoDefenderC3_v8\DUP", None]
DIRS = [r"E:\nkproject\training_data0915\malicious",
        r"E:\nkproject\training_data0915\benign"]
# 直接复用上一轮探针找到的 3 个 (tlsh, sha256) 配对
pairs = []
for sid in range(0, 256, 8):
    p = os.path.join(DB + ".shards", "%02x.db" % sid)
    c = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    for tlsh_val, size, sha_hex in c.execute(
            "SELECT tlsh, size, hex(sha256) FROM sigs_tlsh LIMIT 400"):
        if not sha_hex:
            continue
        for d in DIRS:
            fp = os.path.join(d, sha_hex.lower())
            if os.path.exists(fp):
                pairs.append((fp, tlsh_val, size))
    c.close()
    if len(pairs) >= 3:
        break

ok_n = 0
for fp, stored, size in pairs[:3]:
    data = open(fp, "rb").read()
    key = SI.compute_tlsh_db_key(data, max_bytes=None)        # 不限流, 验证格式
    hits = db.check_by_computed_hashes(tlsh=key, file_size=len(data))
    hit_ok = bool(hits) and hits[0].get("fuzzy_type") == "tlsh"
    ok_n += 1 if hit_ok else 0
    print("   %s  size=%d  key=%s  -> 命中=%s (%s)" % (
        os.path.basename(fp)[:12] + "...", len(data), (key or "")[:12] + "...",
        bool(hits), hits[0].get("fuzzy_type") if hits else "-"))
    if hits:
        print("        返回结构 keys:", sorted(hits[0].keys()))

print("\n== 5. 限流生效 (max_bytes 小于文件) ==")
if pairs:
    fp, _, _ = pairs[0]
    data = open(fp, "rb").read()
    print("   文件 %d B, cap=1KB -> %s ; cap=%d -> %s" % (
        len(data), SI.compute_tlsh_db_key(data, max_bytes=1024),
        len(data), (SI.compute_tlsh_db_key(data, max_bytes=len(data)) or "None")[:12] + "..."))

print("\n== 6. 负样本 (随机数据, 不应命中) ==")
neg_hits = 0
for i in range(30):
    blob = random.randbytes(random.randint(200, 200000))
    k = SI.compute_tlsh_db_key(blob, max_bytes=None)
    if k and db.check_by_computed_hashes(tlsh=k, file_size=len(blob)):
        neg_hits += 1
print("   30 个随机文件误报: %d" % neg_hits)

print("\n== 7. 正确性: 不做 size 校验时 (file_size=None) ==")
if pairs:
    fp, _, _ = pairs[0]
    data = open(fp, "rb").read()
    k = SI.compute_tlsh_db_key(data, max_bytes=None)
    print("   file_size=None ->", bool(db.check_by_computed_hashes(tlsh=k)))
    print("   错误 size 比对 ->", bool(db.check_by_computed_hashes(tlsh=k, file_size=len(data) + 1)))

db.close()
print("\n样本端到端命中 %d/%d" % (ok_n, min(3, len(pairs))))
