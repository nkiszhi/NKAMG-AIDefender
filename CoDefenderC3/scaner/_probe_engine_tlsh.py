"""临时探针: engine 路径 fuzzy/tlsh 第四级端到端 (用完即删)"""
import os, sys, logging, time

ROOT = r"D:\VM_Share\CoDefenderC3_v8\CoDefenderC3"
sys.path.insert(0, ROOT)
os.chdir(ROOT)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

import engine.app as A

print("\n== 启动态 ==")
print("  _sha256_db:", A._sha256_db is not None, getattr(A._sha256_db, "count", None))
print("  _md5_db   :", A._md5_db is not None, getattr(A._md5_db, "count", None))
print("  _fuzzy_db :", A._fuzzy_db is not None, getattr(A._fuzzy_db, "_counts", None))
print("  tlsh cap  :", A.config.FUZZY_DB_TLSH_MAX_BYTES)

DIRS = [r"E:\nkproject\training_data0915\malicious", r"E:\nkproject\training_data0915\benign"]
PREF = ["000d5607cdf0ce60", "00a275f08bc314eb", "009e1dddee1f811a"]
files = []
for pref in PREF:
    for d in DIRS:
        hit = [f for f in os.listdir(d) if f.startswith(pref)]
        if hit:
            files.append(os.path.join(d, hit[0]))
            break

print("\n== 1. 默认 cap=1MB: 三个样本都 >1MB → tlsh 应被限流跳过 ==")
for fp in files:
    data = open(fp, "rb").read()
    hit, src = A._lookup_fuzzy(data, len(data))
    print("  %s %8d B -> src=%s" % (os.path.basename(fp)[:12] + "...", len(data), src))

print("\n== 2. 临时放大 cap=8MB → 应命中 tlsh 第四级 ==")
A.config.FUZZY_DB_TLSH_MAX_BYTES = 8 * 1024 * 1024
for fp in files:
    data = open(fp, "rb").read()
    t0 = time.time()
    hit, src = A._lookup_fuzzy(data, len(data))
    dt = time.time() - t0
    print("  %s %8d B -> src=%s fuzzy_type=%s size=%s (%.2fs)" % (
        os.path.basename(fp)[:12] + "...", len(data), src,
        (hit or {}).get("fuzzy_type"), (hit or {}).get("size"), dt))

print("\n== 3. 完整预检链返回结构 (cap=8MB) ==")
fp = files[0]
data = open(fp, "rb").read()
res = A._hash_precheck(data, os.path.basename(fp), len(data))
print("  Source=%s IsMalicious=%s VirusName=%s" % (
    res.get("Source"), res.get("IsMalicious"), res.get("ScanResult", {}).get("VirusName")))
print("  HashMatch=%s" % (res.get("ScanResult", {}).get("HashMatch"),))

print("\n== 4. 负样本 (随机 300KB, cap 内, 应无命中) ==")
import random
blob = random.randbytes(300000)
print("  ", A._lookup_fuzzy(blob, len(blob)))

print("\n== 5. 非 PE 小文件 (>=50B 非 PE, 走 tlsh 但不命中) ==")
blob2 = b"this is a plain text file, not PE. " * 10
print("  ", A._lookup_fuzzy(blob2, len(blob2)))
