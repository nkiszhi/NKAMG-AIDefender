# -*- coding: utf-8 -*-
"""探针: 确认 ssdeep 库口径 (DB 存的是 ':' 还是 '-'), 决定 CSV 导入是否需要归一化。

做法: 遍历训练样本 → sha256 在 sha256 库命中 → 本地算 ssdeep → 分别用
      ':' 原样 与 ':'→'-' 两种键查 fuzzy 库, 看哪种命中。
"""
import os, sys, glob, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import scanner as S
import staticinfo as SI

sig_dir = os.path.join(config.HASH_DB_DIR)
print("sig_dir =", sig_dir)

sha = S.HashSignatureDB(os.path.join(sig_dir, "sha256.db"),
                        shard_count=config.HASH_DB_SHARDS,
                        bloom_fp_rate=config.HASH_DB_FP_RATE,
                        max_open_shards=config.HASH_DB_MAX_OPEN,
                        layout=config.HASH_DB_LAYOUT)
fz = S.FuzzySignatureDB(os.path.join(sig_dir, "fuzzy.db"),
                        max_open_shards=config.FUZZY_DB_MAX_OPEN, layout="hex")
print("sha256=%s  fuzzy=%s" % (f"{sha.count:,}", f"{fz.count:,}"))

root = r"E:\nkproject\training_data0915\malicious"
files = [p for p in glob.glob(os.path.join(root, "*")) if os.path.getsize(p) <= 2 * 1024 * 1024]
print("候选样本(<=2MB):", len(files))

n_sha_hit = 0
n_ss = 0
colon_hit = dash_hit = both = 0
shown = 0
for p in files[:400]:
    data = open(p, "rb").read()
    h = hashlib.sha256(data).hexdigest()
    if not sha.check_hash(h):
        continue
    n_sha_hit += 1
    ss = SI.compute_ssdeep(data)
    if not ss:
        continue
    n_ss += 1
    c = bool(fz.check_by_computed_hashes(ssdeep=ss, file_size=len(data)))
    d = bool(fz.check_by_computed_hashes(ssdeep=ss.replace(":", "-"), file_size=len(data)))
    colon_hit += c
    dash_hit += d
    both += (c and d)
    if shown < 3:
        print("  sample=%s" % os.path.basename(p))
        print("    computed      = %s" % ss)
        print("    check_by_computed_hashes 原生':' 命中 = %s" % c)
        print("    check_by_computed_hashes '-'-形式命中 = %s" % d)
        shown += 1
    if n_sha_hit >= 40:
        break

print()
print("sha256 命中样本: %d, 其中可算 ssdeep: %d" % (n_sha_hit, n_ss))
print("经 check_by_computed_hashes (归一化后) 命中: %d / %d" % (colon_hit, n_ss))
print("（修复前该值应为 0：本地 ppdeep 输出 ':' 而库内为 '-' 分隔）")
assert n_ss and colon_hit == n_ss, "ssdeep 查询侧归一化未生效"
