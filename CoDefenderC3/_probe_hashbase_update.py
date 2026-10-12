# -*- coding: utf-8 -*-
"""端到端验证 hashBase 9 字段格式走 /update-signatures（dir_path 模式）。

用真实 hashBase 文件的前 N 行构造 mini 集:
  base   = 00.hdb 前 250 行 (先建"生产现状")
  weekly = 00.hdb 前 500 行 + 01.hdb 前 500 行 (dir_path 上传, 含重叠行验证幂等)
断言: 发布成功 / 三库计数只增且增量=新增行数 / 新 sha256 在线可查 /
      同 week 重复提交 no_new_rows / 换 week_id 后仍 no_new_rows (行级幂等)。
"""
import os, sys, shutil, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scaner"))

SRC = r"D:\VM_Share\hashBase\hdb_2026\hdb_2026"
TMP = tempfile.mkdtemp(prefix="hbu_")

import config as C
C.HASH_DB_DIR = TMP
C.FUZZY_DB_ENABLED = True

import scanner as S

HP = dict(shard_count=C.HASH_DB_SHARDS, bloom_fp_rate=C.HASH_DB_FP_RATE,
          max_open_shards=C.HASH_DB_MAX_OPEN, layout=C.HASH_DB_LAYOUT)


def take(src, dst, n):
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        lines = [next(f) for _ in range(n)]
    open(dst, "w", encoding="utf-8").writelines(lines)


def build_base(base_hdb):
    sha = S.HashSignatureDB(os.path.join(TMP, "sha256.db"), **HP)
    md5 = S.HashSignatureDB(os.path.join(TMP, "md5.db"), hash_algo="md5", **HP)
    fz = S.FuzzySignatureDB(os.path.join(TMP, "fuzzy.db"),
                            max_open_shards=C.FUZZY_DB_MAX_OPEN, layout="hex")
    c = {"sha256": sha.import_hashbase_hdb(base_hdb),
         "md5": md5.import_hashbase_hdb(base_hdb),
         "fuzzy": fz.import_hashbase_hdb(base_hdb)}
    for d in (sha, md5, fz):
        d.finalize(); d.close()
    print("[base]", c)
    return c


class OldDB:
    def __init__(self, cnt): self.count = cnt


def main():
    # mini 周更集: 真实文件前 500 行 × 2 个分片文件
    mini = os.path.join(TMP, "mini")
    os.makedirs(mini)
    take(os.path.join(SRC, "00.hdb"), os.path.join(mini, "00.hdb"), 500)
    take(os.path.join(SRC, "01.hdb"), os.path.join(mini, "01.hdb"), 500)
    # base: 00.hdb 前 250 行
    base_hdb = os.path.join(TMP, "base.hdb")
    take(os.path.join(SRC, "00.hdb"), base_hdb, 250)
    base_counts = build_base(base_hdb)

    import engine.app as A
    A._sha256_db = OldDB(base_counts["sha256"])
    A._md5_db = OldDB(base_counts["md5"])
    A._fuzzy_db = OldDB(base_counts["fuzzy"])

    r1 = A.update_signatures(dir_path=mini, week_id="2026W39", vacuum=True)
    print("[publish] status=%s formats=%s files=%d" % (r1["status"], r1["formats"], r1["files"]))
    print("  rows_inserted =", r1["rows_inserted"])
    print("  counts        =", r1["counts"])
    print("  vacuum        =", r1["vacuum"])
    assert r1["status"] == "published" and r1["formats"] == {"hashbase9": 2}, r1
    assert r1["files"] == 2, r1
    assert r1["rows_inserted"]["sha256"] == 750, r1["rows_inserted"]  # 00 后250 + 01 前500
    assert r1["counts"]["after"]["sha256"] == base_counts["sha256"] + 750
    assert all(r1["counts"]["after"][k] == base_counts[k] + r1["rows_inserted"][k]
               for k in r1["rows_inserted"])
    assert A._sha256_db.count == r1["counts"]["after"]["sha256"], "热切换计数未生效"
    assert A._active_sig_dir() == r1["release"]

    # 新 sha256 在线可查: 取 01.hdb 首行 (base 只含 00.hdb 前 250 行, 必为新)
    with open(os.path.join(SRC, "01.hdb"), "r", encoding="utf-8", errors="ignore") as f:
        new_sha = f.readline().split(":")[0].strip().lower()
    hit = A._sha256_db.check_hash(new_sha)
    assert hit, "新样本 sha256 查不中"
    print("[verify] 真实新样本在线可查:", new_sha[:16], "size=", hit[0].get("size"))
    # fuzzy 侧: tlsh 归一化后可查
    import staticinfo as SI
    with open(os.path.join(SRC, "01.hdb"), "r", encoding="utf-8", errors="ignore") as f:
        p = f.readline().split(":")
    tlsh_key = SI.normalize_tlsh_db_key(p[4])
    assert tlsh_key and A._fuzzy_db.check_by_computed_hashes(
        tlsh=tlsh_key, file_size=int(p[1])), "新样本 tlsh 查不中"
    print("[verify] 真实新样本 tlsh 在线可查:", tlsh_key[:16])

    # 幂等: 同 week 重复提交 → no_new_rows
    r2 = A.update_signatures(dir_path=mini, week_id="2026W39", vacuum=False)
    print("[idempotent-同week]", r2["status"])
    assert r2["status"] == "no_new_rows", r2
    # 换 week_id (绕开 basename 去重) → 依然 no_new_rows (行级幂等)
    r3 = A.update_signatures(dir_path=mini, week_id="2026W40", vacuum=False)
    print("[idempotent-换week]", r3["status"])
    assert r3["status"] == "no_new_rows", r3

    print("ALL OK")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
