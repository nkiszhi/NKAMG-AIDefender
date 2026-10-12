# -*- coding: utf-8 -*-
"""端到端验证「日更 CSV → /update-signatures」全链路（dir_path 模式, 真实数据）。

真实源: E:\\nkproject\\日更hash库\\cn_vt9-*.csv（22 列, 共 6 个文件）
  base   = cn_vt9-11_part001.csv 前 30 行（先用 CSV 建"生产现状"）
  update = 整个目录（6 个 CSV, 含与 base 重叠的行验证幂等）

断言:
  1) 格式探测 = csv, 6 个文件全部识别
  2) 三库增量精确 = 去重后的新增行数; 计数只增
  3) 在线可查: sha256 / ssdeep(传原生 ':' 形式, 验证查询侧归一化) / tlsh / imphash / authentihash
  4) 库内 ssdeep 全为 '-' 分隔（与建库口径一致）
  5) 幂等: 同 week 重复提交 / 换 week_id 重复提交 → no_new_rows
  6) CSV 统计: 无威胁标注行被正确过滤计数
"""
import os
import sys
import csv
import glob
import shutil
import sqlite3
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scaner"))

SRC = r"E:\nkproject\日更hash库"
TMP = tempfile.mkdtemp(prefix="csvup_")

import config as C
C.HASH_DB_DIR = TMP
C.FUZZY_DB_ENABLED = True

import scanner as S

HP = dict(shard_count=C.HASH_DB_SHARDS, bloom_fp_rate=C.HASH_DB_FP_RATE,
          max_open_shards=C.HASH_DB_MAX_OPEN, layout=C.HASH_DB_LAYOUT)


def rows_of(path):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def build_base(base_csv, n):
    """base 直接用 CSV 建库（n 行），校验 CSV 通道自身可用"""
    with open(base_csv, "r", encoding="utf-8-sig", newline="") as f:
        lines = f.read().splitlines(True)
    cut = os.path.join(TMP, "base.csv")
    open(cut, "w", encoding="utf-8").writelines(lines[:n + 1])
    sha = S.HashSignatureDB(os.path.join(TMP, "sha256.db"), **HP)
    md5 = S.HashSignatureDB(os.path.join(TMP, "md5.db"), hash_algo="md5", **HP)
    fz = S.FuzzySignatureDB(os.path.join(TMP, "fuzzy.db"),
                            max_open_shards=C.FUZZY_DB_MAX_OPEN, layout="hex")
    dbs = {"sha256": sha, "md5": md5, "fuzzy": fz}
    st = {}
    per = S.import_csv_signatures(cut, dbs, record_name="base.csv", stats=st)
    for d in dbs.values():
        d.finalize()
        d.close()
    print("[base] rows=%d inserted=%s" % (st["rows_total"], per))
    return per, st


class OldDB:
    def __init__(self, cnt):
        self.count = cnt


def main():
    files = sorted(glob.glob(os.path.join(SRC, "*.csv")))
    assert files, "未找到 CSV 源文件"
    base_file = files[0]
    base_rows = rows_of(base_file)
    base_n = 30
    base_per, base_st = build_base(base_file, base_n)

    import engine.app as A
    A._sha256_db = OldDB(base_per["sha256"])
    A._md5_db = OldDB(base_per["md5"])
    A._fuzzy_db = OldDB(base_per["fuzzy"])

    # 预期新增（用集合精确计算, 不写死）
    all_rows = [r for f in files for r in rows_of(f)]
    base_sha = {r["sha256"].strip().lower() for r in base_rows[:base_n]}
    base_md5 = {r["md5"].strip().lower() for r in base_rows[:base_n] if r["md5"].strip()}
    new_sha = [r["sha256"].strip().lower() for r in all_rows
               if r["sha256"].strip().lower() not in base_sha]
    new_md5 = [r["md5"].strip().lower() for r in all_rows
               if r["md5"].strip() and r["md5"].strip().lower() not in base_md5]
    exp_sha = len(set(new_sha))
    exp_md5 = len(set(new_md5))
    print("[expect] 全量行=%d base行=%d → 预期新增 sha256=%d md5=%d"
          % (len(all_rows), base_n, exp_sha, exp_md5))

    r1 = A.update_signatures(dir_path=SRC, week_id="20260923", vacuum=True)
    print("[publish] status=%s files=%d formats=%s" % (r1["status"], r1["files"], r1["formats"]))
    print("  rows_inserted =", r1["rows_inserted"])
    print("  counts        =", r1["counts"])
    print("  csv_stats     =", r1["csv_stats"])
    print("  vacuum        =", r1["vacuum"])
    assert r1["status"] == "published", r1
    assert r1["formats"] == {"csv": len(files)}, r1["formats"]
    assert r1["rows_inserted"]["sha256"] == exp_sha, (r1["rows_inserted"], exp_sha)
    assert r1["rows_inserted"]["md5"] == exp_md5, (r1["rows_inserted"], exp_md5)
    assert r1["csv_stats"]["rows_total"] == len(all_rows), r1["csv_stats"]
    assert r1["csv_stats"]["rows_ok"] == len(all_rows), r1["csv_stats"]
    assert A._sha256_db.count == r1["counts"]["after"]["sha256"], "热切换计数未生效"
    assert A._active_sig_dir() == r1["release"]

    # 3) 在线可查：取最后一个文件（不在 base 中）的首行
    probe = rows_of(files[-1])[0]
    size = int(probe["length"])
    hit = A._sha256_db.check_hash(probe["sha256"].lower())
    assert hit, "新样本 sha256 查不中"
    print("[verify] sha256 在线可查:", probe["sha256"][:16], "size=", hit[0].get("size"))

    # ssdeep：传 CSV 原生 ':' 形式（等价于本地 ppdeep 现算结果）→ 必须命中
    fz = A._fuzzy_db
    ss_raw = probe["ssdeep"].strip()
    hit = fz.check_by_computed_hashes(ssdeep=ss_raw, file_size=size)
    assert hit and hit[0]["fuzzy_type"] == "ssdeep", ("ssdeep 未命中", ss_raw[:40])
    print("[verify] ssdeep 查中(原生':'形式经归一化):", hit[0]["detail"], hit[0]["size"])

    # tlsh：本地口径 70 位无前缀大写 → 归一化后命中
    import staticinfo as SI
    t_raw = probe["tlsh"].strip()
    key = SI.normalize_tlsh_db_key(t_raw)
    hit = fz.check_by_computed_hashes(tlsh=key, file_size=size)
    assert hit and hit[0]["fuzzy_type"] == "tlsh", ("tlsh 未命中", key)
    print("[verify] tlsh 查中:", hit[0]["detail"])

    # imphash / authentihash
    hit = fz.check_by_computed_hashes(imphash_hex=probe["imphash"].strip(), file_size=size)
    assert hit and hit[0]["fuzzy_type"] == "imphash", ("imphash 未命中",)
    hit = fz.check_by_computed_hashes(authentihash_hex=probe["authentihash"].strip(),
                                      file_size=size)
    assert hit and hit[0]["fuzzy_type"] == "authentihash", ("authentihash 未命中",)
    print("[verify] imphash / authentihash 查中")

    # 4) 库内 ssdeep 全部为 '-' 分隔 + 各表计数
    d = os.path.join(r1["release"], "fuzzy.db.shards")
    meta = sqlite3.connect("file:%s/_meta.db?mode=ro" % d, uri=True)
    print("[db] fuzzy 各表计数:",
          dict(meta.execute("SELECT type,SUM(cnt) FROM fuzzy_counts GROUP BY type")))
    meta.close()
    colon = dash = 0
    for p in glob.glob(os.path.join(d, "[0-9a-f][0-9a-f].db")):
        con = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
        for (v,) in con.execute("SELECT ssdeep FROM sigs_ssdeep"):
            if ":" in v:
                colon += 1
            elif "-" in v:
                dash += 1
        con.close()
    print("[db] ssdeep 键: 含':'=%d  含'-'=%d" % (colon, dash))
    assert colon == 0 and dash > 0, (colon, dash)

    # 5) 幂等
    r2 = A.update_signatures(dir_path=SRC, week_id="20260923", vacuum=False)
    assert r2["status"] == "no_new_rows", r2
    r3 = A.update_signatures(dir_path=SRC, week_id="20260924", vacuum=False)
    assert r3["status"] == "no_new_rows", r3
    print("[idempotent] 同 week / 换 week 均 no_new_rows")

    # 6) malicious_only 过滤（构造一行无标注数据 + 一行缺 sha256）
    bad = os.path.join(TMP, "bad.csv")
    hdr = open(files[0], "r", encoding="utf-8-sig").readline()
    with open(bad, "w", encoding="utf-8", newline="") as f:
        f.write(hdr)
        f.write("clean.exe,100,%s,%s,,,,,,,,,,,,,,,,,\n" % ("0" * 64, "1" * 32))
        f.write("nosha.exe,100,deadbeef,,,,,,,,,,,,,,,,,\n")
    fz2 = S.FuzzySignatureDB(os.path.join(TMP, "fuzzy2.db"),
                             max_open_shards=C.FUZZY_DB_MAX_OPEN, layout="hex")
    st = {}
    S.import_csv_signatures(bad, {"fuzzy": fz2}, record_name="bad.csv", stats=st)
    fz2.close()
    print("[filter] stats =", st)
    assert st["skip_unlabeled"] == 1, st
    assert st["skip_no_sha256"] == 1, st
    assert st["rows_ok"] == 0, st

    print("ALL OK")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
