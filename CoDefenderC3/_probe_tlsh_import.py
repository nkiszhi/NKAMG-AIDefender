# -*- coding: utf-8 -*-
"""验证 FuzzySignatureDB.import_hdb 可选第 9 字段 tlsh：归一化入库 + 查询命中。"""
import os, sys, tempfile, shutil, sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scaner"))

import config as C
import scanner as S
import staticinfo as SI

TMP = tempfile.mkdtemp(prefix="tlshtl_")
try:
    hdb = os.path.join(TMP, "weekly-2026W39.hdb")
    t_official = "t1" + "ab" * 35          # 72 字符官方格式（小写，带前缀）
    t_upper70 = "CD" * 35                  # 70 位无前缀大写（本地旧口径）
    t_upper72 = "T1" + "ef" * 35           # 72 字符大写前缀变体
    lines = [
        # sha256:size:name:ssdeep:vhash:authentihash:imphash:rich:tlsh  (9 字段)
        "%s:2048:Fam1:384:aabb:ccdd:1122::%s" % ("aa" * 32, t_official),
        "%s:4096:Fam2:387:1111:2222:3333::%s" % ("bb" * 32, t_upper70),
        "%s:8192:Fam3:388:4444:5555:6666::%s" % ("cc" * 32, t_upper72),
        "%s:1024:NoTlsh:386:dead:beef:0707:" % ("dd" * 32),              # 8 字段, 无 tlsh
    ]
    open(hdb, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    fz = S.FuzzySignatureDB(os.path.join(TMP, "fuzzy.db"),
                            max_open_shards=C.FUZZY_DB_MAX_OPEN, layout="hex")
    n = fz.import_hdb(hdb)
    print("imported rows =", n)
    c = sqlite3.connect("file:%s?mode=ro" % os.path.join(TMP, "fuzzy.db.shards", "_meta.db"), uri=True)
    counts = dict(c.execute("SELECT type, SUM(cnt) FROM fuzzy_counts GROUP BY type"))
    print("table counts  =", counts)

    # 断言：tlsh 表 3 条
    assert counts.get("tlsh") == 3, counts

    # 查询命中：三种源格式经归一化后（normalize 与导入同口径）都应查中
    for raw, size in ((t_official, 2048), (t_upper70, 4096), (t_upper72, 8192)):
        k = SI.normalize_tlsh_db_key(raw)
        assert k.startswith("t1") and len(k) == 72 and k == k.lower(), k
        hits = fz.check_by_computed_hashes(tlsh=k, file_size=size)
        assert hits, "tlsh %s 查不中" % k[:12]
        print("hit:", hits[0]["fuzzy_type"], hits[0].get("size"), hits[0].get("name"))
    # 8 字段行不受影响：ssdeep 正常入库可查
    hits = fz.check_by_computed_hashes(ssdeep="386", file_size=1024)
    assert hits and hits[0]["fuzzy_type"] == "ssdeep", hits
    print("8-field line still ok:", hits[0]["fuzzy_type"])
    fz.close()
    print("ALL OK")
finally:
    shutil.rmtree(TMP, ignore_errors=True)
