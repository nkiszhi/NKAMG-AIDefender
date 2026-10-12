# -*- coding: utf-8 -*-
"""端到端验证 POST /update-signatures：临时目录构造小库 → 上传 hdb → 断言发布/热切换/幂等。"""
import os, sys, io, json, shutil, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scaner"))

TMP = tempfile.mkdtemp(prefix="sigt_")
import config as C
C.HASH_DB_DIR = TMP          # 探针：把签名库根指到临时目录
C.FUZZY_DB_ENABLED = True

import scanner as S
HP = dict(shard_count=C.HASH_DB_SHARDS, bloom_fp_rate=C.HASH_DB_FP_RATE,
          max_open_shards=C.HASH_DB_MAX_OPEN, layout=C.HASH_DB_LAYOUT)


def make_base():
    """在 TMP 下建一个小型 sha256 + fuzzy 库作为『生产现状』。"""
    base_sha = os.path.join(TMP, "base_sha.hdb")
    lines = ["%s:123:OldA" % ("aa" * 32), "%s:456:OldB" % ("bb" * 32)]
    open(base_sha, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    base_fz = os.path.join(TMP, "base_fz.hdb")
    # 8 字段: sha256:size:name:ssdeep:vhash:authentihash:imphash:rich
    fz_line = "%s:2048:OldFam:384:AAAA:BBBB:CCCC:" % ("dd" * 32)
    open(base_fz, "w", encoding="utf-8").write(fz_line + "\n")

    sha = S.HashSignatureDB(os.path.join(TMP, "sha256.db"), **HP)
    n1 = sha.import_hdb(base_sha); sha.finalize(); sha.close()
    fz = S.FuzzySignatureDB(os.path.join(TMP, "fuzzy.db"),
                            max_open_shards=C.FUZZY_DB_MAX_OPEN, layout="hex")
    n2 = fz.import_hdb(base_fz); fz.finalize(); fz.close()
    print("[base] sha256 +%d, fuzzy +%d" % (n1, n2))
    return n1, n2


class StubUpload:
    def __init__(self, path, name):
        self.filename = name
        self.file = open(path, "rb")


def main():
    n_sha, n_fz = make_base()

    import engine.app as A
    # 把在线全局替换为指向 TMP 基线的桩（仅暴露 .count 供回退校验）
    class OldDB:  # 计数桩
        def __init__(self, c): self.count = c
    A._sha256_db = OldDB(n_sha)
    A._md5_db = None
    A._fuzzy_db = OldDB(n_fz)

    # 周更文件：1 条新 sha256(3 字段) + 1 条新 fuzzy(8 字段，带 ssdeep)
    weekly = os.path.join(TMP, "weekly-2026W38.hdb")
    body = ("%s:789:NewMal:384:aabb:ccdd:1122:\n" % ("ee" * 32)
            + "%s:999:NewHash\n" % ("cc" * 32))
    open(weekly, "w", encoding="utf-8").write(body)

    r1 = A.update_signatures(StubUpload(weekly, "weekly-2026W38.hdb"))
    print("[publish] status=%s" % r1["status"])
    print("  rows_inserted =", r1["rows_inserted"])
    print("  counts        =", r1["counts"])
    print("  vacuum        =", r1["vacuum"])
    print("  release       =", r1["release"])
    assert r1["status"] == "published", r1
    # 8 字段行首列 sha256 同样进 sha256 库 → 2 行全进；fuzzy 至少 1 条
    assert r1["rows_inserted"]["sha256"] == 2, r1
    assert r1["rows_inserted"]["fuzzy"] >= 1, r1
    assert r1["counts"]["after"]["sha256"] == n_sha + r1["rows_inserted"]["sha256"]
    assert r1["counts"]["after"]["fuzzy"] == n_fz + r1["rows_inserted"]["fuzzy"]
    assert A._sha256_db.count == r1["counts"]["after"]["sha256"], "热切换后在线 sha256 库计数未更新"
    assert A._fuzzy_db.count == r1["counts"]["after"]["fuzzy"], "热切换后在线 fuzzy 库计数未更新"
    assert A._active_sig_dir() == r1["release"], "重启解析目录与发布目录不一致"

    # 真实命中验证：新哈希在线库立即可查
    hit = A._sha256_db.check_hash("cc" * 32)
    assert hit, "热切换后新 sha256 查不中"
    print("[verify] 新 sha256 在线可查:", hit[0].get("size"))

    # 幂等：同名文件重传 → no_new_rows，不发布新版本
    r2 = A.update_signatures(StubUpload(weekly, "weekly-2026W38.hdb"))
    print("[idempotent] status=%s" % r2["status"])
    assert r2["status"] == "no_new_rows", r2

    # 目录结构
    print("[layout] releases =", os.listdir(os.path.join(TMP, "releases")))
    cur = os.path.join(TMP, "current")
    print("[layout] current 存在 =", os.path.exists(cur),
          "(symlink=%s)" % os.path.islink(cur))

    print("ALL OK")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
