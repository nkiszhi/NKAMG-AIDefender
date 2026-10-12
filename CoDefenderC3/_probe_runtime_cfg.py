# -*- coding: utf-8 -*-
"""验证「免重启改配置」：运行时热切换过滤引擎 + 覆盖文件持久化。

不依赖 HTTP：直接 import engine.app 后调用 admin_config_set / admin_config_get
（FastAPI 的默认参数已做 isinstance 容错）。全程断言式校验，退出码非 0 表示失败。

用法:
  PYTHONIOENCODING=utf-8 python -u _probe_runtime_cfg.py
"""
import logging
import os
import sys
import tempfile

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config

FAIL = []


def check(cond, msg):
    print(("  ✅ " if cond else "  ❌ ") + msg)
    if not cond:
        FAIL.append(msg)


print("=" * 70)
print("阶段 1 — 纯 config 层：覆盖 / 复位 / 落盘 / 读回")
print("-" * 70)
base_hash = config.HASH_DB_ENABLED
base_fuzzy = config.FUZZY_DB_ENABLED
print("  基线(env/默认): HASH_DB_ENABLED=%s FUZZY_DB_ENABLED=%s" % (base_hash, base_fuzzy))

config.apply_runtime_overrides({"hash_db_enabled": False, "fuzzy_db_enabled": "0"})
check(config.HASH_DB_ENABLED is False, "改后 config.HASH_DB_ENABLED == False（字符串 '0' 也解析正确）")
check(config.FUZZY_DB_ENABLED is False, "改后 config.FUZZY_DB_ENABLED == False")
st = config.runtime_cfg_state()
check(st["HASH_DB_ENABLED"]["origin"] == "runtime:api", "来源标记 = runtime:api")

# 原子性：非法项不允许"改一半"
_base_maxbytes = config.FUZZY_DB_MAX_BYTES
try:
    config.apply_runtime_overrides({"FUZZY_DB_MAX_BYTES": 4096, "NOPE": 1})
    check(False, "含非法项时应当抛错")
except KeyError:
    check(config.FUZZY_DB_MAX_BYTES == _base_maxbytes,
          "覆盖是原子的：非法项导致整批不生效（MAX_BYTES 保持 %s）" % _base_maxbytes)

tmp_json = os.path.join(tempfile.gettempdir(), "_probe_runtime_cfg.json")
try:
    config.save_runtime_cfg_file(tmp_json)
    applied, err = config.load_runtime_cfg_file(tmp_json)
    check(not err and applied.get("HASH_DB_ENABLED") is False, "落盘后读回一致: %s" % applied)
    check(os.path.isfile(tmp_json), "覆盖文件已生成: %s" % tmp_json)
finally:
    if os.path.isfile(tmp_json):
        os.remove(tmp_json)

config.reset_runtime_overrides()
check(config.HASH_DB_ENABLED == base_hash, "复位后 HASH_DB_ENABLED 回到基线 %s" % base_hash)
check(config.FUZZY_DB_ENABLED == base_fuzzy, "复位后 FUZZY_DB_ENABLED 回到基线 %s" % base_fuzzy)

print()
print("=" * 70)
print("阶段 2 — 进程内热切换：import engine.app 后关闭 / 开启过滤引擎")
print("-" * 70)
import engine.app as A  # noqa: E402  （import 即执行 _init_hash_dbs）

print("  初始状态:", A._hash_db_state())
probe_bytes = b"MZ" + b"\x00" * 4096
db0 = A._sha256_db

# 2.1 关闭
r = A.admin_config_set({"hash_db_enabled": False, "fuzzy_db_enabled": False})
check(r["hash_db"]["enabled"] is False, "返回体 hash_db.enabled == False")
check(A._sha256_db is None and A._md5_db is None and A._fuzzy_db is None,
      "三库全局引用已被摘除（无需重启）")
check(A._hash_precheck(probe_bytes, "dummy.exe", len(probe_bytes)) is None,
      "_hash_precheck 短路 → 样本全部走模型")
check(A.metrics()["hash_db_enabled"] is False, "/metrics hash_db_enabled == False")
check(A.health()["hash_db"]["enabled"] is False, "/health hash_db.enabled == False")
check(isinstance(A.health()["pid"], int), "/health 暴露 pid=%s（判断是否打到旧进程）"
      % A.health()["pid"])

# 2.2 重新开启（走 _init_hash_dbs 的降级逻辑重建）
r2 = A.admin_config_set({"hash_db_enabled": True, "fuzzy_db_enabled": True})
st2 = r2["hash_db"]
check(st2["enabled"] is True, "重新开启后 enabled == True")
check((st2["sha256"] or 0) > 0, "SHA256 库重新装载: %s 条" % st2["sha256"])
check((st2["fuzzy"] or 0) > 0, "Fuzzy 库重新装载: %s 条" % st2["fuzzy"])
check(A._sha256_db is not None and A._fuzzy_db is not None, "全局引用已换新实例")
check(A._sha256_db is not db0, "换的是新对象，不是复用了旧句柄")

# 2.5 新实例必须真能命中：count 对得上不代表查询链路可用
import sqlite3  # noqa: E402
_shard = os.path.join(A._hash_db_state()["dir"], "sha256.db.shards", "00.db")
_conn = sqlite3.connect(_shard)
_known = _conn.execute("select sha256 from sigs limit 1").fetchone()[0].hex()
_conn.close()
check(bool(A._sha256_db.check_hash(_known, file_size=0)),
      "热切换后的库能命中库内真实哈希 %s…" % _known[:16])

# 2.3 非法项 / 冷配置项
try:
    A.admin_config_set({"nope": 1})
    check(False, "非法配置项应当 400")
except Exception as e:
    check("400" in str(e), "非法配置项被拒: %s" % type(e).__name__)
r3 = A.admin_config_set({"views_require_all": False})
check(r3["cold_keys_pending_restart"] == ["VIEWS_REQUIRE_ALL"],
      "冷配置项被标记待重启: %s" % r3["cold_keys_pending_restart"])
config.reset_runtime_overrides(["VIEWS_REQUIRE_ALL"])

# 2.4 覆盖文件热重载
saved_path = config.RUNTIME_CFG_FILE
tmp2 = os.path.join(tempfile.gettempdir(), "_probe_runtime_cfg2.json")
try:
    with open(tmp2, "w", encoding="utf-8") as f:
        f.write('{"overrides": {"hash_db_enabled": false}}')
    config.RUNTIME_CFG_FILE = tmp2
    r4 = A.admin_config_set({"reload_file": True})
    check(r4["hash_db"]["enabled"] is False, "reload_file 加载文件并热切换为关闭")
    check(r4["reloaded_from_file"].get("HASH_DB_ENABLED") is False,
          "reloaded_from_file 回显: %s" % r4["reloaded_from_file"])
finally:
    config.RUNTIME_CFG_FILE = saved_path
    if os.path.isfile(tmp2):
        os.remove(tmp2)

# 收尾：恢复现场（开启过滤引擎）
A.admin_config_set({"hash_db_enabled": base_hash, "fuzzy_db_enabled": base_fuzzy})
config.reset_runtime_overrides()
print()
print("=" * 70)
print("收尾状态:", A._hash_db_state())
if FAIL:
    print("❌ 失败 %d 项: %s" % (len(FAIL), FAIL))
    sys.exit(1)
print("✅ 全部断言通过：运行时可热切换，无需重启进程")
print("=" * 70)
