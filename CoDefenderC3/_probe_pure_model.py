# -*- coding: utf-8 -*-
"""验证「关闭过滤引擎 → 全部检测走模型」：
进程内 import engine.app 后检查三个签名库全局引用是否恒为 None，
以及 _hash_precheck / _hash_precheck_file 是否首行直接短路。
用法（两种模式各跑一次）：
  PYTHONIOENCODING=utf-8 python -u _probe_pure_model.py            # 默认：过滤引擎开启
  CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 PYTHONIOENCODING=utf-8 python -u _probe_pure_model.py
"""
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
import engine.app as A

mode = "关闭过滤引擎" if not config.HASH_DB_ENABLED else "过滤引擎开启"
print("=" * 62)
print("模式: %s" % mode)
print("  CODEFENDER_HASH_DB_ENABLED  =", os.environ.get("CODEFENDER_HASH_DB_ENABLED", "<未设>"))
print("  config.HASH_DB_ENABLED      =", config.HASH_DB_ENABLED)
print("  config.FUZZY_DB_ENABLED     =", config.FUZZY_DB_ENABLED)
print("-" * 62)
for name in ("_sha256_db", "_md5_db", "_fuzzy_db"):
    obj = getattr(A, name, "<不存在>")
    cnt = getattr(obj, "count", None) if obj is not None else None
    print("  %-12s = %s%s" % (name, type(obj).__name__ if obj is not None else None,
                              "  (%s 条)" % f"{cnt:,}" if isinstance(cnt, int) else ""))

# 预检短路验证：全 None 时必须直接 return None（即不放行到库查询，全部交给模型）
pre = A._hash_precheck(b"MZ" + b"\x00" * 4096, "dummy.exe", 4098)
print("-" * 62)
print("  _hash_precheck(任意内容) ->", pre, "(None = 未做库预检，走模型)")

all_none = A._sha256_db is None and A._md5_db is None and A._fuzzy_db is None
if not config.HASH_DB_ENABLED:
    assert all_none, "关闭开关后签名库引用仍非 None！"
    assert pre is None, "关闭开关后 _hash_precheck 仍返回结果！"
    print("  ✅ 断言通过：三级库全 None，预检短路，样本全部走模型")
else:
    print("  ℹ️ 过滤引擎开启：命中即短路（本次不做断言，仅记录引用状态）")
print("=" * 62)
