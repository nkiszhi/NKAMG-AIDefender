# -*- coding: utf-8 -*-
"""探针: 直接查询 BN 核心的许可校验位与到期时间。"""
import sys
import time
import datetime

import binaryninja as bn
from binaryninja import _binaryninjacore as core

print("core_version :", bn.core_version())

# 直接问核心
checks = [
    ("BNIsLicenseValidated()", lambda: core.BNIsLicenseValidated()),
    ("BNGetLicenseExpirationTime()", lambda: core.BNGetLicenseExpirationTime()),
    ("BNGetSerialNumber()", lambda: core.BNGetSerialNumber()),
    ("BNGetProduct()", lambda: core.BNGetProduct()),
    ("BNGetProductType()", lambda: core.BNGetProductType()),
    ("BNGetLicenseCount()", lambda: core.BNGetLicenseCount()),
    ("BNGetLicensedUserEmail()", lambda: core.BNGetLicensedUserEmail()),
]
for name, fn in checks:
    try:
        v = fn()
        if "ExpirationTime" in name and v:
            v = "%s  (epoch=%s)" % (datetime.datetime.fromtimestamp(v), v)
        print("  %-32s = %r" % (name, v))
    except Exception as e:
        print("  %-32s ! %r" % (name, e))

# 是否 UI 模式
try:
    print("  %-32s = %r" % ("BNIsUIEnabled()", core.BNIsUIEnabled()))
except Exception as e:
    print("  ui:", e)

print()
print("  bn.user_directory() =", bn.user_directory())
print("  bn.core_ui_enabled() =", bn.core_ui_enabled())
