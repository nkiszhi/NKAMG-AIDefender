# -*- coding: utf-8 -*-
"""探针: 对比 BNInitPlugins 前后 BNIsLicenseValidated 的变化，判定真实许可模式。"""
import binaryninja as bn
from binaryninja import _binaryninjacore as core

print("=== 调用前 ===")
print("  BNIsLicenseValidated() =", core.BNIsLicenseValidated())
print("  BNGetSerialNumber()    =", repr(core.BNGetSerialNumber()))
print("  BNGetProductType()     =", repr(core.BNGetProductType()))

print("\n=== 调用 BNInitPlugins(True) ===")
try:
    r = core.BNInitPlugins(True)
    print("  BNInitPlugins(True) =", r)
except Exception as e:
    print("  BNInitPlugins 异常:", repr(e))

print("\n=== 调用后 ===")
print("  BNIsLicenseValidated() =", core.BNIsLicenseValidated())
print("  BNGetSerialNumber()    =", repr(core.BNGetSerialNumber()))
print("  BNGetProductType()     =", repr(core.BNGetProductType()))
print("  BNGetLicenseExpirationTime() =", core.BNGetLicenseExpirationTime())

print("\n=== bn._init_plugins() ===")
try:
    bn._init_plugins()
    print("  [OK] 通过，_plugin_init =", bn._plugin_init)
except Exception as e:
    print("  [X] 抛异常:", repr(e))
