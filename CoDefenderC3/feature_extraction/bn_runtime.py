# -*- coding: utf-8 -*-
"""BinaryNinja 运行时引导（路径注入 + 许可激活）。

为什么需要它
------------
* BN 的 Python 绑定是纯 ctypes（binaryninja/_binaryninjacore.py 用
  ctypes.CDLL 加载 binaryninjacore.dll，没有 .pyd），但**仍然要求 BN 安装
  目录下的 python/ 在 sys.path 上**，否则 import binaryninja 直接失败。
* BN **不会自动读** license.dat，必须显式 bn.core_set_license(raw)；
  没激活 → bn.load() 抛 C++ 异常（Windows Error 0xe06d7363）。
* BN 的许可**在线校验需要联网**（vector35.com:443）；断网时同样表现为
  "Unable to create new BinaryView"，但许可本身是好的 —— 别误判成许可过期。

本模块只做"让 import binaryninja 能用"，**不判断许可是否真的生效**
（唯一可信判据是能否真的开出一个 BinaryView）。

2026-11-07
"""
from __future__ import annotations

import os
import sys


def _bn_python_candidates():
    """BN python 包目录候选。"""
    cands = []
    env = os.environ.get("CODEFENDER_BN_PYTHON_DIR")
    if env:
        cands.append(env)
    pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
    cands.append(os.path.join(pf, "Vector35", "BinaryNinja", "python"))
    cands.append(r"/opt/binaryninja/python")
    cands.append(r"/usr/lib/binaryninja/python")
    cands.append(r"/usr/local/lib/binaryninja/python")
    extra = []
    for base in list(cands):
        root = os.path.dirname(base)
        if os.path.isdir(root):
            try:
                for name in os.listdir(root):
                    if name.lower().startswith("python"):
                        extra.append(os.path.join(root, name))
            except OSError:
                pass
    cands.extend(extra)
    return cands


def _license_candidates():
    """BN 许可文件候选（按优先级）。"""
    cands = []
    env = os.environ.get("CODEFENDER_BN_LICENSE")
    if env:
        cands.append(env)
    home = os.path.expanduser("~")
    cands.append(os.path.join(home, ".binaryninja", "license.dat"))
    cands.append(os.path.join(home, "AppData", "Roaming", "Binary Ninja",
                              "license.dat"))
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands.append(os.path.join(repo, "license.txt"))
    cands.append("/root/.binaryninja/license.dat")
    return cands


def ensure_binaryninja():
    """返回可用的 binaryninja 模块（已完成路径注入 + 许可提交）。

    失败抛 RuntimeError（消息里带上探测过的路径，便于定位）。
    """
    try:
        import binaryninja as bn
        return bn
    except ImportError:
        pass

    # ① 若仓库里已有 bn_bootstrap（更完整的实现），优先用它
    try:
        try:
            from .bn_bootstrap import bootstrap_bn
        except ImportError:
            from bn_bootstrap import bootstrap_bn
        return bootstrap_bn()
    except Exception:
        pass

    # ② 自带兜底：路径注入 + 许可提交
    tried = []
    for d in _bn_python_candidates():
        if not d:
            continue
        d = os.path.abspath(d)
        tried.append(d)
        if os.path.isfile(os.path.join(d, "binaryninja", "__init__.py")):
            if d not in sys.path:
                sys.path.insert(0, d)
            break
    try:
        import binaryninja as bn
    except ImportError as exc:
        raise RuntimeError("无法 import binaryninja（%s）。探测过的目录: %s"
                           % (exc, tried)) from exc
    for path in _license_candidates():
        try:
            if not path or not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
            bn.core_set_license(raw)
        except Exception:
            continue
    return bn
