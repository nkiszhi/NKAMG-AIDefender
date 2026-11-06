# -*- coding: utf-8 -*-
import sys, os, gc, io, zipfile

# Windows: 禁止 segfault 弹出「应用程序错误」对话框
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x0002 | 0x8000)
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _ensure_numpy():
    """worker 是全新解释器, 不继承父进程的 sys.path —— numpy 可能不在。

    BN 自带的 python 没有 numpy; 这里从 CODEFENDER_PY310_PKGS 指定的目录补齐。
    """
    try:
        import numpy  # noqa: F401
        return
    except ImportError:
        pass
    cands = []
    env = os.environ.get("CODEFENDER_PY310_PKGS")
    if env:
        cands.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(os.path.dirname(os.path.dirname(here)), "_tools", "py310_pkgs"))
    for c in cands:
        if os.path.isdir(c) and os.path.exists(os.path.join(c, "numpy")):
            sys.path.insert(0, c)
            return
    raise ImportError("numpy 缺失: 用 CODEFENDER_PY310_PKGS 指定目录")


_ensure_numpy()

import numpy as np
from ir import ProgramIR
from features_from_ir import all_features


def append_to_npz(npz_path, arrays):
    with zipfile.ZipFile(npz_path, "a", zipfile.ZIP_STORED) as zf:
        existing = set(zf.namelist())
        for key, arr in arrays.items():
            fname = key + ".npy"
            if fname in existing:
                continue
            buf = io.BytesIO()
            np.save(buf, arr)
            zf.writestr(fname, buf.getvalue())


sys.stdout.write("READY\n")
sys.stdout.flush()

n_done = 0
for raw_line in sys.stdin:
    line = raw_line.strip()
    if not line or line == "EXIT":
        break
    parts = line.split("\t")
    if len(parts) != 3:
        sys.stdout.write("FAIL\t\tinvalid_input\n")
        sys.stdout.flush()
        continue
    pe_path, ir_path, npz_path = parts
    try:
        ir = ProgramIR.load(ir_path)
        feats = all_features(ir)
        if feats:
            append_to_npz(npz_path, feats)
            del feats
            sys.stdout.write("OK\t" + pe_path + "\n")
        else:
            sys.stdout.write("FAIL\t" + pe_path + "\tempty_feats\n")
        sys.stdout.flush()
    except Exception as e:
        sys.stdout.write("FAIL\t" + pe_path + "\t" + str(e)[:120] + "\n")
        sys.stdout.flush()
    n_done += 1
    if n_done % 20 == 0:
        gc.collect()
