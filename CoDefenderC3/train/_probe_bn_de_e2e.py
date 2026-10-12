# -*- coding: utf-8 -*-
"""
探针: 端到端验证 BinaryNinja 能否产出项目所需的 D/E 视角特征。

D01-D07 (V6_opcode_seq/stat/embed) + E01-E04 (V7_graph) 都需要 BN 反汇编，
这 11 个视角喂 9 个模型（D01-D07、E01-E04）。本探针用项目自己的
BinjaExtractor.extract_de_only() 跑真实 PE，核对 key 与维度。

用法（必须用 BN 自带解释器）:
  "C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" train/_probe_bn_de_e2e.py [PE目录或PE路径]
"""
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, REPO)

DEFAULT_DIR = r"D:\nkproject\data_test\20260928"

# 期望的 D/E 视角 key 数目（11 个）
EXPECT_DE_PREFIX = ("D", "E")


def main(argv):
    target = argv[1] if len(argv) > 1 else DEFAULT_DIR
    pcs = []
    if os.path.isfile(target):
        pcs = [target]
    else:
        for sub in ("benign", "malicious"):
            d = os.path.join(target, sub)
            if not os.path.isdir(d):
                d = target
            if not os.path.isdir(d):
                continue
            for fn in sorted(os.listdir(d)):
                p = os.path.join(d, fn)
                if os.path.isfile(p) and os.path.getsize(p) > 4096:
                    pcs.append(p)
            if pcs:
                break
    pcs = pcs[:3]
    if not pcs:
        print("[X] 没找到可测样本: %s" % target)
        return 1

    from feature_extraction.extract_feature import BinjaExtractor

    ext = BinjaExtractor(headless=True, require_bn=True)
    print("样本数: %d\n" % len(pcs))
    fails = 0
    for i, pe in enumerate(pcs, 1):
        sz = os.path.getsize(pe)
        print("[%d] %s (%.1f KB)" % (i, os.path.basename(pe)[:48], sz / 1024.0))
        t0 = time.time()
        try:
            feats = ext.extract_de_only(pe)
        except Exception as e:
            print("    [X] extract_de_only 异常: %r" % (e,))
            fails += 1
            continue
        dt = time.time() - t0
        if not feats:
            print("    [X] 返回空 dict（BN 不可用或样本无法分析）")
            fails += 1
            continue
        keys = sorted(feats.keys())
        de_keys = [k for k in keys if k[0] in EXPECT_DE_PREFIX]
        print("    [OK] %.2fs  视角数=%d  D/E 视角数=%d" % (dt, len(keys), len(de_keys)))
        total = 0
        for k in keys:
            import numpy as np
            a = np.asarray(feats[k])
            total += a.size
            print("        %-22s shape=%-16s dtype=%s" % (k, str(a.shape), a.dtype))
        print("        参数总量 = %d" % total)
    print()
    if fails:
        print("[X] %d/%d 样本 D/E 提取失败" % (fails, len(pcs)))
        return 1
    print("[OK] 全部样本 D/E 提取成功 —— BinaryNinja 在本机可用于训练/推理")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
