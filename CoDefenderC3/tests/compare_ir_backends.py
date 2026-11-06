# -*- coding: utf-8 -*-
"""跨后端 IR 对比：BN-IR vs SMDA-IR。

Phase 2 的验收工具。回答两个问题：

1. 字段级：两个后端发现的函数/块/指令/调用边差多少？（后端差异的规模）
2. 特征级：把两份 IR 分别喂给同一个特征层，D01-D07/E03-E04 的差异如何？
   （哪些特征对后端敏感 → Phase 7 指标对比时要重点看的）

跑法（BN 与 SMDA 分开进程跑，互不干扰）:

# ① BN-IR（需要 BinaryNinja + 联网；用 bnpython3 跑）
"C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" tests\\compare_ir_backends.py bn \\
    --pe a.exe --pe b.exe --out-dir _ir_bn

# ② SMDA-IR（普通 python 即可，不需要网络）
python tests/compare_ir_backends.py smda --pe a.exe --pe b.exe --out-dir _ir_smda

# ③ 对比（任一 python）
python tests/compare_ir_backends.py compare --bn-dir _ir_bn --smda-dir _ir_smda

2026-11-07
"""
import argparse
import hashlib
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FE_DIR = os.path.join(REPO, "feature_extraction")
if FE_DIR not in sys.path:
    sys.path.insert(0, FE_DIR)


def _ensure_pkgs():
    """按解释器版本补齐 numpy/pefile（BN 自带 python 没有 numpy）。"""
    try:
        import numpy  # noqa: F401
        return
    except ImportError:
        pass
    here = os.path.dirname(REPO)
    ver = "%d%d" % sys.version_info[:2]
    cands = []
    env = os.environ.get("CODEFENDER_PY310_PKGS")
    if env:
        cands.append(env)
    cands.append(os.path.join(here, "_tools", "py%s_pkgs" % ver))
    cands.append(os.path.join(here, "_tools", "py310_pkgs"))
    for c in cands:
        if os.path.isdir(os.path.join(c, "numpy")):
            sys.path.insert(0, c)
            print("[deps] numpy from %s" % c)
            return
    raise ImportError("numpy 缺失")


def _ir_path(out_dir, pe_path):
    h = hashlib.md5(os.path.abspath(pe_path).encode()).hexdigest()
    return os.path.join(out_dir, h + ".ir.json.gz")


def cmd_bn(args):
    _ensure_pkgs()
    import backend_bn
    os.makedirs(args.out_dir, exist_ok=True)
    for pe in args.pe:
        print("[bn] %s" % pe, flush=True)
        ir = backend_bn.build_ir_from_path(pe)
        p = _ir_path(args.out_dir, pe)
        ir.save(p)
        print("[bn]   -> %s  funcs=%d blocks=%d ins=%d" % (
            os.path.basename(p), ir.n_functions, ir.n_blocks, ir.n_instructions), flush=True)
    return 0


def cmd_smda(args):
    _ensure_pkgs()
    import backend_smda
    os.makedirs(args.out_dir, exist_ok=True)
    for pe in args.pe:
        print("[smda] %s" % pe, flush=True)
        ir = backend_smda.build_ir(pe, backend=args.backend)
        p = _ir_path(args.out_dir, pe)
        ir.save(p)
        print("[smda]   -> %s  funcs=%d blocks=%d ins=%d" % (
            os.path.basename(p), ir.n_functions, ir.n_blocks, ir.n_instructions), flush=True)
    return 0


def _load_all(d):
    from ir import ProgramIR
    out = {}
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".ir.json.gz"):
            out[fn] = ProgramIR.load(os.path.join(d, fn))
    return out


def cmd_compare(args):
    _ensure_pkgs()
    import numpy as np
    from features_from_ir import all_features
    bn = _load_all(args.bn_dir)
    smda = _load_all(args.smda_dir)
    common = sorted(set(bn) & set(smda))
    print("BN-IR %d 份, SMDA-IR %d 份, 可比 %d 份" % (len(bn), len(smda), len(common)))
    if not common:
        print("没有可比样本")
        return 2
    agg = {}
    for k in common:
        a, b = bn[k], smda[k]
        fa, fb = all_features(a), all_features(b)
        row = {"funcs": (a.n_functions, b.n_functions),
               "blocks": (a.n_blocks, b.n_blocks),
               "insns": (a.n_instructions, b.n_instructions),
               "addr_overlap": len(set(f.start for f in a.functions) & set(f.start for f in b.functions)),
               "feat_diff": []}
        for fid in sorted(set(fa) | set(fb)):
            if fid not in fa or fid not in fb:
                row["feat_diff"].append((fid, "缺失"))
                continue
            ha = hashlib.sha256(np.ascontiguousarray(fa[fid]).tobytes()).hexdigest()
            hb = hashlib.sha256(np.ascontiguousarray(fb[fid]).tobytes()).hexdigest()
            if ha != hb:
                x = np.asarray(fa[fid], dtype=np.float64).ravel()
                y = np.asarray(fb[fid], dtype=np.float64).ravel()
                na, nb = np.linalg.norm(x), np.linalg.norm(y)
                cos = float(x.dot(y) / (na * nb)) if na and nb else 0.0
                den = max(np.abs(x).sum(), np.abs(y).sum(), 1e-12)
                l1 = float(np.abs(x - y).sum() / den)
                row["feat_diff"].append((fid, "cos=%.4f l1=%.4f" % (cos, l1)))
        agg[k] = row
    print("")
    print("=== 字段级对比 (BN vs SMDA) ===")
    print("%-34s %15s %15s %15s %10s" % ("样本", "函数数", "基本块数", "指令数", "地址重合"))
    for k in common:
        r = agg[k]
        print("%-34s %6d/%-7d %6d/%-7d %6d/%-7d %6d/%d" % (
            os.path.basename(k)[:34], r["funcs"][0], r["funcs"][1],
            r["blocks"][0], r["blocks"][1], r["insns"][0], r["insns"][1],
            r["addr_overlap"], max(r["funcs"][0], 1)))
    tot_f = sum(agg[k]["funcs"][0] for k in common)
    tot_s = sum(agg[k]["funcs"][1] for k in common)
    tot_ov = sum(agg[k]["addr_overlap"] for k in common)
    print("")
    print("合计: 函数 %d (BN) vs %d (SMDA); 函数起始地址重合 %d (%.1f%% of BN)"
          % (tot_f, tot_s, tot_ov, 100.0 * tot_ov / max(tot_f, 1)))
    print("")
    print("=== 特征级对比 (同一特征层喂两份 IR) ===")
    diff_count = {}
    same_count = {}
    cos_sum = {}
    for k in common:
        diff_ids = set(x[0] for x in agg[k]["feat_diff"])
        for fid, why in agg[k]["feat_diff"]:
            diff_count[fid] = diff_count.get(fid, 0) + 1
            if why.startswith("cos="):
                cos_sum.setdefault(fid, []).append(float(why.split()[0].split("=")[1]))
        for fid in all_features(bn[k]):
            if fid not in diff_ids:
                same_count[fid] = same_count.get(fid, 0) + 1
    print("%-8s %12s %12s %12s" % ("特征", "不一致", "完全一致", "平均余弦"))
    for fid in sorted(set(list(diff_count) + list(same_count))):
        cs = cos_sum.get(fid) or []
        avg = sum(cs) / len(cs) if cs else None
        print("%-8s %8d/%-3d %9d/%-3d %12s" % (fid, diff_count.get(fid, 0), len(common),
                                              same_count.get(fid, 0), len(common),
                                              ("%.4f" % avg) if cs else "-"))
    print("")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    pb = sub.add_parser("bn", help="生成 BN-IR")
    pb.add_argument("--pe", action="append", required=True)
    pb.add_argument("--out-dir", required=True)
    pb.set_defaults(func=cmd_bn)
    ps = sub.add_parser("smda", help="生成 SMDA-IR")
    ps.add_argument("--pe", action="append", required=True)
    ps.add_argument("--out-dir", required=True)
    ps.add_argument("--backend", default="intel")
    ps.set_defaults(func=cmd_smda)
    pc = sub.add_parser("compare", help="字段级 + 特征级对比")
    pc.add_argument("--bn-dir", required=True)
    pc.add_argument("--smda-dir", required=True)
    pc.set_defaults(func=cmd_compare)
    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
