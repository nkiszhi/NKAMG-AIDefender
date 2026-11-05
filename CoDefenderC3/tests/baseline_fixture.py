# -*- coding: utf-8 -*-
"""BN 基线特征快照（golden fixture）—— 采集 / 校验工具。

为什么需要它
────────────
Phase 1（IR 抽象）会把「BinaryNinja → 特征」这条链路重构一遍。重构后必须能证明
**在仍然是 BN 后端时，特征逐位不变** —— 否则无法区分「重构引入的 bug」和
「后端换了导致的分布漂移」。本工具就是那个判据。

它做什么
────────
· select  : 从样本池里**确定性**地挑一批样本（分层：标签 × 32/64 位），
            记录元数据（sha256 / 位数 / 节数 / 导入数 / 熵 / 疑似加壳）
· capture : 对每个样本跑**真实生产路径**（extract_fast + extract_de_only），
            为每个特征向量算 sha256 指纹 → manifest.json
· verify  : 重跑一遍并与 manifest 逐位比对 → 回归门禁

为什么用指纹而不是直接存数组
────────────────────────────────
B01 = 2MB 字节流、F01/F02/F04 = 256²~768² 图像，单样本全量数组约 10 MB，
100 个样本 = 1 GB，不可能进版本库。指纹（sha256 of 原始字节）是**逐位相等**的判据，
体积只有几十字节。需要看具体数值时，用 --arrays 把全量数组导到仓库外。

跑法
────
# ① 选样本（任意 python 均可，不需要 BN）
python tests/baseline_fixture.py select --out tests/fixtures/bn_baseline/samples.json

# ② 采集（需要 BinaryNinja；BN 自带 python 无 numpy 时用 --pkgs 指定）
"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests/baseline_fixture.py \
    capture --samples tests/fixtures/bn_baseline/samples.json \
             --out tests/fixtures/bn_baseline/manifest.json

# ③ 校验（回归门禁）
python tests/baseline_fixture.py verify --samples tests/fixtures/bn_baseline/samples.json \
                                        --manifest tests/fixtures/bn_baseline/manifest.json

2026-11-05
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)


def _pkg_dirs(explicit=None):
    """可能存放 numpy / pefile 的目录（BN 自带 python 没有 numpy）。"""
    cands = []
    if explicit:
        cands.append(explicit)
    env = os.environ.get("CODEFENDER_PY310_PKGS")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.dirname(REPO), "_tools", "py310_pkgs"))
    cands.append(os.path.join(REPO, "_tools", "py310_pkgs"))
    return cands


def _ensure_deps(explicit=None):
    """把 numpy / pefile 补齐（不污染 BN 的安装目录）。"""
    missing = []
    for mod in ("numpy", "pefile"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        return
    for cand in _pkg_dirs(explicit):
        if not os.path.isdir(cand):
            continue
        hits = [m for m in missing
                if os.path.exists(os.path.join(cand, m + ".py"))
                or os.path.isdir(os.path.join(cand, m))]
        if hits:
            sys.path.insert(0, cand)
            print("[deps] 从 %s 补齐: %s" % (cand, ", ".join(hits)))
            missing = [m for m in missing if m not in hits]
        if not missing:
            break
    if missing:
        raise ImportError("缺少依赖: %s（用 --pkgs 指定目录）" % ", ".join(missing))


DEFAULT_POOLS = [
    (r"E:\nkproject\00 样本库\00 原始旧样本-2024恶意\2024", "malicious"),
    (r"E:\nkproject\00 样本库\01 白样本\benign_samples_20260909_110353_f41761f0\samples", "benign"),
    (r"E:\nkproject\01 测试集\测试集\benign", "benign"),
    (r"E:\nkproject\01 测试集\测试集\malicious\2024", "malicious"),
]

PE_EXTS = (".exe", ".dll", ".sys", ".scr", ".cpl", ".drv", ".ocx", ".msi")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(data):
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log(p, 2)
    return e


def pe_meta(path):
    """轻量 PE 元数据：位数 / 节数 / 导入数 / 熵 / 疑似加壳。"""
    import pefile
    info = {"size": os.path.getsize(path), "sha256": None}
    try:
        raw = open(path, "rb").read()
        info["sha256"] = hashlib.sha256(raw).hexdigest()
        pe = pefile.PE(data=raw, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        machine = pe.FILE_HEADER.Machine
        info["bitness"] = 64 if machine == 0x8664 else (32 if machine == 0x14C else 0)
        info["machine"] = hex(machine)
        secs = list(pe.sections)
        info["n_sections"] = len(secs)
        max_ent = 0.0
        for s in secs:
            try:
                e = _entropy(s.get_data()[:65536])
                max_ent = max(max_ent, e)
            except Exception:
                pass
        info["max_entropy"] = round(max_ent, 3)
        n_dll = 0
        n_func = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            n_dll += 1
            n_func += len(entry.imports)
        info["n_import_dll"] = n_dll
        info["n_import_func"] = n_func
        overlay = 0
        try:
            off = pe.get_overlay_data_start_offset()
            if off:
                overlay = max(0, len(raw) - off)
        except Exception:
            pass
        info["overlay_ratio"] = round(overlay / max(len(raw), 1), 4)
        packed = False
        if n_func <= 2:
            packed = True
        if max_ent >= 7.2 and n_func <= 12:
            packed = True
        if info["overlay_ratio"] >= 0.10:
            packed = True
        info["packed_hint"] = bool(packed)
        pe.close()
    except Exception as e:
        info["error"] = "%s: %s" % (type(e).__name__, e)
    return info


def _iter_pool_files(pool_dir, limit_scan):
    """列出候选 PE 文件（按文件名排序，确定性）。"""
    out = []
    try:
        names = sorted(os.listdir(pool_dir))
    except Exception:
        return out
    for n in names:
        p = os.path.join(pool_dir, n)
        if not os.path.isfile(p):
            continue
        if not (n.lower().endswith(PE_EXTS) or "." not in n):
            continue
        out.append(p)
        if len(out) >= limit_scan:
            break
    return out



def _load_extractor():
    """按文件路径加载 extract_feature —— 跳过 feature_extraction/__init__.py
    （它会 import torch，而 BN 自带的 python 没有 torch）。
    与 train/data_loader.py::_extract_fast_chunk 的加载方式一致。
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "extract_feature", os.path.join(REPO, "feature_extraction", "extract_feature.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["extract_feature"] = mod
    spec.loader.exec_module(mod)
    return mod.BinjaExtractor

def _bn_functional_probe(ext, sample_path=None):
    """**功能性**探测 BN 能不能用：能不能真的创建 BinaryView。

    不要只看 bn.core_license_count() —— 它在许可过期时也会先变成 1 再失败，
    极具误导性。唯一可信的判据是「能否开出一个 view」。
    """
    try:
        import binaryninja as bn
    except Exception as e:
        return {"usable": False, "reason": "无法 import binaryninja: %s" % e}
    if not sample_path or not os.path.isfile(sample_path):
        return {"usable": None, "reason": "没有可探测的样本"}
    try:
        bv = bn.load(sample_path)
        if bv is None:
            return {"usable": False, "reason": "bn.load 返回 None（许可无效时常见）"}
        try:
            bv.update_analysis_and_wait()
            n = len(list(bv.functions))
        finally:
            try:
                bv.file.close()
            except Exception:
                pass
        return {"usable": True, "functions": n}
    except Exception as e:
        return {"usable": False, "reason": "%s: %s" % (type(e).__name__, e)}
def cmd_select(args):
    _ensure_deps(args.pkgs)
    pools = DEFAULT_POOLS
    if args.pools:
        pools = []
        for spec in args.pools.split(";"):
            d, _, lab = spec.rpartition("=")
            pools.append((d, lab or "unknown"))
    per = args.per_stratum
    candidates = []
    for pool_dir, label in pools:
        files = _iter_pool_files(pool_dir, args.scan_limit)
        if not files:
            print("[select] 池为空或不存在: %s" % pool_dir)
            continue
        step = max(1, len(files) // max(1, args.candidates_per_pool))
        picked = files[::step][:args.candidates_per_pool]
        print("[select] 池 %s (%s): 候选 %d / 共 %d" % (os.path.basename(pool_dir), label, len(picked), len(files)))
        for p in picked:
            m = pe_meta(p)
            if m.get("bitness") in (32, 64):
                m.update({"path": p, "label": label})
                candidates.append(m)
    strata = {}
    for c in candidates:
        strata.setdefault((c["label"], c["bitness"]), []).append(c)
    chosen = []
    for key in sorted(strata):
        group = sorted(strata[key], key=lambda c: c["sha256"])
        take = group[:per]
        print("[select]   层 %s/%d位: 可选 %d -> 取 %d" % (key[0], key[1], len(group), len(take)))
        chosen.extend(take)
    doc = {
        "schema": "codefender-bn-baseline-samples/1",
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pools": [{"dir": d, "label": l} for d, l in pools],
        "per_stratum": per,
        "samples": chosen,
    }
    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    n_packed = sum(1 for c in chosen if c.get("packed_hint"))
    print("[select] 写入 %s：%d 个样本（疑似加壳 %d）" % (out, len(chosen), n_packed))
    return 0


def _fingerprint(arr):
    """特征向量的指纹：sha256(原始字节) 是逐位相等的判据。"""
    import numpy as np
    a = np.ascontiguousarray(arr)
    b = a.tobytes()
    return {
        "dim": int(a.size),
        "dtype": str(a.dtype),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sum": round(float(a.sum()), 6),
        "nz": int(np.count_nonzero(a)),
    }


def _extract_all(pe_path, ext):
    """跑真实生产路径：extract_fast（无 BN）+ extract_de_only（BN）。"""
    feats = {}
    errs = {}
    try:
        feats.update(ext.extract_fast(pe_path))
    except Exception as e:
        errs["fast"] = "%s: %s" % (type(e).__name__, e)
    try:
        feats.update(ext.extract_de_only(pe_path))
    except Exception as e:
        errs["de"] = "%s: %s" % (type(e).__name__, e)
    return feats, errs


def _activate_license(path=None):
    """激活 BinaryNinja 许可。

    BN 不会自动读 license.dat —— 必须显式 bn.core_set_license(raw)，
    这也是 start_codefender.sh 里做的事（容器里 license.txt 被 COPY 到
    ~/.binaryninja/license.dat，start 脚本再调 core_set_license）。

    许可无效时 BN 不会抛错，只是静默不生效（core_license_count() 仍为 0），
    随后创建 BinaryView 会失败。故这里把结果显式报出来。
    """
    try:
        import binaryninja as bn
    except Exception:
        return {"available": False, "reason": "无法 import binaryninja"}
    cands = []
    if path:
        cands.append(path)
    env = os.environ.get("CODEFENDER_BN_LICENSE")
    if env:
        cands.append(env)
    cands.append(os.path.join(os.path.expanduser("~"), "AppData", "Roaming",
                              "Binary Ninja", "license.dat"))
    cands.append(os.path.join(REPO, "license.txt"))
    tried = []
    for c in cands:
        if not c or not os.path.isfile(c):
            tried.append("%s (不存在)" % c)
            continue
        tried.append(c)
        try:
            with open(c, "r", encoding="utf-8") as f:
                raw = f.read()
            bn.core_set_license(raw)
        except Exception as e:
            tried.append("%s (激活异常 %s)" % (c, e))
            continue
        n = 0
        try:
            n = bn.core_license_count()
        except Exception:
            pass
        if n:
            return {"available": True, "source": c, "license_count": n,
                    "serial": bn.core_serial(), "tried": tried}
        tried.append("%s (BN 未接受：许可无效或已过期)" % c)
    return {"available": False, "reason": "没有可用的许可", "tried": tried}


def _env_info(license=None, probe_path=None):
    info = {"python": sys.version.split()[0], "platform": platform.platform()}
    try:
        import numpy
        info["numpy"] = numpy.__version__
    except Exception:
        info["numpy"] = None
    try:
        import binaryninja
        info["binaryninja"] = binaryninja.core_version()
    except Exception:
        info["binaryninja"] = None
    lic = _activate_license(license)
    info["bn_license"] = lic
    info["bn_licensed"] = bool(lic.get("available"))
    if probe_path:
        probe = _bn_functional_probe(None, probe_path)
        info["bn_functional"] = probe
        info["bn_usable"] = probe.get("usable")
    return info


def cmd_capture(args):
    _ensure_deps(args.pkgs)
    _lic = _activate_license(args.license)
    if _lic.get("available"):
        print("[bn] 许可已载入: %s (serial=%s)" % (_lic.get("source"), _lic.get("serial")))
        print("     注意：license_count 不可信，仍需确认能否创建 BinaryView")
    else:
        print("[bn] 警告: BinaryNinja 无有效许可 → D/E 视角无法采集")
        print("     原因: %s" % _lic.get("reason"))
        for x in _lic.get("tried", []):
            print("       - %s" % x)
    import numpy as np
    BinjaExtractor = _load_extractor()
    with open(args.samples, "r", encoding="utf-8") as f:
        doc = json.load(f)
    samples = doc["samples"]
    ext = BinjaExtractor()
    entries = []
    t0 = time.time()
    for i, s in enumerate(samples, 1):
        p = s["path"]
        rec = {
            "id": (s.get("sha256") or "")[:16],
            "path": p,
            "label": s.get("label"),
            "bitness": s.get("bitness"),
            "packed_hint": s.get("packed_hint"),
            "file_sha256": s.get("sha256"),
            "features": {},
            "errors": {},
        }
        if not os.path.isfile(p):
            rec["errors"]["missing"] = "样本文件不存在"
            entries.append(rec)
            print("[capture] %3d/%d %s  !! 样本不存在" % (i, len(samples), os.path.basename(p)))
            continue
        feats, errs = _extract_all(p, ext)
        rec["errors"] = errs
        for fid in sorted(feats):
            try:
                rec["features"][fid] = _fingerprint(feats[fid])
            except Exception as e:
                rec["errors"]["fp:" + fid] = "%s: %s" % (type(e).__name__, e)
        if args.arrays:
            adir = os.path.join(os.path.abspath(args.arrays), rec["id"] + ".npz")
            try:
                os.makedirs(os.path.dirname(adir), exist_ok=True)
                np.savez_compressed(adir, **feats)
                rec["arrays_file"] = adir
            except Exception as e:
                rec["errors"]["arrays"] = "%s: %s" % (type(e).__name__, e)
        entries.append(rec)
        el = time.time() - t0
        print("[capture] %3d/%d %-16s %-8s %dbit nfeat=%2d  %.1fs" % (
            i, len(samples), os.path.basename(p)[:16], s.get("label"),
            s.get("bitness"), len(rec["features"]), el))
    man = {
        "schema": "codefender-bn-baseline/1",
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "env": _env_info(args.license, samples[0]["path"] if samples else None),
        "samples_source": os.path.abspath(args.samples),
        "samples": entries,
    }
    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)
    tot = sum(len(e["features"]) for e in entries)
    print("[capture] 写入 %s：%d 样本 / %d 特征指纹，用时 %.1fs" % (out, len(entries), tot, time.time() - t0))
    if args.require_de:
        de_ok = sum(1 for e in entries if any(k.startswith("D") or k.startswith("E")
                                            for k in e["features"]))
        if de_ok < len(entries):
            print("[capture] 失败：--require-de 要求每个样本都有 D/E 特征，实际 %d/%d"
                  % (de_ok, len(entries)))
            print("         常见原因：BinaryNinja 许可无效 → 无法创建 BinaryView")
            return 2
        print("[capture] D/E 视角齐备：%d/%d" % (de_ok, len(entries)))
    return 0


def cmd_verify(args):
    _ensure_deps(args.pkgs)
    _activate_license(args.license)
    BinjaExtractor = _load_extractor()
    with open(args.manifest, "r", encoding="utf-8") as f:
        man = json.load(f)
    ext = BinjaExtractor()
    n_feat = 0
    n_bad = 0
    bad_samples = 0
    for i, e in enumerate(man["samples"], 1):
        p = e["path"]
        if not os.path.isfile(p):
            print("[verify] %3d/%d !! 样本不存在: %s" % (i, len(man["samples"]), p))
            bad_samples += 1
            continue
        feats, errs = _extract_all(p, ext)
        diffs = []
        for fid, ref in e["features"].items():
            n_feat += 1
            if fid not in feats:
                diffs.append((fid, "缺失"))
                continue
            try:
                cur = _fingerprint(feats[fid])
            except Exception as ex:
                diffs.append((fid, "指纹失败 %s" % ex))
                continue
            if cur["sha256"] != ref["sha256"]:
                diffs.append((fid, "sha256 不一致"))
            elif cur["dim"] != ref["dim"] or cur["dtype"] != ref["dtype"]:
                diffs.append((fid, "维度/dtype 不一致"))
        extra = [fid for fid in feats if fid not in e["features"]]
        if diffs or extra:
            bad_samples += 1
            n_bad += len(diffs) + len(extra)
            print("[verify] %3d/%d FAIL %s" % (i, len(man["samples"]), os.path.basename(p)[:20]))
            for fid, why in diffs:
                print("           - %s: %s" % (fid, why))
            for fid in extra:
                print("           + %s: 基线中不存在" % fid)
        else:
            print("[verify] %3d/%d OK   %s" % (i, len(man["samples"]), os.path.basename(p)[:20]))
    print("")
    print("本次环境: %s" % json.dumps(_env_info(), ensure_ascii=False))
    print("基线环境: %s" % json.dumps(man.get("env"), ensure_ascii=False))
    print("样本 %d 个，其中 %d 个有差异；共比对 %d 个特征，差异 %d 个"
          % (len(man["samples"]), bad_samples, n_feat, n_bad))
    if bad_samples:
        print("结论: FAIL 特征未逐位不变（Phase 1 的验收不通过）")
        return 1
    print("结论: OK 特征逐位不变")
    return 0


def main():
    ap = argparse.ArgumentParser(description="BN 基线特征快照（golden fixture）")
    sub = ap.add_subparsers(dest="cmd")
    ps = sub.add_parser("select", help="确定性分层选样本")
    ps.add_argument("--out", required=True)
    ps.add_argument("--pools", default=None, help="目录=标签;目录=标签")
    ps.add_argument("--per-stratum", type=int, default=25)
    ps.add_argument("--candidates-per-pool", type=int, default=120)
    ps.add_argument("--scan-limit", type=int, default=20000)
    ps.add_argument("--pkgs", default=None, help="numpy/pefile 所在目录")
    ps.set_defaults(func=cmd_select)
    pc = sub.add_parser("capture", help="采集特征指纹")
    pc.add_argument("--samples", required=True)
    pc.add_argument("--out", required=True)
    pc.add_argument("--arrays", default=None, help="全量数组输出目录（建议放仓库外）")
    pc.add_argument("--pkgs", default=None, help="numpy/pefile 所在目录")
    pc.add_argument("--license", default=None, help="BN 许可文件（默认自动找）")
    pc.add_argument("--require-de", action="store_true",
                    help="要求 D/E 视角必须采集成功（BN 不可用时直接失败，用于 CI 门禁）")
    pc.set_defaults(func=cmd_capture)
    pv = sub.add_parser("verify", help="校验特征是否逐位不变")
    pv.add_argument("--samples", required=True)
    pv.add_argument("--manifest", required=True)
    pv.add_argument("--pkgs", default=None)
    pv.add_argument("--license", default=None, help="BN 许可文件（默认自动找）")
    pv.set_defaults(func=cmd_verify)
    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
