# -*- coding: utf-8 -*-
"""MalGraph 训练产物重建（SMDA 后端）。

一次跑完三件事：

1. **作废**旧产物（BN 时代的 features.jsonl / 词表 / .pt / 权重）
2. 用 **SMDA** 重新抽取图特征（多进程），产出 features.jsonl
3. 用 SMDA 的导入名**重建外部函数词表**（带指纹），并转成 .pt

为什么必须重建（而不是直接复用 BN 时代的产物）
------------------------------------------------
* 函数集合变了：BN 的线性扫描会把数据区也扫成函数（实测 16 个样本里
  BN 12032 个函数里只有 2792 个"带正常序言"的，SMDA 10269 个里有 2836 个
  —— SMDA 找到的**真函数**反而更多），
* FCG 边变了：BN 的 MLIL_IMPORT 分支 83% 取不到符号 → 导入调用边被丢，
* 11 维块特征变了：retn/ret 渲染差异、常量口径差异，
* 外部函数词表变了：两后端导入名集合 Jaccard 只有 0.755。

直接复用 = 权重与特征的分布完全错位，而且**不会报错**，只是分数变差。

用法
----
    python models/MalGraph_2022/rebuild_smda.py \\
        --benign-dir "E:\\...\\benign" \\
        --malicious-dir "E:\\...\\malicious" \\
        --limit-per-class 600 --workers 8

产物
----
    models/MalGraph_2022/saved/features.jsonl          图特征（中间产物）
    models/MalGraph_2022/saved/train_external_function_name_vocab.jsonl
    models/MalGraph_2022/saved/pt_files/*.pt           训练用 .pt
    models/MalGraph_2022/saved/feature_manifest.json   指纹（后端/口径/样本数）

2026-11-07
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import time
from collections import Counter
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

MALGRAPH_DIR = os.path.join(ROOT, "models", "MalGraph_2022")
SAVED_DIR = os.path.join(MALGRAPH_DIR, "saved")
PT_DIR = os.path.join(SAVED_DIR, "pt_files")
JSONL_OUT = os.path.join(SAVED_DIR, "features.jsonl")
VOCAB_OUT = os.path.join(SAVED_DIR, "train_external_function_name_vocab.jsonl")
MANIFEST_OUT = os.path.join(SAVED_DIR, "feature_manifest.json")


# ══════════════════════════════════════════════════════════════════════
# 作废旧产物
# ══════════════════════════════════════════════════════════════════════
def invalidate_old(stamp: str, keep_vocab: bool = True, verbose: bool = True):
    """把 BN 时代的 MalGraph 产物挪进 saved/_invalidated/<stamp>/。

    为什么要"挪"而不是全删：
      * 词表只有几百 KB，留着可以做新旧对比（哪些外部函数名变了）；
      * features.jsonl 有 100+ MB，删掉省空间，而且**必须删** ——
        它是旧口径的图特征，留着会被 resume 逻辑误当成"已处理"。
    """
    archive = os.path.join(SAVED_DIR, "_invalidated", stamp)
    os.makedirs(archive, exist_ok=True)
    moved = []
    removed = []

    # 1) 旧图特征（体积大且会被 resume 误用）→ 删
    for p in (JSONL_OUT, os.path.join(MALGRAPH_DIR, "output", "features.jsonl")):
        if os.path.exists(p):
            os.remove(p)
            removed.append(p)

    # 2) 旧 .pt
    if os.path.isdir(PT_DIR):
        shutil.rmtree(PT_DIR, ignore_errors=True)
        removed.append(PT_DIR)

    # 3) 旧权重
    for name in ("best_model.pt", "malgraph_best.pth"):
        p = os.path.join(SAVED_DIR, name)
        if os.path.exists(p):
            shutil.move(p, os.path.join(archive, name))
            moved.append(p)
    p = os.path.join(MALGRAPH_DIR, "malgraph_best.pth")
    if os.path.exists(p):
        shutil.move(p, os.path.join(archive, os.path.basename(p)))
        moved.append(p)

    # 4) 旧词表（留着做对比）
    if os.path.exists(VOCAB_OUT):
        dst = os.path.join(archive, "train_external_function_name_vocab.jsonl")
        if keep_vocab and not os.path.exists(dst):
            shutil.move(VOCAB_OUT, dst)
            moved.append(VOCAB_OUT)
        else:
            os.remove(VOCAB_OUT)
            removed.append(VOCAB_OUT)

    readme = os.path.join(archive, "README.md")
    with open(readme, "w", encoding="utf-8") as fw:
        fw.write(
            "# 已作废的 MalGraph 训练产物（%s）\n\n"
            "这些产物是 **BN 后端**口径下生成的，BN → SMDA 切换后输入特征"
            "（函数集合 / FCG 边 / 11 维块特征 / 外部函数词表）全部改变，"
            "**不能**继续用于推理。\n\n"
            "保留它们只是为了做新旧对比。重建命令见 "
            "`models/MalGraph_2022/rebuild_smda.py`。\n\n"
            "* 移入：%s\n* 删除：%s\n"
            % (stamp,
               ", ".join(os.path.basename(x) for x in moved) or "（无）",
               ", ".join(os.path.basename(x) for x in removed) or "（无）"))
    if verbose:
        print("[invalidate] 归档目录: %s" % archive)
        print("[invalidate] 移入 %d 个, 删除 %d 个" % (len(moved), len(removed)))
    return archive


# ══════════════════════════════════════════════════════════════════════
# 样本枚举
# ══════════════════════════════════════════════════════════════════════
def _is_pe(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            off = int.from_bytes(f.read(4), "little")
            if off <= 0 or off > 10 * 1024 * 1024:
                return False
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def list_pe_files(root: str, limit: int = 0, seed: int = 20261107):
    """递归枚举目录下的 PE 文件，确定性抽样。

    确定性很重要：同一份抽样清单要能被复现（写进 manifest）。
    """
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) == 0:
                    continue
            except OSError:
                continue
            out.append(p)
    out.sort()
    if limit and len(out) > limit:
        rnd = random.Random(seed)
        out = rnd.sample(out, limit)
        out.sort()
    return out


# ══════════════════════════════════════════════════════════════════════
# 并行提取
# ══════════════════════════════════════════════════════════════════════
def _extract_one(path: str):
    """worker：抽一个样本的图特征。返回 (ok, payload)。"""
    try:
        from models.MalGraph_2022.utils import extract_cfg_and_fcg
        counter = Counter()
        feat = extract_cfg_and_fcg(path, counter)
        if not feat:
            return (False, {"path": path, "error": "extract returned None"})
        payload = dict(feat)
        payload["path"] = path
        payload["external_names"] = sorted(counter.keys())
        return (True, payload)
    except Exception as e:
        return (False, {"path": path, "error": "%s: %s" % (type(e).__name__, e)})


def _finalize(payload: dict, label: int) -> dict:
    """去掉只用于统计的字段，落盘。"""
    out = dict(payload)
    out.pop("external_names", None)
    out["label"] = int(label)
    return out


def run_extraction(samples, workers: int, jsonl_out: str, resume: bool = True):
    """多进程抽取，边抽边写 JSONL（可断点续跑）。"""
    from concurrent.futures import ProcessPoolExecutor, as_completed

    # ⚠ 已完成的判定必须按 **路径**（JSONL 里存的是 path），不能按 hash ——
    #   hash 是文件内容的摘要，跟待处理列表里的路径对不上，
    #   会导致"续跑"把全部样本重抽一遍（之前踩过：1200 条里 642 条重复）。
    done_paths = set()
    resumed_external = Counter()
    if resume and os.path.exists(jsonl_out):
        # ⚠ 续跑时必须**重新统计外部函数名**：词表是整个训练集的聚合，
        #   只统计本次新抽的样本会让词表缺一大截（而且不会报错）。
        with open(jsonl_out, "r", encoding="utf-8") as fr:
            for line in fr:
                try:
                    obj = json.loads(line)
                    if obj.get("path"):
                        done_paths.add(os.path.normpath(obj["path"]))
                    names = obj.get("function_names") or []
                    n_local = len(obj.get("acfg_list") or [])
                    for nm in names[n_local:]:
                        resumed_external[nm] += 1
                except Exception:
                    continue

    todo = [(p, lab) for (p, lab) in samples
             if os.path.normpath(p) not in done_paths]
    print("[extract] 待处理 %d 个（已完成 %d 个）" % (len(todo), len(done_paths)))
    external_counter = Counter(resumed_external)
    if not todo:
        print("[extract] 全部已处理，沿用已有 JSONL 的词表统计（%d 个外部函数名）"
              % len(external_counter))
        return 0, 0, external_counter
    n_ok = 0
    n_fail = 0
    t0 = time.time()
    os.makedirs(os.path.dirname(jsonl_out) or ".", exist_ok=True)
    with open(jsonl_out, "a", encoding="utf-8") as fw:
        if workers <= 1:
            for (p, lab) in todo:
                ok, payload = _extract_one(p)
                if ok:
                    fw.write(json.dumps(_finalize(payload, lab), ensure_ascii=False) + "\n")
                    fw.flush()
                    external_counter.update(payload.get("external_names") or [])
                    n_ok += 1
                else:
                    n_fail += 1
                    print("[extract] FAIL %s: %s" % (os.path.basename(p), payload.get("error")))
        else:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(_extract_one, p): (p, lab) for (p, lab) in todo}
                for i, fut in enumerate(as_completed(futs), 1):
                    p, lab = futs[fut]
                    try:
                        ok, payload = fut.result()
                    except Exception as e:
                        ok, payload = False, {"path": p, "error": repr(e)}
                    if ok:
                        fw.write(json.dumps(_finalize(payload, lab), ensure_ascii=False) + "\n")
                        fw.flush()
                        external_counter.update(payload.get("external_names") or [])
                        n_ok += 1
                    else:
                        n_fail += 1
                        if n_fail <= 10:
                            print("[extract] FAIL %s: %s"
                                  % (os.path.basename(p), payload.get("error")))
                    if i % 50 == 0 or i == len(todo):
                        el = time.time() - t0
                        print("[extract] %d/%d ok=%d fail=%d %.1fs (%.2f/s)"
                              % (i, len(todo), n_ok, n_fail, el,
                                 i / max(el, 1e-6)))
    return n_ok, n_fail, external_counter


def _count_jsonl_lines(path):
    """JSONL 里的样本数（续跑时 n_ok 只统计本次新抽的，不是总数）。"""
    n = 0
    try:
        with open(path, "r", encoding="utf-8") as fr:
            for line in fr:
                if line.strip():
                    n += 1
    except Exception:
        return 0
    return n

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="用 SMDA 重建 MalGraph 的图特征 / 外部函数词表 / .pt")
    ap.add_argument("--benign-dir", action="append", default=[],
                    help="良性样本目录（可多次指定）")
    ap.add_argument("--malicious-dir", action="append", default=[],
                    help="恶意样本目录（可多次指定）")
    ap.add_argument("--limit-per-class", type=int, default=0,
                    help="每类最多取多少个（0 = 不限）")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) // 2))
    ap.add_argument("--seed", type=int, default=20261107)
    ap.add_argument("--no-invalidate", action="store_true",
                    help="不要作废旧产物")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--skip-pt", action="store_true",
                    help="只出 JSONL + 词表，不转 .pt")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dirs-file", default="",
                    help="从 JSON 文件读样本目录（避免 Windows 下带中文/空格的"
                         "路径在命令行里被 cmd 拆词）。格式："
                         '{"benign": [...], "malicious": [...]}')
    args = ap.parse_args(argv)

    if args.dirs_file:
        with open(args.dirs_file, "r", encoding="utf-8") as fr:
            spec = json.load(fr)
        args.benign_dir += list(spec.get("benign") or [])
        args.malicious_dir += list(spec.get("malicious") or [])

    if not args.benign_dir and not args.malicious_dir:
        print("至少要指定 --benign-dir 或 --malicious-dir")
        return 2

    from models.MalGraph_2022.artifact_guard import current_backend, make_fingerprint

    backend = current_backend()
    print("=" * 70)
    print("MalGraph 重建  |  后端 = %s" % backend)
    print("=" * 70)

    samples = []
    for d in args.benign_dir:
        files = list_pe_files(d, args.limit_per_class, args.seed)
        print("[scan] benign    %-58s %d 个" % (d, len(files)))
        samples += [(f, 0) for f in files]
    for d in args.malicious_dir:
        files = list_pe_files(d, args.limit_per_class, args.seed)
        print("[scan] malicious %-58s %d 个" % (d, len(files)))
        samples += [(f, 1) for f in files]
    print("[scan] 合计 %d 个样本" % len(samples))
    if args.dry_run:
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not args.no_invalidate:
        invalidate_old(stamp)

    n_ok, n_fail, external_counter = run_extraction(
        samples, args.workers, JSONL_OUT, resume=not args.no_resume)

    # ── 外部函数词表（确定性排序 + 指纹）──
    from models.MalGraph_2022.utils import save_vocab_from_train
    os.makedirs(SAVED_DIR, exist_ok=True)
    save_vocab_from_train(external_counter, SAVED_DIR)
    print("[vocab] %d 个外部函数名 → %s" % (len(external_counter), VOCAB_OUT))

    # ── .pt ──
    n_pt = 0
    if not args.skip_pt:
        from models.MalGraph_2022.Vocabulary import Vocab
        from models.MalGraph_2022.utils import parse_json_list_2_pyg_object
        os.makedirs(PT_DIR, exist_ok=True)
        vocab = Vocab(freq_file=VOCAB_OUT, max_vocab_size=10000)
        parse_json_list_2_pyg_object(jsonl_file=JSONL_OUT, output_dir=PT_DIR,
                                     vocab=vocab)
        n_pt = len([f for f in os.listdir(PT_DIR) if f.endswith(".pt")])
        print("[pt] %d 个 .pt → %s" % (n_pt, PT_DIR))

    fp = make_fingerprint(
        backend=backend,
        built_at=datetime.now().isoformat(timespec="seconds"),
        extra={
            "n_samples": _count_jsonl_lines(JSONL_OUT),
            "n_failed": n_fail,
            "n_external_names": len(external_counter),
            "n_pt": n_pt,
            "sample_limit_per_class": args.limit_per_class,
            "seed": args.seed,
            "benign_dirs": args.benign_dir,
            "malicious_dirs": args.malicious_dir,
        })
    from models.MalGraph_2022.artifact_guard import write_manifest
    write_manifest(SAVED_DIR, fp)
    print("[manifest] %s" % MANIFEST_OUT)
    print("")
    print("完成: ok=%d fail=%d 外部函数名=%d .pt=%d"
          % (n_ok, n_fail, len(external_counter), n_pt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
