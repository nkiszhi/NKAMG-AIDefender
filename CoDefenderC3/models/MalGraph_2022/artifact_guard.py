# -*- coding: utf-8 -*-
"""MalGraph 训练产物的"新鲜度指纹" —— 防止拿旧口径的权重/词表去跑新特征。

为什么需要它
------------
BN → SMDA 切换后，MalGraph 的输入**全变了**：

* 函数集合变了（BN 的线性扫描会把数据区也扫成函数，SMDA 不会）
* FCG 边变了（BN 的 MLIL_IMPORT 分支 83% 取不到符号，导入调用边被丢；
  SMDA 从 RIP 相对寻址直接算 IAT 地址）
* 11 维块特征变了（retn/ret 的渲染差异、常量口径差异）
* 外部函数词表变了（BN 与 SMDA 的导入名集合 Jaccard 只有 0.755）

于是 **BN 时代训练出来的权重与词表在 SMDA 特征上完全失效**，
而且失效是**静默**的 —— 推理照常出分数，只是分数没有意义。

本模块给每个训练产物打一个**指纹**：

    {feature_schema, ir_schema, backend, built_at, ...}

推理侧加载词表时会比对指纹：

* 指纹缺失 → 视为过期（旧产物没有指纹）
* backend 不同 → 拒绝加载（"这份词表是 BN 训的，当前跑的是 SMDA"）
* feature_schema 不同 → 拒绝加载（特征口径改过了）

2026-11-07
"""
from __future__ import annotations

import json
import os

# ── 特征口径版本 ────────────────────────────────────────────────────
# 11 维块特征 / FCG 边的口径一旦改动（比如新增维度、换分类规则），
# 就必须 +1 —— 否则老权重会被当成"仍然兼容"而静默劣化。
FEATURE_SCHEMA = "malgraph-ir/2"

# ── ProgramIR 契约版本（与 feature_extraction/ir.py 的 SCHEMA_VERSION 对应）
IR_SCHEMA = "codefender-ir/1"

META_KEY = "_codefender_meta"


def current_backend() -> str:
    """当前反汇编后端（"bn" / "smda"）。

    读环境变量 CODEFENDER_DISASM_BACKEND；读不到就按 feature_extraction
    的默认（smda）。这里刻意不 import feature_extraction.backend ——
    Vocabulary 会被推理侧直接 import，不能拖进 numpy 之类的重依赖。
    """
    raw = (os.environ.get("CODEFENDER_DISASM_BACKEND") or "smda").strip().lower()
    return raw if raw in ("bn", "smda") else "smda"


def current_fingerprint() -> dict:
    """当前应有的指纹（与训练时写入的比对）。"""
    return {
        "feature_schema": FEATURE_SCHEMA,
        "ir_schema": IR_SCHEMA,
        "backend": current_backend(),
    }


def make_fingerprint(backend: str, built_at: str = "", extra: dict = None) -> dict:
    """训练时生成指纹。"""
    fp = current_fingerprint()
    fp["backend"] = backend
    if built_at:
        fp["built_at"] = built_at
    if extra:
        fp.update(extra)
    return fp


def fingerprint_mismatch(expected: dict, actual: dict):
    """返回不一致的字段列表（空 = 一致）。

    只比**决定性**字段：feature_schema / ir_schema / backend。
    built_at 之类的元信息不比。
    """
    diffs = []
    for key in ("feature_schema", "ir_schema", "backend"):
        want = expected.get(key)
        got = actual.get(key)
        if want != got:
            diffs.append("%s: 期望 %r，实际 %r" % (key, want, got))
    return diffs


def stamp_vocab_file(path: str, fingerprint: dict) -> None:
    """给外部函数词表文件打指纹（写进第一行）。

    词表文件格式：一行一个 JSON。第一行是 meta，其余是 {f_name, count}。
    """
    tmp = path + ".tmp"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fr:
            lines = fr.readlines()
    else:
        lines = []
    body = [ln for ln in lines
            if ln.strip() and META_KEY not in ln]
    with open(tmp, "w", encoding="utf-8") as fw:
        fw.write(json.dumps({META_KEY: fingerprint}, ensure_ascii=False) + "\n")
        for ln in body:
            fw.write(ln)
    os.replace(tmp, path)


def read_vocab_meta(path: str):
    """读词表第一行的指纹；没有就返回 None。"""
    try:
        with open(path, "r", encoding="utf-8") as fr:
            first = fr.readline()
    except Exception:
        return None
    if not first.strip():
        return None
    try:
        obj = json.loads(first)
    except Exception:
        return None
    if isinstance(obj, dict) and META_KEY in obj:
        return obj[META_KEY]
    return None


def write_manifest(directory: str, fingerprint: dict, extra: dict = None) -> str:
    """把指纹写进 <directory>/feature_manifest.json。"""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "feature_manifest.json")
    payload = dict(fingerprint)
    if extra:
        payload.update(extra)
    with open(path, "w", encoding="utf-8") as fw:
        json.dump(payload, fw, ensure_ascii=False, indent=2, sort_keys=True)
    return path


def read_manifest(directory: str):
    """读 <directory>/feature_manifest.json；没有就返回 None。"""
    path = os.path.join(directory, "feature_manifest.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fr:
            return json.load(fr)
    except Exception:
        return None


class StaleArtifactError(RuntimeError):
    """训练产物与当前特征口径/后端不匹配。"""
