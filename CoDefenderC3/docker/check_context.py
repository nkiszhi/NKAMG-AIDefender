#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoDefenderC3 — Docker 构建上下文预检（stage 之后、docker build 之前）
=====================================================================

一次 `docker build` 要过 1.7GB 的上下文（736MB 模型 + 1000MB 签名库），
路径写错、或被 .dockerignore 误挡的代价是几十分钟白跑。这个脚本把三类
失败前移到 1 秒内：

  1. **COPY 源不存在** —— 例：历史上 `COPY data_loader.py` / `COPY scaner/`，
     前者已在 train/ 下（根目录没有 → COPY failed），后者漏写（构建能过、
     容器启动 ImportError）。这类错误只在 COPY 那一刻才炸，而那一刻
     前面已经跑完 pip 装了 20 分钟依赖。
  2. **COPY 源被 .dockerignore 整目录挡掉** —— Docker 的报错是
     `COPY failed: no source files were specified`，完全看不出是哪条规则。
     这里直接打印命中的规则名。
  3. **上下文体积失控** —— runs/、ensemble-old.pkl、papers/ 这类
     「只该在本机躺着」的目录一旦漏挡，上下文会凭空多出 2GB+ 过 hgfs。

同时输出「将被 COPY 进镜像的文件数与字节数」，用于和 `docker images` 对账。

用法
----
    python docker/check_context.py                          # 用 Dockerfile 里的默认 ARG
    python docker/check_context.py --build-arg MODEL_FILE=runs/run-5k-0917/ensemble.pkl
    python docker/check_context.py --dockerfile Dockerfile --context .

退出码
------
    0 通过    2 有致命问题（不要开始构建）
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from typing import Dict, List, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ══════════════════════════════════════════════════════════════════════════
#  .dockerignore 匹配（对齐 moby/patternmatcher 的语义）
#    · 规则自上而下计算，**最后一条命中的生效**（所以 ! 例外要写在通配后面）
#    · `*` 不跨 `/`；`**` 可跨任意层（含 0 层）；裸名字只锚定上下文根目录
#    · 命中「祖先目录」= 整棵子树被排除
#    · 尾斜杠写法按裸名处理（兼收两派实现，宁可多报也不漏报）
# ══════════════════════════════════════════════════════════════════════════
def _to_regex(pat: str) -> "re.Pattern[str]":
    out = ["^"]
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if i + 1 < n and pat[i + 1] == "*":
                j = i + 2
                if j < n and pat[j] == "/":
                    j += 1
                out.append(".*" if j >= n else "(.*/)?")
                i = j
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


class Ignore:
    def __init__(self, path: str):
        self.path = path
        self.rules: List[Tuple[str, bool, str]] = []  # (pattern, is_negation, raw)
        if not os.path.isfile(path):
            return
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                neg = line.startswith("!")
                pat = line[1:].strip() if neg else line
                pat = pat.rstrip("/") or pat
                self.rules.append((pat, neg, line))

    def hit_rule(self, rel_path: str) -> str:
        """返回导致排除的规则原文；未被排除返回 ""。"""
        rel_path = rel_path.replace("\\", "/")
        matched, rule = False, ""
        for pat, neg, raw in self.rules:
            rx = _to_regex(pat)
            if rx.match(rel_path):
                matched, rule = (not neg), ("" if neg else raw)
                continue
            parts = rel_path.split("/")
            for k in range(1, len(parts)):
                if rx.match("/".join(parts[:k])):
                    matched, rule = (not neg), ("" if neg else raw)
                    break
        return rule if matched else ""


def iter_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            out.append(os.path.relpath(full, root).replace("\\", "/"))
    return out


# ══════════════════════════════════════════════════════════════════════════
#  Dockerfile 解析
# ══════════════════════════════════════════════════════════════════════════
def read_instructions(path: str) -> List[str]:
    """逻辑行合并（处理 \\ 续行、# 注释）。"""
    out: List[str] = []
    buf = ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not buf:
                if line.strip().startswith("#") or not line.strip():
                    continue
                # 去掉行内 # 注释（简单处理：不在引号里的 #）
                line = re.sub(r"\s+#(?![^\"]*\"\s*$).*$", "", line)
            if line.endswith("\\"):
                buf += line[:-1] + " "
                continue
            buf += line
            out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def parse_args(instructions: List[str], overrides: Dict[str, str]) -> Dict[str, str]:
    args: Dict[str, str] = {}
    for ins in instructions:
        m = re.match(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$", ins)
        if m:
            args[m.group(1)] = (m.group(2) or "").strip().strip('"')
    args.update(overrides)
    return args


def expand(s: str, args: Dict[str, str]) -> str:
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: args.get(m.group(1), m.group(0)), s)


def copy_sources(instructions: List[str], args: Dict[str, str]) -> List[Tuple[str, List[str], str]]:
    """返回 [(指令原文, 源路径列表, 目标)]，只取 COPY/ADD（无 --from 的）。"""
    out = []
    for ins in instructions:
        if not re.match(r"^(COPY|ADD)\s", ins, re.I):
            continue
        if re.search(r"--from\s*=", ins):  # 多阶段拷贝，源来自其它 stage，跳过
            continue
        body = re.sub(r"^[A-Za-z]+\s+", "", ins)
        body = re.sub(r"--\S*=\S*\s*", "", body).strip()
        parts = re.split(r"\s+", re.sub(r'"([^"]*)"', r"\1", body))
        parts = [p for p in parts if p]
        if len(parts) < 2:
            continue
        srcs = [expand(p, args) for p in parts[:-1]]
        out.append((ins, srcs, expand(parts[-1], args)))
    return out


# ══════════════════════════════════════════════════════════════════════════
def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CoDefenderC3 Docker 构建上下文预检")
    ap.add_argument("--dockerfile", default=os.path.join(REPO_ROOT, "Dockerfile"))
    ap.add_argument("--context", default=REPO_ROOT)
    ap.add_argument("--build-arg", action="append", default=[], metavar="K=V")
    ap.add_argument("--list-copy", action="store_true", help="逐条打印 COPY 源与命中情况")
    args = ap.parse_args(argv)

    overrides = {}
    for kv in args.build_arg:
        if "=" in kv:
            k, v = kv.split("=", 1)
            overrides[k.strip()] = v.strip()
    if "SIG_STAGE" in overrides or "MODEL_FILE" in overrides:
        pass  # 路径按上下文根解释

    ctx = os.path.abspath(args.context)
    ig = Ignore(os.path.join(ctx, ".dockerignore"))
    instructions = read_instructions(args.dockerfile)
    a = parse_args(instructions, overrides)

    print("── 预检 ───────────────────────────────────────────────────────")
    print("  Dockerfile : %s" % args.dockerfile)
    print("  context    : %s" % ctx)
    if overrides:
        print("  build-arg  : %s" % overrides)
    if "SIG_STAGE" in a or "MODEL_FILE" in a:
        print("  ARG 生效值 : SIG_STAGE=%r  MODEL_FILE=%r" % (a.get("SIG_STAGE"), a.get("MODEL_FILE")))
    print()

    problems: List[str] = []
    total_files = 0
    total_bytes = 0

    print("── COPY 源检查 ────────────────────────────────────────────────")
    for ins, srcs, dst in copy_sources(instructions, a):
        line = "  %-46s -> %s" % (ins[:46], dst)
        for src in srcs:
            raw = src.rstrip("/\\")
            full = os.path.normpath(os.path.join(ctx, raw))
            rel = os.path.relpath(full, ctx).replace("\\", "/")

            if "*" in raw or "?" in raw:
                hits = glob.glob(full)
                if not hits:
                    problems.append("COPY 通配源无匹配: %s" % src)
                    print("    [FAIL] 通配无匹配 %s" % src)
                continue

            if not os.path.exists(full):
                problems.append("COPY 源不存在: %s" % src)
                print("    [FAIL] 源不存在 %s" % src)
                continue

            if os.path.isdir(full):
                files = iter_files(full)          # 相对「源目录」的路径
                kept, blocked_by = [], {}
                for f in files:
                    # ⚠ .dockerignore 的规则锚定在**上下文根**，不是源目录。
                    #   例：规则 models/MalGraph_2022/**/features.jsonl 要匹配的是
                    #   "models/MalGraph_2022/saved/features.jsonl"；若只拿
                    #   "MalGraph_2022/saved/features.jsonl" 去匹配就会漏判，
                    #   于是报告"已挡住"实为空话。这里补回源目录前缀。
                    r = ig.hit_rule(("%s/%s" % (rel, f)) if rel not in ("", ".") else f)
                    if r:
                        blocked_by.setdefault(r, 0)
                        blocked_by[r] += 1
                    else:
                        kept.append(f)
                if not kept:
                    rule = (list(blocked_by.keys())[0] if blocked_by else "?")
                    problems.append("COPY 目录被 .dockerignore 全部挡住: %s（命中规则 %s）" % (src, rule))
                    print("    [FAIL] %s 全部被挡（规则: %s）" % (src, rule))
                    continue
                b = 0
                for f in kept:
                    try:
                        b += os.path.getsize(os.path.join(full, f.replace("/", os.sep)))
                    except OSError:
                        pass
                total_files += len(kept)
                total_bytes += b
                extra = ""
                if blocked_by:
                    extra = "  挡住 %d 个（%s）" % (sum(blocked_by.values()), "; ".join(blocked_by))
                print("    [ ok ] %-42s %5d 文件  %10s%s" % (src, len(kept), human(b), extra))
            else:
                r = ig.hit_rule(rel)
                if r:
                    problems.append("COPY 文件被 .dockerignore 挡住: %s（命中 %s）" % (src, r))
                    print("    [FAIL] %s 被挡（规则: %s）" % (src, r))
                    continue
                b = os.path.getsize(full)
                total_files += 1
                total_bytes += b
                print("    [ ok ] %-42s      1 文件  %10s" % (src, human(b)))

        if args.list_copy:
            print(line)

    # ── 上下文体积（.dockerignore 之后实际会传给 daemon 的部分）──────────
    print()
    print("── 上下文体积 ────────────────────────────────────────────────")
    sent_files = sent_bytes = 0
    biggest: List[Tuple[int, str]] = []
    for f in iter_files(ctx):
        if ig.hit_rule(f):
            continue
        try:
            sz = os.path.getsize(os.path.join(ctx, f.replace("/", os.sep)))
        except OSError:
            continue
        sent_files += 1
        sent_bytes += sz
        if sz > 20 * 1024 * 1024:
            biggest.append((sz, f))
    biggest.sort(reverse=True)
    print("  未过滤文件 : %d 个 / %s" % (sent_files, human(sent_bytes)))
    print("  COPY 入镜像 : %d 个 / %s" % (total_files, human(total_bytes)))
    if biggest:
        print("  上下文大件 ( >20MB )：")
        for sz, f in biggest[:12]:
            print("    %10s  %s" % (human(sz), f))

    ok_total = total_bytes
    print()
    if problems:
        print("── 结论：%d 个致命问题，先修复再构建 ─────────────────────────" % len(problems))
        for p in problems:
            print("  ! %s" % p)
        return 2

    print("── 结论：通过。预计镜像内容 %s（含 736MB 模型 + ~1000MB 签名库）──" %
          human(ok_total))
    print("  下一步: docker build -t codefender-c3:v8 .")
    return 0


def human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if x < 1024 or unit == "TB":
            return "%.1f%s" % (x, unit) if unit != "B" else "%dB" % n
        x /= 1024.0
    return str(n)


if __name__ == "__main__":
    sys.exit(main())
