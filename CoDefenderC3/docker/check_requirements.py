#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_requirements.py — 校验 requirements.txt 是否覆盖了代码里的真实依赖
==========================================================================

做法：从 engine/app.py 出发做「导入闭包」分析（纯 AST，不执行代码），把闭包内
触达的第三方模块与 requirements.txt 逐条比对，并按导入方式分三档：

    hard     模块顶层直接 import            → 缺了服务直接起不来
    guarded  顶层但被 try/except 包住       → 缺失自动降级
    lazy     函数体内 import                → 只在特定功能被调用时才需要

关键点：
  1. 可达性会**沿模块传递**。若 A 在函数里 `import B`，那么 B 及其内部所有顶层
     import 都只是 lazy（不会阻塞启动）——否则 MalGraph 的 torch_geometric
     会被误判成硬依赖。
  2. **包级 `__init__.py` 的副作用也算可达**。`from core.sdd_engine import X` 会让
     Python 先执行 `core/__init__.py`，而它往往一次性 `from .a import B` 拉起好几个
     子模块（本仓库 core/ 就拉起 sdd_engine+llm_module+baselines+stats）。
     相对导入同样要按当前文件所在包解析，否则整条链会被漏掉。

用法：
    python docker/check_requirements.py          # 运行时闭包（严格，推荐）
    python docker/check_requirements.py --all    # 连 train/ _tools/ 全仓一起查
    python docker/check_requirements.py -v       # 打印每个模块的导入位置

退出码：
    0  运行时硬依赖全部覆盖
    2  有未覆盖的硬依赖（脚本会列出该加的包名）
    3  脚本自身出错（如 requirements.txt 不存在）
==========================================================================
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from collections import defaultdict

# ── 包名(PyPI) ↔ 导入名(import) 映射 ────────────────────────────────────────
PKG_TO_IMPORT = {
    "numpy": "numpy",
    "scipy": "scipy",
    "scikit-learn": "sklearn",
    "matplotlib": "matplotlib",
    "pillow": "PIL",
    "torch": "torch",
    "torchvision": "torchvision",
    "torch-geometric": "torch_geometric",
    "fastapi": "fastapi",
    "starlette": "starlette",
    "uvicorn": "uvicorn",
    "python-multipart": "multipart",
    "pefile": "pefile",
    "ppdeep": "ppdeep",
    "yara-python": "yara",
    "tqdm": "tqdm",
    "pandas": "pandas",
    "requests": "requests",
    "gdown": "gdown",
    "datasets": "datasets",
    "boto3": "boto3",
    "botocore": "botocore",
    "thrember": "thrember",
    "anthropic": "anthropic",
    "ember-dataset": "ember",
    "binaryninja": "binaryninja",
    "lightgbm": "lightgbm",
}
IMPORT_TO_PKG = {v: k for k, v in PKG_TO_IMPORT.items()}

# 本仓库自带、故意不 pip 安装的「第三方名字」
VENDORED = {
    "tlsh": "scaner/tlsh.py（本地纯 Python 移植，scaner/ 在 sys.path 最前，优先命中）",
    "filetype": "scaner/filetype.py（本地实现）",
}

# 「启用但闭包内不出现」的白名单：属正常情况，不报为残留
EXPECTED_NON_IMPORT = {
    "uvicorn": "由 `python -m uvicorn` 启动，代码中从不 import",
    "multipart": "python-multipart：FastAPI 解析 form-data 时按需加载，代码不直接 import",
}

# 「有意不声明」的包：代码里确实用到，但不在生产链路 → requirements.txt 已整条删除。
# 列在这里，避免 --all 每次把它们报成"漏项"，同时保留"为什么可以不装"的说明。
INTENTIONAL_EXCLUSION = {
    "anthropic": "漂移归因 LLM（core/llm_module.py）；API 从未调用，仅离线实验用 → requirements §5",
}

# 不由 requirements.txt 安装、但在镜像里一定存在的包（requirements 里只做注释声明）
INSTALLED_ELSEWHERE = {
    "torch": "Dockerfile 第 1 层：--index-url https://download.pytorch.org/whl/cpu",
    "torchvision": "Dockerfile 第 1 层：随 torch 一起从 PyTorch CPU 源安装",
    "torch_geometric": "Dockerfile 第 1 层：单独 pip install",
    "binaryninja": "基础镜像 multiscan_basic_v3:with_binja 自带（商业库）",
}

RUNTIME_ROOT = ["engine", "core", "models", "scaner", "feature_extraction"]
EXTRA_ROOT = ["train", "update", "_tools"]
SKIP_DIRS = {".docker_build", ".feature_cache", "runs", "__pycache__",
             "node_modules", "signatures", "papers", "experiments", ".git"}

STDLIB = set(sys.stdlib_module_names)
SEV = {"hard": 0, "guarded": 1, "lazy": 2}     # 越小越"要命"


def combine(reach_kind, local_kind):
    """合并「模块可达方式」与「该 import 本身的方式」→ 取较不严重的那个"""
    return reach_kind if SEV[reach_kind] >= SEV[local_kind] else local_kind


# ════════════════════════════════════════════════════════════════════
#  AST：收集一个文件里的 import，并按 hard / guarded / lazy 分类
# ════════════════════════════════════════════════════════════════════
class ImportCollector(ast.NodeVisitor):
    """收集一个文件里的 import，并按 hard / guarded / lazy 分类。

    hits 元素 = (module_str, kind, lineno, level)
        level == 0 → 绝对导入，module_str 即模块名（可含点）
        level  > 0 → 相对导入，module_str 是「去掉前导点后的部分」（可为 ""，表示当前包）
    """

    def __init__(self):
        self.in_func = 0
        self.try_depth = 0          # >0 表示位于某个 try 的 body 内
        self.hits = []              # [(module_str, kind, lineno, level)]

    def visit_FunctionDef(self, node):
        self.in_func += 1
        self.generic_visit(node)
        self.in_func -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Try(self, node):
        self.try_depth += 1
        for n in node.body:
            self.visit(n)
        self.try_depth -= 1
        for n in list(node.handlers) + list(node.orelse) + list(node.finalbody):
            self.visit(n)

    def _kind(self):
        if self.in_func:
            return "lazy"
        if self.try_depth:
            return "guarded"
        return "hard"

    def visit_Import(self, node):
        for a in node.names:
            self.hits.append((a.name, self._kind(), node.lineno, 0))

    def visit_ImportFrom(self, node):
        self.hits.append((node.module or "", self._kind(), node.lineno, node.level))


def parse_file(path):
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    src = src.lstrip("\ufeff")
    try:
        return ast.parse(src)
    except SyntaxError:
        return None


# ════════════════════════════════════════════════════════════════════
#  本地模块解析
# ════════════════════════════════════════════════════════════════════
def make_resolver(root):
    """把 import 名解析到本地文件；返回 None 表示第三方。

    需要覆盖三类本地导入：
      1) 常规包路径        engine.inference → engine/inference.py
      2) scaner/ 被插入 sys.path 后的裸名    scanner → scaner/scanner.py
      3) train/ 等同理被插入 sys.path 的裸名 data_loader → train/data_loader.py
    """
    search_dirs = ["scaner", "train", "update", "engine", "core",
                   "models", "feature_extraction", "_tools"]

    def resolve(mod: str):
        parts = mod.split(".")
        cands = [
            os.path.join(*parts) + ".py",
            os.path.join(*parts, "__init__.py"),
        ]
        for d in search_dirs:
            cands.append(os.path.join(d, parts[0] + ".py"))
            cands.append(os.path.join(d, parts[0], "__init__.py"))
        for c in cands:
            p = os.path.join(root, c)
            if os.path.isfile(p):
                return os.path.normpath(os.path.relpath(p, root)).replace(os.sep, "/")
        # 本地目录（含隐式命名空间包，如 scaner/ 无 __init__.py）
        if os.path.isdir(os.path.join(root, *parts)):
            return os.path.normpath(os.path.join(*parts)).replace(os.sep, "/") + "/"
        return None
    return resolve


def resolve_relative(root, rel, level, mod):
    """把相对导入解析成本地文件（相对 root）；返回 None 表示落到仓库外/第三方。"""
    base = os.path.dirname(rel)                  # 当前文件所在目录 == 当前包目录
    for _ in range(level - 1):                   # `from ..x` 多跳一层
        base = os.path.dirname(base)
    parts = [p for p in mod.split(".") if p]
    target = os.path.join(base, *parts) if parts else base
    for cand in (target + ".py", os.path.join(target, "__init__.py"), target):
        p = os.path.join(root, cand)
        if os.path.isfile(p):
            return os.path.normpath(os.path.relpath(p, root)).replace(os.sep, "/")
        if os.path.isdir(p):
            init = os.path.join(p, "__init__.py")
            rel_init = os.path.normpath(os.path.join(cand, "__init__.py")).replace(os.sep, "/")
            return rel_init if os.path.isfile(init) else \
                os.path.normpath(cand).replace(os.sep, "/") + "/"
    return None


def parent_init_files(root, rel):
    """`from pkg.sub import X` 会先执行 pkg/__init__.py —— 祖先包的 __init__ 同样可达。

    这是纯 AST 闭包最容易漏的一块：包级 __init__ 里常有 `from .a import B`
    这类副作用导入（如 core/__init__.py 一次性拉起 sdd_engine/llm_module/baselines/stats）。
    """
    out = []
    d = os.path.dirname(rel)
    while d not in ("", ".", os.sep):
        init = os.path.join(d, "__init__.py")
        if os.path.isfile(os.path.join(root, init)):
            out.append(os.path.normpath(init).replace(os.sep, "/"))
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return out


def collect_closure(root, seed, resolver):
    """BFS + 可达性传播。返回 (third, reach)

    third: {mod: {kind: [(file, line), ...]}}
    reach: {local_rel_path: kind}
    """
    third = defaultdict(lambda: defaultdict(list))
    reach = {seed: "hard"}
    work = [(seed, "hard")]          # 允许同一模块被「更严重」的可达方式重新处理
    parsed = {}

    def push(rel_path, kind):
        if rel_path not in reach or SEV[kind] < SEV[reach[rel_path]]:
            reach[rel_path] = kind
            work.append((rel_path, kind))

    while work:
        rel, rk = work.pop()
        if rel not in parsed:
            parsed[rel] = parse_file(os.path.join(root, rel))
        tree = parsed[rel]
        if tree is None:
            continue
        c = ImportCollector()
        c.visit(tree)
        for mod, lk, lineno, level in c.hits:
            eff = combine(rk, lk)
            if level:                                  # 相对导入
                local = resolve_relative(root, rel, level, mod)
                if local is None:
                    continue                           # 仓库外，忽略
            else:
                top = mod.split(".")[0]
                if top in STDLIB:
                    continue
                local = resolver(mod)
                if local is None:
                    third[top][eff].append((rel, lineno))
                    continue
            for tgt in [local] + parent_init_files(root, local):
                push(tgt, eff)
    return third, reach


# ════════════════════════════════════════════════════════════════════
#  requirements.txt 解析
# ════════════════════════════════════════════════════════════════════
def load_requirements(path):
    if not os.path.isfile(path):
        print("!! 找不到 %s" % path, file=sys.stderr)
        sys.exit(3)
    active, commented = set(), set()
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line:
            continue
        is_comment = line.startswith("#")
        body = (line.lstrip("#").strip() if is_comment else line)
        body = body.split("#")[0].strip()
        if not body or body.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[].*)?$", body)
        if not m:
            continue
        name = m.group(1).lower()
        (commented if is_comment else active).add(name)
    return active, commented


def repo_scan_third_party(root, resolver):
    """全仓扫一遍，返回 未被任何 import 触达 的第三方名集合（用于判断"残留"）"""
    found = set()
    for r in RUNTIME_ROOT + EXTRA_ROOT:
        base = os.path.join(root, r)
        if not os.path.isdir(base):
            continue
        for dp, dns, fns in os.walk(base):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            for f in fns:
                if not f.endswith(".py"):
                    continue
                tree = parse_file(os.path.join(dp, f))
                if tree is None:
                    continue
                c = ImportCollector()
                c.visit(tree)
                for mod, _k, _l, level in c.hits:
                    if level:
                        continue
                    top = mod.split(".")[0]
                    if top in STDLIB or resolver(mod):
                        continue
                    found.add(top)
    # 根目录 .py
    for f in os.listdir(root):
        if f.endswith(".py"):
            tree = parse_file(os.path.join(root, f))
            if tree is None:
                continue
            c = ImportCollector()
            c.visit(tree)
            for mod, _k, _l, level in c.hits:
                if level:
                    continue
                top = mod.split(".")[0]
                if top in STDLIB or resolver(mod):
                    continue
                found.add(top)
    return found


# ════════════════════════════════════════════════════════════════════
#  主流程
# ════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description="校验 requirements.txt 与代码实际依赖是否一致")
    ap.add_argument("root", nargs="?", default=".", help="项目根目录（默认当前目录）")
    ap.add_argument("--all", action="store_true", help="连 train/ _tools/ 全仓一起扫描")
    ap.add_argument("-v", "--verbose", action="store_true", help="打印每个模块的导入位置")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    os.chdir(root)

    active, commented = load_requirements("requirements.txt")
    active_imports = {PKG_TO_IMPORT.get(p, p) for p in active}
    commented_imports = {PKG_TO_IMPORT.get(p, p) for p in commented}

    resolver = make_resolver(root)

    print("=" * 74)
    print(" CoDefenderC3 依赖核查")
    print("=" * 74)
    print(" 项目根          : %s" % root)
    print(" requirements.txt: 启用 %d 条 / 注释 %d 条" % (len(active), len(commented)))
    print()

    third, reach = collect_closure(root, "engine/app.py", resolver)
    print(" [运行时闭包] 从 engine/app.py 触达本地模块 %d 个、第三方模块 %d 个"
          % (len(reach), len(third)))
    print()

    def worst(mod):
        return min(third[mod], key=lambda k: SEV[k])

    hard = sorted(m for m in third if worst(m) == "hard")
    guarded = sorted(m for m in third if worst(m) == "guarded")
    lazy = sorted(m for m in third if worst(m) == "lazy")

    def show(title, mods):
        if not mods:
            return
        print(" " + title)
        for m in mods:
            where = ""
            if args.verbose:
                locs = sorted({x for k in third[m] for x in third[m][k]})
                where = "   " + ", ".join("%s:%d" % x for x in locs[:2])
            if m in VENDORED:
                tag = "本仓库自带（无需 pip）"
            elif m in active_imports:
                tag = "OK"
            elif m in commented_imports:
                tag = ("OK（requirements 注释声明·另行安装）"
                       if m in INSTALLED_ELSEWHERE else "已声明（注释态）")
            elif m in INSTALLED_ELSEWHERE:
                tag = "!! 未在 requirements.txt 提及（%s）" % INSTALLED_ELSEWHERE[m]
            elif m in INTENTIONAL_EXCLUSION:
                tag = "i 有意不声明（非生产路径，requirements §5）"
            else:
                tag = "!! 未在 requirements.txt 出现"
            print("     %-18s [%s]%s" % (m, tag, where))
        print()

    show("硬依赖（顶层 import，缺则启动失败）:", hard)
    show("可选依赖（try/except 保护，缺失自动降级）:", guarded)
    show("延迟依赖（函数内 import，按功能需要）:", lazy)

    def covered(m):
        """该 import 名是否被 requirements.txt（启用或注释）覆盖"""
        return (m in active_imports or m in commented_imports
                or m in VENDORED or m in INSTALLED_ELSEWHERE
                or m in INTENTIONAL_EXCLUSION)

    missing_hard = [m for m in hard if not covered(m)]
    missing_soft = [m for m in (guarded + lazy) if not covered(m)]

    # 反向：requirements 启用但闭包内未出现
    used_anywhere = repo_scan_third_party(root, resolver) if (args.all or True) else set()
    residual = []
    for m in sorted(active_imports - set(third) - set(VENDORED)):
        if m in EXPECTED_NON_IMPORT:
            continue
        if m in used_anywhere:
            residual.append((m, "非运行时导入（训练 / 数据构建 / CLI）"))
        else:
            residual.append((m, "全仓未见 import，疑似残留"))
    if residual:
        print(" [i] requirements 启用但运行时闭包未出现（不代表错误）：")
        for m, why in residual:
            print("     %-14s %s" % (m, why))
        print()

    # --all：全仓扫描，列出任何未提及的第三方
    if args.all:
        extra = sorted(used_anywhere - active_imports - commented_imports
                       - set(VENDORED) - set(INTENTIONAL_EXCLUSION))
        print(" [全仓扫描] 未在 requirements.txt 出现的第三方模块 %d 个：" % len(extra))
        for m in extra:
            print("     %-18s 建议包名: %s" % (m, IMPORT_TO_PKG.get(m, m)))
        print()
        excl = sorted(set(INTENTIONAL_EXCLUSION) & used_anywhere)
        if excl:
            print(" [i] 有意不声明（生产不带，代码里仅在非生产路径使用）：")
            for m in excl:
                print("     %-18s %s" % (m, INTENTIONAL_EXCLUSION[m]))
            print()

    if missing_hard:
        print(" [X] 运行时硬依赖缺失 %d 个 —— 必须加进 requirements.txt：" % len(missing_hard))
        for m in missing_hard:
            print("     %s" % IMPORT_TO_PKG.get(m, m))
        print()
    if missing_soft:
        print(" [~] 可选依赖未提及 %d 个（建议至少注释说明）：" % len(missing_soft))
        for m in missing_soft:
            print("     %s" % IMPORT_TO_PKG.get(m, m))
        print()

    ok = not missing_hard
    print("=" * 74)
    print(" 结论：%s" % ("运行时硬依赖全部覆盖 ✔" if ok else "存在未覆盖的硬依赖 ✘"))
    print("=" * 74)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
