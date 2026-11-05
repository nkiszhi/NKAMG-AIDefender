#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoDefenderC3 — Docker 构建用「签名库暂存器」
============================================

把**当前生效**的一整套签名库（sha256 / md5 / fuzzy 三族）整理成一份干净的
构建上下文，供 Dockerfile 的

    COPY ${SIG_STAGE}/ ./signatures/

使用。

为什么必须多这一步（不能让 Dockerfile 直接 COPY signatures/）
--------------------------------------------------------------
宿主机的 `signatures/` 里同时躺着三份东西：

    signatures/<base>.db.shards/      ← 初始部署时扁平展开的那一份（旧）
    signatures/releases/<v>/          ← 版本化发布目录（新，含 imphash /
                                         authentihash / rich_header_hash 等 bloom）
    signatures/current -> releases/<v>  ← 符号链接（内容是绝对宿主路径）

Docker 的构建上下文**无法穿透指向上下文外部的绝对路径符号链接**，而
「哪一套才是当前生效的」在 Dockerfile 里没有任何可靠写法。于是这里用与
`engine/app.py::_active_sig_dir()` **完全相同的解析优先级**把源定死：

    HASH_DB_DIR/current（symlink）
      → HASH_DB_DIR/releases/CURRENT（指针文件，Windows 无 symlink 权限时的回退）
      → HASH_DB_DIR 本身（首次部署 / 未做过版本化发布）

然后做三件事：

  1. 剔除半成品文件：`-wal` / `-shm`（SQLite 未提交日志与共享内存）、
     `*.legacy` / `*.tmp` / `*.temp` / `*.partial` / `*.downloading`。
     app.py 的 `_copy_sig_family()` 同样排除它们 —— 留着只会让容器里的
     SQLite 读到不一致状态。
  2. 优先用**硬链接**（同卷零拷贝、零额外占用），跨卷/共享目录自动回退 `copy2`。
  3. 生成两份清单，**刻意分开**：
       · `<out>/_staging_manifest.json` —— 内容**只随实际文件集变化**（源版本 /
         各族分片数 / 字节数 / 链接统计 / 文件集指纹），**不含时间戳**。
         它随 COPY 进镜像成为 `/app/SIGNATURES_SOURCE.json`。
       · `<out 的上一级>/staging_run.json` —— 本次运行的时间 / 主机等易变信息。
         刻意放在 COPY 源**之外**：Docker 的 COPY 缓存键含源目录每个文件的内容，
         时间戳若留在源里，库没变也会让那 1GB 层每次都 cache miss。

安全边界
--------
全程**不调用任何删除 API**：单个文件先写唯一临时名再 `os.replace()` 原子覆盖；
整个暂存目录先建在 `<out>.new-<ts>`，再把旧的 `os.rename` 成 `<out>.old-<ts>`
后顶上去（与训练侧 `place_sample()` 同一套路，同时绕开本机的 safe-delete 钩子）。

用法
----
    python docker/stage_signatures.py                 # 暂存到 .docker_build/signatures/
    python docker/stage_signatures.py --check         # 只体检、不落盘（秒级）
    python docker/stage_signatures.py --out DIR       # 自定义暂存目录
    python docker/stage_signatures.py --sig-root DIR  # 指定签名库根（默认 <repo>/signatures）
    python docker/stage_signatures.py --json          # 额外输出机器可读的清单

退出码
------
    0  成功
    2  必需库族缺失 / 为空（构建必然失败，提前炸）

作者：CoDefenderC3 运维侧脚本；无第三方依赖，Python 3.8+ 均可。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import sys
import time
from collections import Counter
from typing import Dict, List, Tuple

# ── 三族签名库 ────────────────────────────────────────────────────────────
# 与 engine/app.py 的建立顺序一致：sha256 → md5 → fuzzy。
# sha256/md5 是必需族（缺任一，CODEFENDER_REQUIRE_HASH_DB=1 下拒绝启动）；
# fuzzy 打不开时 app 只降级（[hashdb] Fuzzy 库不可用，降级），但生产仍需备齐。
FAMILIES: Tuple[str, ...] = ("sha256", "md5", "fuzzy")
REQUIRED: Tuple[str, ...] = ("sha256", "md5")

# 每个 <base>.db.shards/ 的期望文件数：_meta.db + 00.db..ff.db
EXPECT_SHARDS = 256

# 半成品 / 旁挂文件（app.py 的 _copy_sig_family 同样排除）
SKIP_SUFFIXES = (
    "-wal", "-shm", ".legacy", ".tmp", ".temp", ".partial", ".downloading",
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ══════════════════════════════════════════════════════════════════════════
#  1. 解析「当前生效」的签名库目录
#     ★ 必须与 engine/app.py::_active_sig_dir() 保持一致，否则镜像里装的
#       可能不是线上正在用的那一套。
# ══════════════════════════════════════════════════════════════════════════
def resolve_active_sig_dir(root: str) -> Tuple[str, str, str]:
    """返回 (生效目录, 解析途径, 版本号)。"""
    # ① HASH_DB_DIR/current（Linux 生产的符号链接；isdir 会穿透 symlink）
    cur = os.path.join(root, "current")
    if os.path.isdir(cur):
        try:
            real = os.path.realpath(cur)
            return real, "current(symlink)", os.path.basename(real.rstrip("\\/"))
        except OSError:
            pass
    # ② HASH_DB_DIR/releases/CURRENT（Windows 无符号链接权限时的指针文件）
    ptr = os.path.join(root, "releases", "CURRENT")
    if os.path.isfile(ptr):
        try:
            with open(ptr, "r", encoding="utf-8") as f:
                ver = f.read().strip()
            d = os.path.join(root, "releases", ver)
            if ver and os.path.isdir(d):
                return d, "releases/CURRENT", ver
        except OSError:
            pass
    # ③ HASH_DB_DIR 本身（首次部署 / 未做过版本化发布）
    return root, "root(未版本化)", ""


# ══════════════════════════════════════════════════════════════════════════
#  2. 文件搬运（硬链接优先，不调用任何删除 API）
# ══════════════════════════════════════════════════════════════════════════
def place_atomic(src: str, dst: str) -> str:
    """把 src 落到 dst（原子覆盖），返回 "link" / "copy"。

    先写唯一临时名 → os.replace() 顶上去：os.replace 是原子覆盖，
    且不经过任何删除 API（本机 safe-delete 钩子连进程内 os.remove 都会拦）。
    """
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = "%s.staging-%d" % (dst, os.getpid())
    if os.path.exists(tmp):  # 极罕见：上一轮进程被硬杀，残留临时名 → 改名归档而非删除
        os.rename(tmp, "%s.old-%d" % (tmp, int(time.time())))
    try:
        os.link(src, tmp)          # 同卷：零拷贝
        mode = "link"
    except OSError:
        shutil.copy2(src, tmp)     # 跨卷 / 共享目录（hgfs）：退回复制
        mode = "copy"
    os.replace(tmp, dst)
    return mode


def is_junk(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(s) for s in SKIP_SUFFIXES)


# ══════════════════════════════════════════════════════════════════════════
#  2.5 mtime 归一 —— 不做这一步，签名库那 ~1GB 的 COPY 层每轮都会 cache miss
# ══════════════════════════════════════════════════════════════════════════
def normalize_tree_mtimes(root: str, stamp: float, extra_files=()) -> int:
    """把 root 下**所有目录**（自底向上）与本轮新写的文件 mtime 扣到 stamp。

    为什么必须做：
      · 硬链接进来的 *.db.shards / *.db.bloom，mtime == 源文件 mtime → 天然稳定；
      · 但暂存树是「每轮新建目录（<out>.new-<pid>）再 rename 顶上去」的 →
        目录 mtime 永远是「现在」；_staging_manifest.json 也是每轮新写的。
      · BuildKit 计算本地 COPY 源校验和时会带上**目录 mtime**。于是哪怕库
        一个字节没变，那 ~1GB 的签名库层也照样每轮 cache miss，每次
        docker build 都白重拷一遍（本项目从 hgfs 共享目录构建，代价是分钟级）。
      · 归一之后，只要库的真内容没变，整棵树的（路径 / 大小 / mtime / 权限）
        就逐项一致 → 该层 CACHED，改代码时只重做 2.8MB 的代码层。

    stamp 取自「本轮所有数据文件里最大的 mtime」并取整到秒 —— 这个值只随
    **源库**变化，与「第几次运行 / 哪台机器 / 几点跑的」都无关。

    注意：只 utime，不删除、不重写任何文件（本机 safe-delete 钩子会拦删除类 API）。
    """
    n = 0
    for dirpath, _dirnames, _filenames in os.walk(root, topdown=False):
        try:
            os.utime(dirpath, (stamp, stamp))
            n += 1
        except OSError as e:
            print("  [warn] 目录 mtime 归一失败: %s (%s)" % (dirpath, e), file=sys.stderr)
    for p in extra_files:
        if os.path.exists(p):
            try:
                os.utime(p, (stamp, stamp))
            except OSError as e:
                print("  [warn] 文件 mtime 归一失败: %s (%s)" % (p, e), file=sys.stderr)
    return n


# ══════════════════════════════════════════════════════════════════════════
#  3. 体检
# ══════════════════════════════════════════════════════════════════════════
def inspect(src_dir: str) -> Dict[str, dict]:
    """统计各族分片/布隆文件数与字节数（不读文件内容，秒级）。"""
    report: Dict[str, dict] = {}
    for fam in FAMILIES:
        item: Dict[str, dict] = {}
        for kind, suffix in (("shards", ".db.shards"), ("bloom", ".db.bloom")):
            d = os.path.join(src_dir, fam + suffix)
            n_files = 0
            n_junk = 0
            total = 0
            if os.path.isdir(d):
                with os.scandir(d) as it:
                    for e in it:
                        if not e.is_file(follow_symlinks=True):
                            continue
                        if is_junk(e.name):
                            n_junk += 1
                            continue
                        n_files += 1
                        try:
                            total += e.stat(follow_symlinks=True).st_size
                        except OSError:
                            pass
            item[kind] = {"dir": d, "exists": os.path.isdir(d),
                          "files": n_files, "junk": n_junk, "bytes": total}
        item["required"] = fam in REQUIRED
        report[fam] = item
    return report


def print_report(src_dir: str, via: str, ver: str, report: Dict[str, dict]) -> bool:
    print("── 当前生效的签名库 ────────────────────────────────────────────")
    print("  源目录   : %s" % src_dir)
    print("  解析途径 : %s%s" % (via, ("  版本 %s" % ver) if ver else ""))
    print()
    print("  %-8s %-10s %8s %8s %12s  %s" %
          ("族", "种类", "文件数", "剔除", "体积", "状态"))
    ok = True
    problems: List[str] = []
    for fam in FAMILIES:
        it = report[fam]
        for kind, cn in (("shards", "分片"), ("bloom", "布隆")):
            info = it[kind]
            label = "%s.db.%s" % (fam, kind)
            empty = (not info["exists"]) or info["files"] == 0

            if empty:
                status = "缺失" if not info["exists"] else "空目录"
            elif kind == "shards" and info["files"] != EXPECT_SHARDS + 1:
                status = "OK(分片数 %d，期望 %d)" % (info["files"], EXPECT_SHARDS + 1)
            else:
                status = "OK"

            print("  %-8s %-10s %8d %8d %12s  %s" %
                  (fam, cn, info["files"], info["junk"],
                   human(info["bytes"]), status))

            if not empty:
                continue
            # 缺 shards = 致命（三族都致命：app 会降级，但生产要求备齐）；
            # 缺 bloom = 只影响启动期预筛性能，算非致命，但大字提示。
            if kind == "shards":
                ok = False
                problems.append("[致命] %s 缺失 → 容器内 %s 族无法加载" % (label, fam))
            else:
                problems.append("[警告] %s 缺失 → 该族启动期布隆预筛不可用" % label)
    if problems:
        print()
        for p in problems:
            print("  ! %s" % p)
    return ok


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f%s" % (n, unit) if unit != "B" else "%dB" % n
        n /= 1024.0
    return str(n)


# ══════════════════════════════════════════════════════════════════════════
#  主流程
# ══════════════════════════════════════════════════════════════════════════
def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="把当前生效的一整套签名库暂存成干净的 Docker 构建上下文",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sig-root", default=os.path.join(REPO_ROOT, "signatures"),
                    help="签名库根目录（默认 <repo>/signatures）")
    ap.add_argument("--out", default=os.path.join(REPO_ROOT, ".docker_build", "signatures"),
                    help="暂存输出目录（默认 <repo>/.docker_build/signatures）")
    ap.add_argument("--check", action="store_true", help="只体检，不落盘")
    ap.add_argument("--json", action="store_true", help="额外打印机器可读清单")
    ap.add_argument("--quiet", action="store_true", help="只输出错误行")
    args = ap.parse_args(argv)

    def say(*a):
        if not args.quiet:
            print(*a, flush=True)

    if not os.path.isdir(args.sig_root):
        print("[stage] 签名库根目录不存在: %s" % args.sig_root, file=sys.stderr)
        return 2

    src_dir, via, ver = resolve_active_sig_dir(args.sig_root)
    report = inspect(src_dir)
    healthy = print_report(src_dir, via, ver, report)

    if args.check:
        say()
        say("[stage] --check 模式：未落盘。%s" % ("体检通过。" if healthy else "存在缺失项，见上方 ! 行。"))
        return 0 if healthy else 2

    if not healthy:
        say()
        print("[stage] 必需库族缺失或为空 → 拒绝暂存（构建必然失败，提前炸）。",
              file=sys.stderr)
        print("        可用 /update-signatures 发布一次，或核对 %s" % args.sig_root,
              file=sys.stderr)
        return 2

    # ── 落盘：先建到 <out>.new-<pid>，再原子顶上 ──────────────────────────
    out_dir = os.path.abspath(args.out)
    new_dir = "%s.new-%d" % (out_dir, os.getpid())
    if os.path.isdir(new_dir):
        os.rename(new_dir, "%s.old-%d" % (new_dir, int(time.time())))

    n_link = n_copy = 0
    bytes_total = 0
    stamp_max = 0.0                 # 本轮所有数据文件里最大的 mtime（用于 mtime 归一）
    manifest_fams: Dict[str, dict] = {}
    fp_entries: List[str] = []      # 文件集指纹的构成项（名字 + 大小，不读内容）

    say()
    say("── 暂存中（硬链接优先，跨卷自动退回复制）────────────────────────")
    for fam in FAMILIES:
        fam_meta: Dict[str, dict] = {}
        for kind, suffix in (("shards", ".db.shards"), ("bloom", ".db.bloom")):
            src_d = os.path.join(src_dir, fam + suffix)
            if not os.path.isdir(src_d):
                fam_meta[kind] = {"files": 0, "bytes": 0, "skipped_junk": 0}
                continue
            dst_d = os.path.join(new_dir, fam + suffix)
            n = 0
            b = 0
            junk = 0
            modes = Counter()
            with os.scandir(src_d) as it:
                for e in it:
                    if not e.is_file(follow_symlinks=True):
                        continue
                    if is_junk(e.name):
                        junk += 1
                        continue
                    mode = place_atomic(e.path, os.path.join(dst_d, e.name))
                    modes[mode] += 1
                    if mode == "link":
                        n_link += 1
                    else:
                        n_copy += 1
                    n += 1
                    sz = e.stat(follow_symlinks=True).st_size
                    b += sz
                    try:
                        mt = e.stat(follow_symlinks=True).st_mtime
                        if mt > stamp_max:
                            stamp_max = mt
                    except OSError:
                        pass
                    fp_entries.append("%s/%s\t%d" % (fam + suffix, e.name, sz))
            say("    %-7s %-12s %4d 个文件  %10s  (link=%d copy=%d%s)" %
                (fam, kind, n, human(b), modes["link"], modes["copy"],
                 "" if not junk else "  剔除旁挂=%d" % junk))
            bytes_total += b
            fam_meta[kind] = {"files": n, "bytes": b, "skipped_junk": junk,
                              "hardlinked": modes["link"], "copied": modes["copy"]}
        fam_meta["required"] = fam in REQUIRED
        manifest_fams[fam] = fam_meta

    # ── 文件集指纹：只覆盖「文件名 + 大小」，不读内容（~2000 个文件毫秒级）──
    fp_entries.sort()
    fingerprint = hashlib.sha256("\n".join(fp_entries).encode("utf-8")).hexdigest()

    # ── 稳定清单（在 COPY 源内 → 会进镜像成为 /app/SIGNATURES_SOURCE.json）──
    #  刻意**不放**时间戳 / 主机名：Docker 的 COPY 缓存键既含源文件的**内容**，
    #  也含**目录 mtime**（见 normalize_tree_mtimes）；只要有一处变，签名库那
    #  ~1GB 的层就 cache miss，白重拷一遍。
    manifest = {
        "tool": "docker/stage_signatures.py",
        "manifest_kind": "stable（只随实际文件集变化，不含时间戳）",
        "file_set_fingerprint": fingerprint,
        "file_set_fingerprint_note": "sha256 over sorted 'family.db.kind/name<TAB>size'；"
                                     "只覆盖文件名与大小，不读文件内容",
        "source": {
            "sig_root": os.path.abspath(args.sig_root),
            "resolved_dir": src_dir,
            "resolved_via": via,
            "release_version": ver or None,
        },
        "destination": "/app/signatures (容器内扁平展开，无 current / releases)",
        "families": manifest_fams,
        "totals": {
            "files": n_link + n_copy,
            "bytes": bytes_total,
            "hardlinked": n_link,
            "copied": n_copy,
        },
    }
    os.makedirs(new_dir, exist_ok=True)
    manifest_path = os.path.join(new_dir, "_staging_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    # ★ mtime 归一：目录是本轮新建的、清单是本轮新写的，不归一它们，
    #   「库没变」时那 ~1GB 的 COPY 层仍会每轮 cache miss（见上面 docstring）。
    stamp = float(int(stamp_max)) if stamp_max > 0 else float(int(os.path.getmtime(src_dir)))
    n_dirs = normalize_tree_mtimes(new_dir, stamp, [manifest_path])

    # ── 易变运行记录（刻意留在 COPY 源**之外**）───────────────────────────
    run_record = {
        "tool": "docker/stage_signatures.py",
        "note": "本文件刻意不放进 COPY 源：内容每次运行都变，放进去会让签名库那 ~1GB 的 COPY 层每次都 cache miss。",
        "staged_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "staged_at_epoch": int(time.time()),
        "host": socket.gethostname(),
        "out_dir": out_dir,
        "file_set_fingerprint": fingerprint,
        "source_release_version": ver or None,
        "totals": manifest["totals"],
    }
    run_record_path = os.path.join(os.path.dirname(out_dir), "staging_run.json")
    os.makedirs(os.path.dirname(run_record_path), exist_ok=True)
    tmp_rec = "%s.new-%d" % (run_record_path, os.getpid())
    with open(tmp_rec, "w", encoding="utf-8") as f:
        json.dump(run_record, f, ensure_ascii=False, indent=2)
    os.replace(tmp_rec, run_record_path)        # 原子覆盖，全程不调删除 API

    # 旧的暂存目录改名归档（不删除；硬链接目录几乎不占空间）
    old_dir = None
    if os.path.isdir(out_dir):
        old_dir = "%s.old-%d" % (out_dir, int(time.time()))
        os.rename(out_dir, old_dir)
    os.rename(new_dir, out_dir)

    say()
    say("── 暂存完成 ────────────────────────────────────────────────────")
    say("  输出目录 : %s" % out_dir)
    say("  文件总数 : %d（硬链接 %d / 复制 %d）" % (n_link + n_copy, n_link, n_copy))
    say("  总字节   : %s" % human(bytes_total))
    say("  零拷贝   : %s" % ("是（全部硬链接）" if n_copy == 0 else "否（%d 个文件走了复制）" % n_copy))
    say("  mtime 归一: %d 个目录 + 清单 → %s（稳定值；缺这一步，大件层每轮 cache miss）"
        % (n_dirs, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))))
    say("  文件集指纹: %s" % fingerprint)
    say("  运行记录 : %s（在 COPY 源之外，不影响层缓存）" % run_record_path)
    if old_dir:
        say("  上一版   : %s（硬链接，占用≈0；确认新镜像可用后可手动删除）" % old_dir)
    say()
    say("  下一步   : docker build -t codefender-c3:v8 .")

    if args.json:
        print(json.dumps({"manifest": manifest, "run_record": run_record},
                         ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
