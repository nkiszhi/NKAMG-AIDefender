# -*- coding: utf-8 -*-
"""place_sample 硬链接语义与回退行为的单元验证（一次性脚本）。"""
import os
import shutil
import sys

sys.path.insert(0, r"D:\VM_Share\CoDefenderC3_v8\CoDefenderC3\train")
from build_minimal_dataset import place_sample, _same_inode  # noqa: E402

SRC = r"D:\nkproject\_link_test\src"
DST = r"D:\nkproject\_link_test\dst"
CROSS = r"C:\Users\Administrator\AppData\Local\Temp\_link_test_dst"
for d in (SRC, DST, CROSS):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)

payload = {("f%d.bin" % i): (b"MZ" + bytes([i]) * (1 << 20)) for i in range(1, 4)}
for fn, data in payload.items():
    with open(os.path.join(SRC, fn), "wb") as f:
        f.write(data)

fails = []


def check(name, cond, extra=""):
    print("  [%s] %s %s" % ("PASS" if cond else "FAIL", name, extra))
    if not cond:
        fails.append(name)


print("1) 同盘 prefer_link=True → 硬链接")
mode, err = place_sample(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1.bin"), True)
check("mode=link", mode == "link", "(mode=%s err=%s)" % (mode, err))
check("同 inode", _same_inode(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1.bin")))
check("内容一致", open(os.path.join(DST, "f1.bin"), "rb").read() == payload["f1.bin"])

print("2) 目标已存在（已是同 inode）→ 幂等")
mode, err = place_sample(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1.bin"), True)
check("仍为 link", mode in ("link", "keep"), "(mode=%s)" % mode)
check("同 inode", _same_inode(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1.bin")))

print("3) 目标已存在但是独立文件 → 原子替换为硬链接")
with open(os.path.join(DST, "f1b.bin"), "wb") as f:
    f.write(b"OLD" * 100)
mode, err = place_sample(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1b.bin"), True)
check("mode=link", mode == "link")
check("同 inode", _same_inode(os.path.join(SRC, "f1.bin"), os.path.join(DST, "f1b.bin")))
check("内容被替换", open(os.path.join(DST, "f1b.bin"), "rb").read() == payload["f1.bin"])

print("4) 跨卷（D: → C:）→ 回退 copy2，不抛异常")
mode, err = place_sample(os.path.join(SRC, "f2.bin"), os.path.join(CROSS, "f2.bin"), True)
check("mode=copy", mode == "copy", "(err=%s)" % err)
check("err 已记录", bool(err))
check("内容一致", open(os.path.join(CROSS, "f2.bin"), "rb").read() == payload["f2.bin"])
check("不同 inode", not _same_inode(os.path.join(SRC, "f2.bin"), os.path.join(CROSS, "f2.bin")))

print("5) prefer_link=False → 始终复制")
mode, err = place_sample(os.path.join(SRC, "f3.bin"), os.path.join(DST, "f3.bin"), False)
check("mode=copy", mode == "copy", "(err=%s)" % err)
check("不同 inode", not _same_inode(os.path.join(SRC, "f3.bin"), os.path.join(DST, "f3.bin")))

print("6) 同盘硬链接不额外占用空间（按 inode 去重统计 D: 上的真实占用）")
files = [os.path.join(SRC, fn) for fn in sorted(os.listdir(SRC))] + \
        [os.path.join(DST, fn) for fn in sorted(os.listdir(DST))]
uniq = {}
inodes = {}
for p in files:
    st = os.stat(p)
    uniq.setdefault((st.st_dev, st.st_ino), (st.st_size, []))[1].append(
        os.path.relpath(p, r"D:\nkproject\_link_test"))
real_bytes = sum(sz for sz, _ in uniq.values())
for sz, names in uniq.values():
    print("     inode 组(%d B): %s" % (sz, ", ".join(sorted(names))))
print("     文件数 %d，独立 inode %d，真实占用 %d B（全复制应为 %d B）"
      % (len(files), len(uniq), real_bytes, sum(os.path.getsize(p) for p in files)))
check("独立 inode=4（f1 共享 / f3 独立复制）", len(uniq) == 4, "实际 %d" % len(uniq))

print("7) 无残留临时名")
strays = [fn for fn in os.listdir(DST) if ".link-tmp" in fn or ".stale" in fn]
check("无 .link-tmp/.stale", not strays, str(strays))

print("\n结果: %s" % ("全部通过" if not fails else "失败 %d 项: %s" % (len(fails), fails)))
sys.exit(0 if not fails else 1)
