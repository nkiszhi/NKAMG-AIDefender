# -*- coding: utf-8 -*-
"""
_probe_bndb_slow_retry.py — 回归验证 bndb 阶段的三项改动 + de_done 覆盖修复

被验证的改动（2026-09-30）
-------------------------
A. data_loader 阶段1 删除「bndb 覆盖率 >98% → 剩余标记永久失败」短路，
   改为三分类：成功 / bndb_fail(硬失败，永久) / bndb_slow(超时或崩溃，
   `路径\\t次数`，下次重跑仍重试，累计 CODEFENDER_BNDB_MAX_SLOW_RETRY 次转永久)。
B. bndb 阶段并发降到 min(N_WORKERS, 4)（可用 CODEFENDER_BNDB_WORKERS 覆盖），
   补救轮单文件超时放宽（CODEFENDER_BNDB_TIMEOUT_RETRY，默认 600s）。
C. generate_bndbs_batch 新增 per_file_timeout / timeout_base 参数。
D. _find_need_de 全量扫描分支不再用 "w" 覆盖 de_done.log，而是与既有 done
   取并集后原子重写（原来会把日志里已有记录整批抹掉）。

用法
----
  python CoDefenderC3/train/_probe_bndb_slow_retry.py            # 纯逻辑，秒级
  python CoDefenderC3/train/_probe_bndb_slow_retry.py --with-bn  # 追加真实 BN 超时用例

退出码: 0 = 全部通过; 1 = 有断言失败
"""
import argparse
import hashlib
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
for _p in (REPO_ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import numpy as np  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print("  %s %s%s" % ("[OK]  " if cond else "[FAIL]", name,
                         ("  | " + detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def hr(t):
    print("\n" + "=" * 62)
    print("  " + t)
    print("=" * 62)


def make_ds(root, n_benign=4, n_mal=0, with_de=()):
    """构造数据集骨架: benign/ + .cache/per_sample/ + npz（默认只有快速视角）。"""
    ps = os.path.join(root, ".cache", "per_sample")
    os.makedirs(ps, exist_ok=True)
    os.makedirs(os.path.join(root, "benign"), exist_ok=True)
    os.makedirs(os.path.join(root, "malicious"), exist_ok=True)
    paths = []
    for i in range(n_benign):
        p = os.path.normpath(os.path.abspath(
            os.path.join(root, "benign", "sample_%02d" % i)))
        with open(p, "wb") as f:
            f.write(b"MZ" + bytes(256))
        paths.append(p)
        npz = os.path.join(ps, hashlib.md5(p.encode()).hexdigest() + ".npz")
        if i in with_de:
            np.savez(npz, A01=np.zeros(3, dtype=np.float32),
                     D01=np.zeros(4, dtype=np.float32))
        else:
            np.savez(npz, A01=np.zeros(3, dtype=np.float32))
    for i in range(n_mal):
        p = os.path.normpath(os.path.abspath(
            os.path.join(root, "malicious", "mal_%02d" % i)))
        with open(p, "wb") as f:
            f.write(b"MZ" + bytes(256))
        paths.append(p)
        npz = os.path.join(ps, hashlib.md5(p.encode()).hexdigest() + ".npz")
        np.savez(npz, A01=np.zeros(3, dtype=np.float32))
    return paths, ps


class FakeExt(object):
    """替代 BinjaExtractor：可编程返回 ok / reason，并记录调用参数。"""

    def __init__(self, mode="timeout", ok_on=()):
        self.mode = mode          # timeout | hardfail | ok
        self.ok_on = set(ok_on)
        self.calls = []
        self.de_calls = []

    def generate_bndbs_batch(self, pairs, n_workers=4, batch_size=20,
                             per_file_timeout=None, timeout_base=None):
        pairs = list(pairs)
        self.calls.append({
            "n": len(pairs), "n_workers": n_workers, "batch_size": batch_size,
            "per_file_timeout": per_file_timeout, "timeout_base": timeout_base,
        })
        ok, reasons = set(), {}
        for pe, bndb in pairs:
            if pe in self.ok_on:
                with open(bndb, "wb") as f:
                    f.write(b"BNDB")
                ok.add(pe)
            elif self.mode == "timeout":
                reasons[pe] = "TIMEOUT after 600s"
            elif self.mode == "hardfail":
                reasons[pe] = "load_returned_None"
        return ok, reasons

    def extract_de_from_bndb_batch(self, pe_paths, bndb_paths, npz_paths,
                                   n_workers=4, batch_size=10, on_ok=None):
        """桩：给每个 npz 写一个假 D key，避免真启动 BN 子进程。"""
        self.de_calls.append(len(pe_paths))
        for npz in npz_paths:
            np.savez(npz, A01=np.zeros(3, dtype=np.float32),
                     D01=np.zeros(4, dtype=np.float32))
        if on_ok:
            for p in pe_paths:
                on_ok(p)
        return set(pe_paths), {}


def main(argv=None):
    ap = argparse.ArgumentParser(description="bndb 慢样本/重试机制回归探针")
    ap.add_argument("--with-bn", action="store_true",
                    help="追加真实 BinaryNinja 子进程超时用例（约 10s，需要本机 BN 可用）")
    args = ap.parse_args(argv)

    tmp = tempfile.mkdtemp(prefix="_bndb_probe_")
    os.environ.setdefault("CODEFENDER_BNDB_MAX_SLOW_RETRY", "3")
    try:
        from data_loader import PELoader
        import feature_extraction.extract_feature as ef

        real_gen = ef.BinjaExtractor.generate_bndbs_batch
        real_de = ef.BinjaExtractor.extract_de_from_bndb_batch

        def patch(fake):
            ef.BinjaExtractor.generate_bndbs_batch = fake.generate_bndbs_batch
            ef.BinjaExtractor.extract_de_from_bndb_batch = \
                fake.extract_de_from_bndb_batch

        def unpatch():
            ef.BinjaExtractor.generate_bndbs_batch = real_gen
            ef.BinjaExtractor.extract_de_from_bndb_batch = real_de

        # ────────────────────────────────────────────────
        hr("D. _find_need_de 不再抹掉 de_done.log 里的既有记录（覆盖 bug 回归）")
        ds = os.path.join(tmp, "dcase")
        paths, ps = make_ds(ds, n_benign=5, with_de=(0, 1, 2, 3, 4))
        ld = PELoader(data_dir=ds)
        # 预先写入 3 条已完成记录（数量 <100，强制走全量扫描分支）
        pre = paths[:3]
        with open(os.path.join(ps, "de_done.log"), "w", encoding="utf-8") as f:
            for p in pre:
                f.write(p + "\n")
        check("前置: de_done.log 有 3 行", len(ld._load_log("de_done")) == 3)
        need = ld._find_need_de(paths)
        after = ld._load_log("de_done")
        check("全量扫描后 need == 0（5 个 npz 全含 D）", len(need) == 0,
              "need=%d" % len(need))
        check("de_done 合并写回 == 5 行（修复前会被抹成 2 行）",
              len(after) == 5, "实际 %d 行" % len(after))
        check("既有 3 条记录仍在", set(pre) <= after)
        check("无残留 .tmp 文件",
              not [f for f in os.listdir(ps) if ".tmp-" in f])

        # 再跑一次（幂等：不该被清）
        ld._find_need_de(paths)
        check("二次调用仍为 5 行（幂等）", len(ld._load_log("de_done")) == 5,
              "实际 %d 行" % len(ld._load_log("de_done")))

        # ────────────────────────────────────────────────
        hr("A1. 超时/崩溃 → bndb_slow（非永久），计数递增")
        ds2 = os.path.join(tmp, "scase")
        paths2, ps2 = make_ds(ds2, n_benign=4)
        ld2 = PELoader(data_dir=ds2)
        fake = FakeExt(mode="timeout")
        patch(fake)
        try:
            ld2.extract_features(paths2)
        finally:
            unpatch()

        slow = ld2._load_slow_log()
        check("bndb_slow.log 记 4 条", len(slow) == 4, "实际 %d" % len(slow))
        check("每条计数 = 1", all(v == 1 for v in slow.values()),
              "计数值 %s" % sorted(set(slow.values())))
        check("bndb_fail.log 未生成（旧逻辑在此会写 4 条永久失败）",
              not os.path.exists(os.path.join(ps2, "bndb_fail.log")))
        check("两轮调用：首轮 batch_size=1（2026-10-10 由 5 改 1）+ 补救轮 batch_size=1",
              [c["batch_size"] for c in fake.calls] == [1, 1],
              "实际 %s" % [c["batch_size"] for c in fake.calls])
        check("首轮超时 = 120s/文件（默认）",
              fake.calls[0]["per_file_timeout"] == 120,
              "实际 %s" % fake.calls[0]["per_file_timeout"])
        check("补救轮超时 = 600s/文件（放宽）",
              fake.calls[1]["per_file_timeout"] == 600,
              "实际 %s" % fake.calls[1]["per_file_timeout"])
        check("并发 = min(N_WORKERS, 4)",
              all(c["n_workers"] <= 4 for c in fake.calls),
              "实际 %s" % [c["n_workers"] for c in fake.calls])

        hr("A2. 慢样本重累计到上限 → 转 bndb_fail 永久失败")
        fake2 = FakeExt(mode="timeout")
        patch(fake2)
        try:
            ld2.extract_features(paths2)   # 第 2 次
            c2 = ld2._load_slow_log()
            check("第 2 次后计数 = 2", all(v == 2 for v in c2.values()),
                  "计数值 %s" % sorted(set(c2.values())))
            check("第 2 次仍不进 bndb_fail",
                  len(ld2._load_log("bndb_fail")) == 0)
            check("第 2 次未被 de_fail 永久排除（慢样本可重试）",
                  len(ld2._load_log("de_fail")) == 0,
                  "de_fail=%d" % len(ld2._load_log("de_fail")))
            ld2.extract_features(paths2)   # 第 3 次 → 到上限
        finally:
            unpatch()
        hard = ld2._load_log("bndb_fail")
        check("第 3 次（=上限 3）全部转 bndb_fail，共 4 条", len(hard) == 4,
              "实际 %d" % len(hard))
        check("转换后 bndb_slow 清空", len(ld2._load_slow_log()) == 0)
        check("已知慢样本不再进首轮（两轮都只有补救 batch_size=1）",
              [c["batch_size"] for c in fake2.calls] == [1, 1],
              "批次 %s" % [c["batch_size"] for c in fake2.calls])

        hr("A3. 硬失败（BN 明确报错）→ 直接 bndb_fail，不进慢样本")
        ds3 = os.path.join(tmp, "hcase")
        paths3, ps3 = make_ds(ds3, n_benign=3)
        ld3 = PELoader(data_dir=ds3)
        fake3 = FakeExt(mode="hardfail")
        patch(fake3)
        try:
            ld3.extract_features(paths3)
        finally:
            unpatch()
        check("bndb_fail 3 条", len(ld3._load_log("bndb_fail")) == 3,
              "实际 %d" % len(ld3._load_log("bndb_fail")))
        check("bndb_slow 为空（硬失败不当慢样本）",
              len(ld3._load_slow_log()) == 0)

        hr("A4. 成功样本会清掉它的慢样本计数")
        ds4 = os.path.join(tmp, "okcase")
        paths4, ps4 = make_ds(ds4, n_benign=3)
        ld4 = PELoader(data_dir=ds4)
        ld4._write_slow_log({paths4[0]: 2, paths4[1]: 2})
        fake4 = FakeExt(mode="timeout", ok_on=paths4)
        patch(fake4)
        try:
            ld4.extract_features(paths4)
        finally:
            unpatch()
        check("全部成功后 bndb_slow 清空", len(ld4._load_slow_log()) == 0,
              "实际 %s" % ld4._load_slow_log())
        check("无永久失败", len(ld4._load_log("bndb_fail")) == 0)
        check("已知慢样本跳过首轮（首轮只有 1 个非慢样本）",
              [c["batch_size"] for c in fake4.calls] == [1, 1]
              and fake4.calls[0]["n"] == 1 and fake4.calls[1]["n"] == 2,
              "批次 %s" % [(c["batch_size"], c["n"]) for c in fake4.calls])

        hr("A5. 已有 bndb 的慢样本记录会被自动过滤（残留自愈）")
        ds5 = os.path.join(tmp, "rescase")
        paths5, ps5 = make_ds(ds5, n_benign=2)
        ld5 = PELoader(data_dir=ds5)
        os.makedirs(ld5._bndb_cache, exist_ok=True)
        for p in paths5:
            with open(ld5._bndb_cache_path(p), "wb") as f:
                f.write(b"BNDB")
        ld5._write_slow_log({paths5[0]: 3, paths5[1]: 3})
        check("写入后文件里有 2 条",
              len(open(os.path.join(ps5, "bndb_slow.log"),
                       encoding="utf-8").read().strip().splitlines()) == 2)
        got = ld5._load_slow_log()
        check("读取时已过滤掉有 bndb 的条目（残留自愈）", len(got) == 0,
              "实际 %s" % got)
        # 无 bndb 的样本仍保留
        ld5._write_slow_log({paths5[0]: 3})
        import os as _os
        _os.replace(ld5._bndb_cache_path(paths5[0]),
                    ld5._bndb_cache_path(paths5[0]) + ".moved")
        check("bndb 消失后该条恢复可见",
              ld5._load_slow_log().get(paths5[0]) == 3,
              "实际 %s" % ld5._load_slow_log())

        hr("B/C. generate_bndbs_batch 新签名与超时计算")
        import inspect
        sig = inspect.signature(ef.BinjaExtractor.generate_bndbs_batch)
        check("签名含 per_file_timeout / timeout_base",
              "per_file_timeout" in sig.parameters
              and "timeout_base" in sig.parameters,
              str(sig))
        check("两者默认均为 None（回落到环境变量）",
              sig.parameters["per_file_timeout"].default is None
              and sig.parameters["timeout_base"].default is None)
        src = inspect.getsource(ef.BinjaExtractor.generate_bndbs_batch)
        check("batch_timeout 已参数化（不再是写死 120*n+30）",
              "_pf * len(batch) + _base" in src)
        check("默认 120s/文件 + 30s 缓冲仍在源码中",
              '"CODEFENDER_BNDB_TIMEOUT_PER_FILE", "120"' in src
              and '"CODEFENDER_BNDB_TIMEOUT_BASE", "30"' in src)

        if args.with_bn:
            hr("C2. 真实 BN 子进程：超时参数确实生效（--with-bn）")
            real_pe = None
            for cand in (r"D:\nkproject\data_test_ds\benign",
                         r"D:\nkproject\data_test\20260928\benign"):
                if os.path.isdir(cand):
                    fs = [f for f in sorted(os.listdir(cand))
                          if os.path.getsize(os.path.join(cand, f)) > 4096]
                    if fs:
                        real_pe = os.path.join(cand, fs[0])
                        break
            if real_pe is None:
                print("  [SKIP] 找不到真实 PE 样本，跳过真实用例")
            else:
                bn_tmp = os.path.join(tmp, "bntest")
                os.makedirs(bn_tmp, exist_ok=True)
                dst_b = os.path.join(bn_tmp, "a.bndb")
                ext = ef.BinjaExtractor()
                # 1) 极小超时 → 必须 TIMEOUT
                ok, reasons = ext.generate_bndbs_batch(
                    [(real_pe, dst_b)], n_workers=1, batch_size=1,
                    per_file_timeout=1, timeout_base=0)
                check("per_file_timeout=1s → 命中 TIMEOUT 分支",
                      (not ok) and "TIMEOUT" in str(reasons.get(real_pe, "")),
                      "reason=%s" % reasons.get(real_pe))
                # 超时被 kill 的子进程可能留下半写 bndb → 清掉再测正常路径
                if os.path.exists(dst_b):
                    try:
                        os.remove(dst_b)
                    except Exception:
                        pass
                # 2) 正常超时 → 应成功（病态样本可能要 130s+，给足 900s）
                ok2, reasons2 = ext.generate_bndbs_batch(
                    [(real_pe, dst_b)], n_workers=1, batch_size=1,
                    per_file_timeout=900, timeout_base=30)
                check("per_file_timeout=900s → 生成 bndb 成功",
                      real_pe in ok2 and os.path.exists(dst_b),
                      "reason=%s" % reasons2.get(real_pe))

    finally:
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass

    hr("结果")
    if FAILS:
        print("  [X] %d 项失败:" % len(FAILS))
        for f in FAILS:
            print("     - %s" % f)
        return 1
    print("  [OK] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
