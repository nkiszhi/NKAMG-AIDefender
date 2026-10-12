# -*- coding: utf-8 -*-
"""
探针: 验证本机 BinaryNinja 是否可用（headless / 许可 / 真实分析）

用途
----
在训练或推理前确认 BN 这一层能不能用：
  1) 解释器与包能否 import（bnpython3 vs 系统 python + pip 包）
  2) 许可类型 / 到期时间 / 是否允许 headless
  3) 真实 PE 能否 open_view + 反汇编 + 建函数/基本块
  4) 能否产出项目需要的 D/E 视角原料（opcode 序列、调用图）

用法
----
  # 用 BN 自带解释器（推荐，与 GUI 同源）
  "C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" train/_probe_bn_available.py [PE路径]

  # 或用系统 python（需 pip install binaryninja 且许可已激活）
  python train/_probe_bn_available.py [PE路径]

退出码
------
  0 = 全部通过，BN 可 headless 使用
  1 = 有失败项（详见输出）
  2 = 无法 import binaryninja
"""
import os
import sys
import time
import calendar
import traceback

# 默认样本：优先用标准测试集里的真实 PE
DEFAULT_PES = [
    r"D:\nkproject\data_test\20260928\benign",
    r"D:\nkproject\data_test\20260928\malicious",
]


def hr(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def find_default_pe():
    """挑一个体积适中的真实 PE（<4MB 优先），避免探针耗时过久。"""
    import glob
    cands = []
    for d in DEFAULT_PES:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if os.path.isfile(p) and os.path.getsize(p) > 4096:
                cands.append(p)
    if not cands:
        return None
    small = [p for p in cands if os.path.getsize(p) < 4 << 20]
    pool = small or cands
    return min(pool, key=os.path.getsize)


def main(argv):
    pe = argv[1] if len(argv) > 1 else find_default_pe()
    problems = []

    # ── 1. 解释器 / 导入 ──
    hr("1. 解释器与包导入")
    print("  python   : %s" % sys.executable)
    print("  version  : %s" % sys.version.replace("\n", " "))
    print("  BN_API   : %s" % os.environ.get("BN_API_PATH", "<unset>"))
    try:
        import binaryninja as bn
    except Exception as e:
        print("  [X] import binaryninja 失败: %r" % (e,))
        traceback.print_exc()
        return 2
    ver = getattr(bn, "core_version", lambda: "?")()
    print("  [OK] binaryninja 已导入  core_version = %s" % ver)
    print("       package path = %s" % os.path.dirname(bn.__file__))

    # ── 2. 许可 ──
    # 注意: import binaryninja 成功本身即隐含许可已通过校验
    #       （__init__ 的 _init_core 在 BNIsLicenseValidated() 为假时直接 raise）
    hr("2. 许可状态")
    exp_t = None
    for fn_name, label in (
        ("core_product", "product"),
        ("core_product_type", "product_type"),
        ("core_serial", "serial"),
        ("core_license_count", "license_count"),
        ("core_ui_enabled", "ui_enabled(False=纯headless)"),
        ("core_expires", "expires(gmtime)"),
    ):
        fn = getattr(bn, fn_name, None)
        if fn is None:
            print("  %-24s : <API 不存在>" % label)
            continue
        try:
            val = fn()
            if label.startswith("expires") and val is not None:
                exp_t = val
                print("  %-24s : %s" % (label, time.strftime("%Y-%m-%d %H:%M:%S", val) + " UTC"))
            else:
                print("  %-24s : %s" % (label, val))
        except Exception as e:
            print("  %-24s : <异常 %r>" % (label, e))
    try:
        email = bn._binaryninjacore.BNGetLicensedUserEmail()  # type: ignore[attr-defined]
        print("  %-24s : %s" % ("licensed_email", email))
    except Exception as e:
        print("  %-24s : <异常 %r>" % ("licensed_email", e))
    # 到期提醒（BN 的 gmtime 是 UTC）
    if exp_t is not None:
        try:
            exp_epoch = calendar.timegm(exp_t)
        except Exception:
            exp_epoch = 0
        if exp_epoch <= 0:
            print("  [!] 许可未携带到期时间（expires=epoch 0）：可能是无期限许可，")
            print("      也可能是 BN 未真正读到 license 文件 —— 以第 3 步真实分析为准")
        else:
            days = (exp_epoch - time.time()) / 86400.0
            if days < 0:
                print("  [X] 许可已过期 %.1f 天" % (-days))
                problems.append("license_expired")
            elif days < 30:
                print("  [!] 许可将在 %.1f 天后到期，建议尽快续期" % days)
            else:
                print("  [OK] 许可有效，剩余 %.1f 天" % days)

    # ── 3. 真实 PE 分析 ──
    hr("3. 真实 PE 反汇编 / 建函数")
    if not pe or not os.path.isfile(pe):
        print("  [!] 未找到可用 PE 样本，跳过真实分析（可显式传入路径）")
        problems.append("no_pe")
    else:
        print("  样本: %s (%.1f KB)" % (pe, os.path.getsize(pe) / 1024.0))
        t0 = time.time()
        try:
            # 与项目 extract_feature.py / _bndb_worker.py 完全一致的加载方式
            bv = bn.load(pe, options={
                "analysis.mode": "basic",
                "analysis.linearSweep.autorun": True,
                "analysis.limits.maxFunctionSize": 262144,
            })
        except Exception as e:
            print("  [X] bn.load() 失败: %r" % (e,))
            traceback.print_exc()
            bv = None
            problems.append("bn.load")
        if bv is not None:
            try:
                bv.update_analysis_and_wait()
            except Exception as e:
                print("  [!] update_analysis_and_wait 异常（继续）: %r" % (e,))
            dt = time.time() - t0
            n_func = len(bv.functions)
            n_bb = sum(len(f.basic_blocks) for f in bv.functions)
            n_ins = 0
            try:
                n_ins = sum(len(list(bb)) for f in bv.functions for bb in f.basic_blocks)
            except Exception:
                pass
            print("  [OK] 分析完成 %.2fs" % dt)
            print("       arch        = %s" % (bv.arch.name if bv.arch else "n/a"))
            print("       platform    = %s" % bv.platform)
            print("       entry       = 0x%x" % bv.entry_point)
            print("       functions   = %d" % n_func)
            print("       basicblocks = %d" % n_bb)
            print("       insns(iter) = %d" % n_ins)
            if n_func == 0:
                problems.append("zero_functions")
                print("  [X] 函数数为 0 —— 许可受限或分析未真正执行")
            # D/E 原料抽样
            try:
                f0 = bv.functions[0]
                mnem = [f0.arch.get_instruction_text(i[0]) for i in list(f0.basic_blocks[0])[:3]]
                print("       首函数前 3 条: %s" % [m[0] if m else None for m in mnem])
            except Exception as e:
                print("       (指令抽样失败: %r)" % (e,))
            # 调用图原料
            try:
                n_calls = sum(1 for f in bv.functions for _ in f.call_sites)
                print("       call_sites  = %d" % n_calls)
            except Exception as e:
                print("       (call_sites 失败: %r)" % (e,))
            try:
                bv.file.close()
            except Exception:
                pass

    # ── 4. 结论 ──
    hr("结论")
    if problems:
        print("  [X] BinaryNinja 本机不可用或受限，问题项: %s" % ", ".join(problems))
        return 1
    print("  [OK] BinaryNinja 本机可用（headless 分析正常）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
