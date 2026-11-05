#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
docker/check_model_imports.py — 构建期「模型模块导入探针」
================================================================
目的：把「改代码改坏了」提前到 `docker build` 阶段红掉，而不是等容器起来
      打 /health 才发现（历史上 torchvision 代际错配就是这么漏过去的：
      构建期自检只 `import engine.app`，而模型类是 ensemble 用 importlib
      按字符串动态加载的 —— AST 看不见，import 也没走到，于是构建一路绿灯，
      容器一打 /health 就是 {"status":"error","reason":...nms does not exist}）。

判定口径**刻意与运行期逐字对齐**，所以不会误红：
    models/ensemble.py::MultiModelEnsemble._load_model_class() 加载每个子模型时
    只吞三类异常 → 打印 `[警告] 无法加载 X`，该模型这一票缺席，服务照跑：

        except (KeyError, ImportError, AttributeError) as e:
            print(f"  [警告] 无法加载 {model_name}: {e}")
            return None, None

    其它异常（例如 torchvision::nms 的 RuntimeError）**不**被吞 →
    一路上抛打挂 _load_ensemble() → /health 直接 error。

    于是本探针：
      · (KeyError, ImportError, AttributeError) → 记 WARN，**不阻断构建**
        （与运行期同口径；只是把「少了几票」这件事显式写进构建日志）
      · 其它异常                              → 记 FATAL，exit 1 阻断构建
        （正是「容器 /health 必挂」的那一类，就该在构建期炸）

用法：
    python3 docker/check_model_imports.py          # 仓库根
    python3 /app/docker/check_model_imports.py     # 容器内（镜像里有一份）
退出码：0 = 无 FATAL；1 = 存在 FATAL 或 model_registry 本身都进不来。
"""
import importlib
import os
import sys
import traceback

# ★ 必须把「仓库根」塞进 sys.path：本脚本固定放在 <root>/docker/ 下
#   （镜像里是 /app/docker/），而 python 会把**脚本所在目录**当 sys.path[0]，
#   于是 `import model_registry` 会找不到。父目录恰好就是根：
#   仓库 <repo>/docker/  → <repo>；镜像 /app/docker/ → /app。
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.environ.get("CODEFENDER_ROOT") or os.path.dirname(_HERE)
if _ROOT and _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 与 models/ensemble.py::_load_model_class() 的 except 子句保持一致 —— 改动前先看那里
TOLERATED = (KeyError, ImportError, AttributeError)


def main() -> int:
    try:
        from model_registry import REGISTRY
    except BaseException as e:                      # noqa: BLE001
        print("[probe] FATAL: 连 model_registry 都导入失败: %s: %s" % (type(e).__name__, e))
        traceback.print_exc()
        return 1

    # 一个模块常被多个模型复用（如 DREBIN_2014.drebin 供 3 个模型）→ 去重后再 import
    modules = {}
    for name, cfg in REGISTRY.items():
        try:
            modules.setdefault(cfg["module"], []).append(name)
        except (KeyError, TypeError) as e:
            print("[probe] FATAL: REGISTRY['%s'] 结构不合法: %s" % (name, e))
            return 1

    print("[probe] REGISTRY 模型 %d 个 / 去重后模块 %d 个" % (len(REGISTRY), len(modules)))

    warn, fatal = [], []
    for mod in sorted(modules):
        users = ",".join(sorted(modules[mod]))
        try:
            importlib.import_module(mod)
            print("  [ ok ] %-44s (%s)" % (mod, users))
        except TOLERATED as e:
            warn.append((mod, users, e))
            print("  [WARN] %-44s %s: %s" % (mod, type(e).__name__, e))
        except BaseException as e:                  # noqa: BLE001
            fatal.append((mod, users, e))
            print("  [FAIL] %-44s %s: %s" % (mod, type(e).__name__, e))
            traceback.print_exc()

    print()
    if warn:
        print("[probe] %d 个模块导入失败 —— 运行期会**静默跳过**这些模型（集成少几票，服务照跑）:"
              % len(warn))
        for mod, users, e in warn:
            print("         %-44s %-28s %s: %s" % (mod, users, type(e).__name__, e))
        print("       · 不想少票 → 补装依赖，或检查 .dockerignore 是否误挡了这些文件。")
        print("       · 若确认这些模型本来就不打算用，忽略本条即可（与运行期行为一致）。")

    if fatal:
        print("[probe] FATAL：%d 个模块抛出了运行期**不会**吞掉的异常 → 容器 /health 必挂:"
              % len(fatal))
        for mod, users, e in fatal:
            print("         %-44s %-28s %s: %s" % (mod, users, type(e).__name__, e))
        print("       → 先在本机复现：python3 -c \"import %s\"" % fatal[0][0])
        return 1

    print("[probe] 通过：无 FATAL（WARN %d 个）" % len(warn))
    return 0


if __name__ == "__main__":
    sys.exit(main())
