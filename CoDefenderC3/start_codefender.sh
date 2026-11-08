#!/bin/bash
# ── 启动脚本（SMDA 后端）─────────────────────────────────────────
#
# 2026-11-07：BN → SMDA 切换。原来的版本要做三件 BN 专属的事：
#   ① export PATH/LD_LIBRARY_PATH/PYTHONPATH 指向 /opt/binaryninja
#   ② 启动时 bn.core_set_license(读 ~/.binaryninja/license.dat)
#   ③ 依赖内网基础镜像 multiscan_basic_v3:with_binja 里的 BN 运行时
# 三件全部不需要了：SMDA 是纯 Python + capstone/lief（BSD-3，无需商业授权），
# 反汇编后端由 CODEFENDER_DISASM_BACKEND 决定（默认 smda）。
#
# 旧 BN 启动脚本留在 git 历史里；如需 A/B 对照，用
#   CODEFENDER_DISASM_BACKEND=bn + 装 binaryninja + 提供 license.dat

# ── 启动 uvicorn ─────────────────────────────────────────────
exec python3 -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
