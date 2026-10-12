#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  本机开发（Linux/VM）：以「纯模型链路」启动
#  （四级哈希预检 sha256/md5/fuzzy/tlsh 全关，所有样本走 33 模型集成）
#
#  · 只影响本进程环境，不写配置文件、零残留 → 不会被带进 Docker 镜像
#  · 生产容器请用 docker run（prod 档位固化全引擎 + 缺签名库拒绝启动），
#    不要用本脚本
#  · 验证：curl -s localhost:8000/health | grep -E '"env"|"engine_mode"'
#    期望 "env":"dev" 且 "engine_mode":"model_only"
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

PORT="${CODEFENDER_PORT:-8000}"
PY="${CODEFENDER_PYTHON:-python3}"

# 端口占用预检：旧进程占着端口 → 新实例起不来、请求打到旧进程，
# 正是「配置改完没生效」最经典的假象。直接拦下。
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]"; then
    echo "[dev] 端口 ${PORT} 已被占用，拒绝启动（否则请求会打到旧进程）：" >&2
    ss -ltnp 2>/dev/null | grep -E "[:.]${PORT}[[:space:]]" >&2 || true
    echo "[dev] 处理：kill <上面的 pid>，或 CODEFENDER_PORT=8001 $0" >&2
    exit 1
  fi
fi

export PYTHONIOENCODING=utf-8
export CODEFENDER_ENV=dev
export CODEFENDER_HASH_DB_ENABLED=0
export CODEFENDER_FUZZY_DB_ENABLED=0
export CODEFENDER_REQUIRE_HASH_DB=0

cat <<EOF

[dev] ===== 纯模型模式（本机开发）=====
[dev] CODEFENDER_ENV=dev  HASH_DB_ENABLED=0  FUZZY_DB_ENABLED=0
[dev] 所有样本走 33 模型集成，哈希预检不参与判定
[dev] 端口 :${PORT}   直接 Ctrl+C 结束
[dev] ==================================

EOF

exec "$PY" -u -m uvicorn engine.app:app --host 0.0.0.0 --port "$PORT"
