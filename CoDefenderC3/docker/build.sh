#!/usr/bin/env bash
# =============================================================================
#  CoDefenderC3 —— 一键构建「自包含推理镜像」（代码 + 签名库 + ensemble.pkl）
# =============================================================================
#  用法：
#      bash docker/build.sh                       # 默认 tag: codefender-c3:v8
#      bash docker/build.sh codefender-c3:v8.1    # 指定 tag
#      bash docker/build.sh codefender-c3:v8 --no-cache
#      PYTHON=/d/work/tools/miniconda3/python.exe bash docker/build.sh   # 指定解释器
#
#  三步走（前两步是本机预处理，很快；第三步才是真正耗时的构建）：
#      ① stage_signatures.py  解析 signatures/current → 暂存到 .docker_build/signatures/
#                              （硬链接零拷贝；跨盘/共享目录自动退回复制）
#      ② check_context.py     预检 COPY 源、.dockerignore 误挡、上下文体积
#      ③ docker build
#
#  ⚠ 注意构建上下文的位置：镜像里 1.7GB 的大件（模型 + 签名库）都要过一次
#    上下文传输。若 docker 跑在 VMware 里的 Ubuntu 上，而仓库在 Windows 宿主
#    （本仓库就是这种拓扑），建议：
#        · ① 在 Windows 侧跑（NTFS 硬链接，1 秒完成、不占额外磁盘）
#        · ② 在任意一侧跑
#        · ③ 在 Ubuntu 侧跑（hgfs 只用于读一次上下文，别把签名库挂回容器）
# =============================================================================
set -euo pipefail

TAG="${1:-codefender-c3:v8}"
shift || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── 选一个可用的 python ────────────────────────────────────────────────
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "[build] 找不到 python。可用 PYTHON=/path/to/python bash docker/build.sh 指定" >&2
  exit 2
fi
export PYTHONIOENCODING=utf-8

echo "▶ [1/3] 暂存签名库（解析 current → .docker_build/signatures/）"
"$PY" docker/stage_signatures.py

echo
echo "▶ [2/3] 预检构建上下文"
"$PY" docker/check_context.py

echo
echo "▶ [3/3] docker build -t ${TAG}"
docker build -t "${TAG}" "$@"

echo
docker images "${TAG}"
echo
echo "✔ 构建完成（代码 + ensemble.pkl + sha256/md5/fuzzy 三族签名库 全部内嵌，零挂载）。启动："
echo "    docker run -d --name codefender -p 8000:8000 ${TAG}"
echo "  ⚠ 不要挂 -v ...:/app/signatures —— 镜像自带完整库，挂卷只会让容器读到卷里的旧库。"
echo "  改了代码/模型/库要重建容器才生效（旧容器 rootfs 在 run 时就固化了）："
echo "    docker rm -f codefender && docker run -d --name codefender -p 8000:8000 ${TAG}"
echo "  自检："
echo "    curl -s localhost:8000/health | python -m json.tool"
echo "    期望 engine_mode=hash_db+model、require_hash_db=true、三库 count 非 null"
