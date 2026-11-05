#!/usr/bin/env bash
# =============================================================================
#  CoDefenderC3 —— 容器接口冒烟测试（不依赖 jq，只读为主）
# =============================================================================
#  用法：
#      bash docker/test_api.sh                                    # 打本机 http://localhost:8000
#      BASE_URL=http://192.168.56.20:8000 bash docker/test_api.sh  # 打 VM 里的容器
#      bash docker/test_api.sh --sample /path/to/x.exe             # 追加「单文件检测」
#      bash docker/test_api.sh --dir /data/samples                 # 追加「批量目录扫描」
#      bash docker/test_api.sh --expect-prod                       # 强制要求 env=prod（否则判 FAIL）
#      TIMEOUT=180 bash docker/test_api.sh                         # 放宽单请求超时（默认 90s）
#
#  测什么：GET /livez /readyz /metrics /health /model-info /admin/config
#          （+ 可选 POST /predict-single、/predict-directory）
#  不测什么：POST /update-signatures（改签名库）、POST /reload-model（换模型）
#          —— 这两条会改状态，按 docs/TESTING.md 3.7 / 3.9 手工执行。
#  代理：默认对 localhost/127.0.0.1 加 --noproxy（见下方 CURL_NOPROXY 注释）。
#
#  ⚠ 两个实测坑，脚本已按正确姿势写：
#    1) /health 要统计三库条数，实测 3~6s 才返回 → 单请求超时默认 90s，别用 3s 判「没起来」。
#    2) include_de 是 **query 参数**，必须写在 URL 上（?include_de=false）。
#       写成 -F "include_de=false" 会被当 multipart 表单字段丢弃 → D/E 特征照跑，
#       单文件耗时从 2~3s 变成 30~130s（BinaryNinja）。docs 里旧示例就是这个错，已修。
#
#  ⚠ predict-directory 的 directory 是**容器内**路径，本镜像零挂载 → 先把样本拷进去：
#       docker cp /mnt/hgfs/VM_Share/testsamples codefender:/data/samples
#       bash docker/test_api.sh --dir /data/samples
# =============================================================================
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
TIMEOUT="${TIMEOUT:-90}"
SAMPLE=""
SCAN_DIR=""
EXPECT_PROD=0
# 本机/回环永远绕过代理：否则 shell 里若有 HTTP_PROXY，请求会被代理截走，
# 服务没起时你看到的是代理的 502「upstream connect failed」而不是「连接被拒绝」，
# 极容易误判。要连真正的远端 VM 且必须走代理时，用 CURL_NOPROXY='' 覆盖。
CURL_NOPROXY="${CURL_NOPROXY-localhost,127.0.0.1,::1}"

while [ $# -gt 0 ]; do
  case "$1" in
    --sample)      SAMPLE="${2:-}"; shift 2 ;;
    --dir)         SCAN_DIR="${2:-}"; shift 2 ;;
    --expect-prod) EXPECT_PROD=1; shift ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "[warn] unknown arg: $1" >&2; shift ;;
  esac
done

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then echo "[err] 需要 python3（用于解析 JSON 与取字段）" >&2; exit 2; fi

HTTP_CODE=""
HTTP_BODY=""
N_PASS=0; N_FAIL=0; N_SKIP=0
declare -a R_NAME R_STAT R_NOTE

record() { R_NAME+=("$1"); R_STAT+=("$2"); R_NOTE+=("$3"); }

ok()   { record "$1" "PASS" "$2"; N_PASS=$((N_PASS+1)); printf '  [PASS] %-34s %s\n' "$1" "$2"; }
bad()  { record "$1" "FAIL" "$2"; N_FAIL=$((N_FAIL+1)); printf '  [FAIL] %-34s %s\n' "$1" "$2"; }
skip() { record "$1" "SKIP" "$2"; N_SKIP=$((N_SKIP+1)); printf '  [SKIP] %-34s %s\n' "$1" "$2"; }

# http <METHOD> <URL> [curl 额外参数...] -> 设置 HTTP_CODE / HTTP_BODY
http() {
  local method="$1"; local url="$2"; shift 2
  local raw
  local -a np=()
  [ -n "$CURL_NOPROXY" ] && np=(--noproxy "$CURL_NOPROXY")
  raw=$(curl -s -m "$TIMEOUT" ${np[@]+"${np[@]}"} -w $'\n%{http_code}' -X "$method" "$@" "$url" 2>&1) || true
  if [[ "$raw" == *$'\n'* ]]; then
    HTTP_CODE="${raw##*$'\n'}"
    HTTP_BODY="${raw%$'\n'*}"
  else
    HTTP_CODE="000"; HTTP_BODY="$raw"
  fi
  [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]] || HTTP_CODE="000"
}

# jget <dotted.path> —— 从上一次响应体里取字段，取不到回空
jget() {
  printf '%s' "$HTTP_BODY" | "$PY" -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); sys.exit(0)
v = d
for k in sys.argv[1].split("."):
    if isinstance(v, dict):
        v = v.get(k)
    elif isinstance(v, list) and k.isdigit():
        v = v[int(k)] if int(k) < len(v) else None
    else:
        v = None
    if v is None:
        break
print("" if v is None else v)' "$1" 2>/dev/null
}

say() { printf '\n== %s\n' "$1"; }

printf 'CoDefenderC3 API smoke test\n'
printf '  BASE_URL = %s\n' "$BASE_URL"
printf '  TIMEOUT  = %ss\n' "$TIMEOUT"

# ── 0. 可达性 ────────────────────────────────────────────────────────────────
say "0/6 可达性"
http GET "$BASE_URL/livez"
if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "502" ]; then
  bad "reachable" "连不上 $BASE_URL（HTTP $HTTP_CODE）"
  printf '         排查顺序：\n'
  printf '           1) docker ps        容器在跑吗？\n'
  printf '           2) docker run 里有没有 -p 8000:8000（端口发布）\n'
  printf '           3) 从 Windows 打，URL 里得是 VM 的 IP，不是 localhost\n'
  printf '           4) HTTP 502 + "upstream connect failed" = 被代理截走了（本地服务没起）\n'
  printf '              脚本已默认对 localhost/127.0.0.1 加 --noproxy\n'
  printf '\n[abort] 后续测试无意义，退出。\n'
  exit 1
fi
ok "reachable" "HTTP $HTTP_CODE"

# ── 1. 存活 / 就绪 ───────────────────────────────────────────────────────────
say "1/6 探针"
if [ "$(jget alive)" = "True" ]; then
  ok "/livez" "alive, uptime=$(jget uptime_human)"
else
  bad "/livez" "HTTP $HTTP_CODE body=$(printf '%s' "$HTTP_BODY" | head -c 120)"
fi

http GET "$BASE_URL/readyz"
if [ "$HTTP_CODE" = "200" ] && [ "$(jget ready)" = "True" ]; then
  ok "/readyz" "model loaded"
elif [ "$HTTP_CODE" = "503" ]; then
  bad "/readyz" "503 模型未加载（还在 startup？看 docker logs）"
else
  bad "/readyz" "HTTP $HTTP_CODE body=$(printf '%s' "$HTTP_BODY" | head -c 120)"
fi

# ── 2. 健康（最关键的「我到底在访问谁」判据）─────────────────────────────────
say "2/6 健康 / 档位"
http GET "$BASE_URL/health"
ENV_V="$(jget env)"
MODE_V="$(jget engine_mode)"
REQ_HASH="$(jget require_hash_db)"
MODEL_PATH_V="$(jget model_path)"
SHA_V="$(jget hash_db.sha256)"; MD5_V="$(jget hash_db.md5)"; FUZ_V="$(jget hash_db.fuzzy)"
if [ "$HTTP_CODE" = "200" ]; then
  ok "/health" "env=$ENV_V engine_mode=$MODE_V require_hash_db=$REQ_HASH"
  printf '         model_path=%s\n' "$MODEL_PATH_V"
  printf '         hash counts: sha256=%s md5=%s fuzzy=%s\n' "${SHA_V:-null}" "${MD5_V:-null}" "${FUZ_V:-null}"
else
  bad "/health" "HTTP $HTTP_CODE"
fi

if [ "$EXPECT_PROD" = "1" ]; then
  if [ "$ENV_V" = "prod" ]; then
    ok "container mode" "env=prod（确认是容器档位）"
  else
    bad "container mode" "env=$ENV_V != prod —— 你很可能在测宿主上的 dev 实例，不是容器！"
  fi
fi

# 判据提示：容器内 env=prod / require_hash_db=true / model_path=/app/ensemble.pkl
if [ "$MODEL_PATH_V" != "/app/ensemble.pkl" ] && [ -n "$MODEL_PATH_V" ]; then
  printf '  [note] model_path 不是 /app/ensemble.pkl → 这不是容器内的服务（宿主 dev 实例？）\n'
fi

# ── 3. 指标 ──────────────────────────────────────────────────────────────────
say "3/6 运行时指标"
http GET "$BASE_URL/metrics"
if [ "$HTTP_CODE" = "200" ]; then ok "/metrics" "total_requests=$(jget total_requests)"; else bad "/metrics" "HTTP $HTTP_CODE"; fi

# ── 4. 模型档案 ──────────────────────────────────────────────────────────────
say "4/6 模型档案"
http GET "$BASE_URL/model-info"
if [ "$HTTP_CODE" = "200" ]; then
  ok "/model-info" "status=$(jget status) model_count=$(jget ensemble.model_count) view_count=$(jget ensemble.view_count) file=$(jget file.path)"
else
  bad "/model-info" "HTTP $HTTP_CODE"
fi

# ── 5. 运行时配置 ────────────────────────────────────────────────────────────
say "5/6 运行时配置"
http GET "$BASE_URL/admin/config"
if [ "$HTTP_CODE" = "200" ]; then ok "/admin/config" "engine_mode=$(jget engine_mode)"; else bad "/admin/config" "HTTP $HTTP_CODE"; fi

# ── 6. 可选：真的跑一次推理 ──────────────────────────────────────────────────
say "6/6 推理（可选）"
if [ -n "$SAMPLE" ]; then
  if [ ! -f "$SAMPLE" ]; then
    skip "/predict-single" "本地找不到文件：$SAMPLE"
  else
    t0=$(date +%s)
    http POST "$BASE_URL/predict-single?include_de=false" -F "file=@${SAMPLE}"
    t1=$(date +%s)
    if [ "$HTTP_CODE" = "200" ]; then
      ok "/predict-single" "$((t1-t0))s  Status=$(jget Status) Score=$(jget Score) IsMalicious=$(jget IsMalicious) ok/skip=$(jget ScanResult.ModelStats.OkModels)/$(jget ScanResult.ModelStats.SkippedModels)"
      SK="$(jget ScanResult.ModelStats.SkippedModels)"
      if [ -n "$SK" ] && [ "$SK" != "0" ] && [ "$SK" -ge 9 ] 2>/dev/null; then
        printf '         [note] SkippedModels=%s 偏高，正常（include_de=false 会跳过 10 个 D/E 模型）\n' "$SK"
      fi
    else
      bad "/predict-single" "HTTP $HTTP_CODE  $(printf '%s' "$HTTP_BODY" | head -c 200)"
    fi
  fi
else
  skip "/predict-single" "未指定 --sample"
fi

if [ -n "$SCAN_DIR" ]; then
  t0=$(date +%s)
  http POST "$BASE_URL/predict-directory?directory=${SCAN_DIR}&recursive=false&include_de=false"
  t1=$(date +%s)
  if [ "$HTTP_CODE" = "200" ]; then
    ok "/predict-directory" "$((t1-t0))s total=$(jget Total) malicious=$(jget Malicious) benign=$(jget Benign)"
  else
    bad "/predict-directory" "HTTP $HTTP_CODE  $(printf '%s' "$HTTP_BODY" | head -c 200)  (directory 必须是容器内路径)"
  fi
else
  skip "/predict-directory" "未指定 --dir"
fi

# ── 汇总 ─────────────────────────────────────────────────────────────────────
printf '\n============================================================\n'
printf '  PASS %d   FAIL %d   SKIP %d\n' "$N_PASS" "$N_FAIL" "$N_SKIP"
printf '============================================================\n'
if [ "$N_FAIL" -gt 0 ]; then
  printf '  failed:\n'
  i=0
  for n in "${R_NAME[@]}"; do
    [ "${R_STAT[$i]}" = "FAIL" ] && printf '    - %-30s %s\n' "$n" "${R_NOTE[$i]}"
    i=$((i+1))
  done
fi
printf '\n  手工未覆盖的写操作（按需执行）：\n'
printf '    curl -s -X POST "%s/reload-model" | python3 -m json.tool\n' "$BASE_URL"
printf '    curl -s -X POST "%s/update-signatures?week_id=2026W41" -F "file=@<csv路径>" | python3 -m json.tool\n' "$BASE_URL"
printf '    Swagger: %s/docs      OpenAPI: %s/openapi.json\n' "$BASE_URL" "$BASE_URL"

[ "$N_FAIL" -eq 0 ]
