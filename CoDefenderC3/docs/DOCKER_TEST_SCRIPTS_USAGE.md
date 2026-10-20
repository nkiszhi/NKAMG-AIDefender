# docker/ 自动化测试与校验脚本 · 用法说明

> 适用范围：`CoDefenderC3/docker/` 下的 6 个脚本。
> 一句话定位：**4 个构建期静态校验 + 1 个运行时接口冒烟 + 1 个一键构建编排**。
> 本文只讲"怎么用"，接口逐条说明见 `docs/TESTING.md`，踩坑清单见 `docs/TESTING.md §6`。

---

## 0. 脚本总览

| 脚本 | 阶段 | 需要什么 | 是否需 docker / 运行态服务 | 退出码含义 |
|---|---|---|---|---|
| `stage_signatures.py` | 构建前 | 宿主 `signatures/` | 否 / 否 | 0 成功；非 0 失败 |
| `check_context.py` | 构建前 | `.docker_build/signatures/`（stage 产物） | 否 / 否 | **0 通过；2 有致命问题（别开始构建）** |
| `check_requirements.py` | 构建前 | 源码即可 | 否 / 否 | **0 硬依赖全覆盖；2 有未覆盖硬依赖；3 脚本自身出错** |
| `check_model_imports.py` | 构建前 | torch / torchvision 等模型依赖 | 否 / 否 | **0 无 FATAL；1 有 FATAL 或 `model_registry` 都进不来** |
| `test_api.sh` | 部署后 | 一个已在跑的 HTTP 服务 | 否（走 HTTP）/ **是** | **0 全过；1 有 FAIL 或打不通** |
| `build.sh` | 编排 | 上述全部 | 是（仅第 3 步） | 任一步失败即中断（`set -euo pipefail`） |

**执行顺序（推荐）**

```
① python docker/stage_signatures.py      # 解析 signatures/current → .docker_build/signatures/
② python docker/check_context.py         # COPY 源 / .dockerignore / 上下文体积 预检
③ python docker/check_requirements.py    # requirements.txt 是否覆盖真实依赖（纯 AST，不执行代码）
④ python docker/check_model_imports.py   # 34 个模型模块能否 import（抓 torchvision 代际错配）
⑤ docker build -t codefender-c3:v8 .     # ②~④ 全绿后再构建
⑥ docker run -d --name codefender -p 8000:8000 codefender-c3:v8
⑦ bash docker/test_api.sh                # 部署后冒烟
```

`build.sh` 就是把 ①②和⑤打包成一条命令（③④是你在需要时单独跑的自检）。

---

## 1. `test_api.sh` —— 容器接口冒烟测试（最常用）

不依赖 `jq`，自带 PASS/FAIL 汇总。**只读**：只打 `GET` 端点，不改任何状态。

### 1.1 基本用法

```bash
# 在 VM 里打容器（默认 http://localhost:8000）
bash docker/test_api.sh

# 从 Windows 打 VM 里的容器（URL 必须是 VM 的 IP，不能是 localhost）
BASE_URL=http://192.168.186.128:8000 bash docker/test_api.sh

# 追加真实推理：单文件（样本路径按"执行脚本的那一侧"给）
bash docker/test_api.sh --sample /mnt/hgfs/VM_Share/testsamples/benign/<文件名>

# 追加真实推理：目录扫描（directory 是**容器内**路径，见 1.3）
bash docker/test_api.sh --dir /data/samples

# 强制要求容器档位：env 不是 prod 直接判 FAIL（防止误测到宿主 dev 实例）
bash docker/test_api.sh --expect-prod

# 放宽单请求超时（默认 90s）。/health 要统计三库条数，实测 3~6s，别调太小
TIMEOUT=180 bash docker/test_api.sh

# 看帮助
bash docker/test_api.sh --help
```

### 1.2 参数与环境变量

| 名称 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `--sample <path>` | 参数 | — | 追加 `POST /predict-single`，本地找不到文件则 SKIP |
| `--dir <path>` | 参数 | — | 追加 `POST /predict-directory`，**必须是服务端（容器内）路径** |
| `--expect-prod` | 参数 | 关 | 要求 `/health` 的 `env == prod`，否则该用例 FAIL |
| `-h/--help` | 参数 | — | 打印脚本头部注释（即用法） |
| `BASE_URL` | 环境变量 | `http://localhost:8000` | 被测地址 |
| `TIMEOUT` | 环境变量 | `90` | 单请求 `curl -m` 秒数 |
| `CURL_NOPROXY` | 环境变量 | `localhost,127.0.0.1,::1` | 对回环地址绕过代理；给了远端且必须走代理时用 `CURL_NOPROXY=''` 覆盖 |

### 1.3 测试覆盖范围

| 阶段 | 端点 | 判据 |
|---|---|---|
| 0/6 可达性 | `GET /livez` | 非 000/502；否则**直接 abort 并打印排查顺序** |
| 1/6 探针 | `GET /livez` → `GET /readyz` | `alive=true`；`ready=true` 且 HTTP 200 |
| 2/6 健康/档位 | `GET /health` | HTTP 200；打印 `env` / `engine_mode` / `require_hash_db` / 三库计数 |
| 3/6 指标 | `GET /metrics` | HTTP 200 |
| 4/6 模型档案 | `GET /model-info` | HTTP 200；打印 `status` / `model_count` / `view_count` |
| 5/6 运行时配置 | `GET /admin/config` | HTTP 200 |
| 6/6 推理（可选） | `POST /predict-single`、`POST /predict-directory` | HTTP 200 |

**刻意不覆盖**（会改状态，需手工执行）：`POST /reload-model`、`POST /update-signatures`。
脚本末尾会把这两条的 curl 命令打出来，照抄即可。

### 1.4 三个必踩的坑（脚本已按正确姿势写好）

1. **`include_de` 是 query 参数，不是表单字段。**
   `-F "include_de=false"` **不报错但被静默忽略** → D/E 特征照跑，单样本耗时从 2~3s 涨到 30~130s（BinaryNinja）。
   正确写法：`curl -X POST ".../predict-single?include_de=false" -F "file=@x.exe"`。
   `recursive` / `directory` 同理，全是 query。用 `GET /openapi.json` 可一眼确认参数位置。
2. **shell 里的 `HTTP_PROXY` 会把本地请求截走。**
   现象：服务没起，却收到 `502 upstream connect failed`（而不是 `Connection refused`），极易误判成"容器启动失败"。
   脚本默认对回环地址加 `--noproxy`；手工 curl 时加 `--noproxy '*'`。
3. **`predict-directory` 的 `directory` 是容器内路径。**
   镜像对签名库零挂载，但样本目录可以挂：
   ```bash
   docker run -d --name codefender -v /mnt/hgfs/VM_Share/testsamples:/data/samples:ro -p 8000:8000 codefender-c3:v8
   # 或已起的容器里塞一份
   docker cp /mnt/hgfs/VM_Share/testsamples codefender:/data/samples
   ```
   `predict-single` 不受影响（文件是 HTTP 上传）。
   ⚠️ 在 Windows 上给 `predict-single` 传**恶意**样本会 500（杀软隔离 `%TEMP%`）→ 用良性样本，或改用 `predict-directory`。

### 1.5 `env=dev` 还是容器？看 `/health` 四个字段，别猜

| 字段 | 宿主 dev 实例 | 容器（prod） |
|---|---|---|
| `env` | `dev` | `prod` |
| `model_path` | `D:\...\ensemble.pkl` | `/app/ensemble.pkl` |
| `require_hash_db` | `false` | `true` |
| `runtime_cfg_file_enabled` | `true` | `false` |

脚本会自动提示：`model_path` 不是 `/app/ensemble.pkl` 时打印
`[note] ... 这不是容器内的服务（宿主 dev 实例？）`；
要把它变成硬判据就加 `--expect-prod`。

---

## 2. `check_requirements.py` —— requirements.txt 覆盖度校验

纯 AST 分析，**不执行任何业务代码**，1 秒出结果。从 `engine/app.py` 出发做导入闭包，
把闭包内触达的第三方模块与 `requirements.txt` 逐条比对，按导入方式分三档：
`hard`（顶层 import，缺了服务起不来）/ `guarded`（try 包裹，缺失自动降级）/ `lazy`（函数体内 import）。

```bash
python docker/check_requirements.py          # 运行时闭包（严格，推荐）
python docker/check_requirements.py --all    # 连 train/ _tools/ 全仓一起查
python docker/check_requirements.py -v       # 打印每个模块的导入位置
```

退出码：`0` 硬依赖全覆盖 ｜ `2` 有未覆盖硬依赖（会列出该加的包名）｜ `3` 脚本自身出错。

## 3. `check_context.py` —— 构建上下文预检

`docker build` 要过 1.7GB 上下文，路径写错或被 `.dockerignore` 误挡的代价是几十分钟白跑。
本脚本把三类失败前移到 1 秒内：**COPY 源不存在** / **COPY 源被 `.dockerignore` 整目录挡掉** / **上下文体积失控**。
同时输出"将被 COPY 进镜像的文件数与字节数"，可用于和 `docker images` 对账。

```bash
python docker/check_context.py                                    # 用 Dockerfile 里的默认 ARG
python docker/check_context.py --build-arg MODEL_FILE=runs/run-5k-0917/ensemble.pkl
python docker/check_context.py --dockerfile Dockerfile --context .
```

退出码：`0` 通过 ｜ `2` 有致命问题（不要开始构建）。

> ⚠️ 前置条件：必须先跑过 `stage_signatures.py`，否则 `.docker_build/signatures/` 不存在会报 COPY 源缺失。

## 4. `check_model_imports.py` —— 模型模块导入探针

把"改代码改坏了"提前到 **构建期** 红掉，而不是等容器起来打 `/health` 才发现。
判定口径**刻意与运行期逐字对齐**（`models/ensemble.py::MultiModelEnsemble._load_model_class()` 只吞
`KeyError/ImportError/AttributeError`）：

- 这三类异常 → 记 **WARN**，不阻断构建（运行期也只是"这票缺席"，服务照跑）
- 其它异常（典型如 torchvision 代际错配的 `operator torchvision::nms does not exist`）→ 记 **FATAL**，`exit 1`

```bash
python docker/check_model_imports.py          # 仓库根
python3 /app/docker/check_model_imports.py    # 容器内（镜像里有一份）
```

退出码：`0` 无 FATAL ｜ `1` 存在 FATAL 或 `model_registry` 本身都进不来。

## 5. `stage_signatures.py` —— 签名库暂存器

把当前生效的一整套签名库（sha256 / md5 / fuzzy）整理成干净的构建上下文，供
`COPY ${SIG_STAGE}/ ./signatures/` 使用。

```bash
python docker/stage_signatures.py
```

做三件事：① 剔除 `-wal`/`-shm`/`*.legacy`/`*.tmp` 等半成品；
② 优先**硬链接**（同卷零拷贝），跨卷/共享目录自动退回复制；
③ 生成两份清单 —— 内容清单 `_staging_manifest.json`（**不含时间戳**，避免 Docker COPY 缓存失效）
放在 COPY 源内，运行信息 `staging_run.json` 放在源外。

因为 `signatures/current` 是**指向上下文外部的绝对路径软链接**，Docker 无法穿透，
所以这一步不能用 Dockerfile 直接 `COPY signatures/` 替代。

## 6. `build.sh` —— 一键构建编排

```bash
bash docker/build.sh                        # 默认 tag: codefenderc3:v8
bash docker/build.sh codefenderc3:v8.1      # 指定 tag
bash docker/build.sh codefenderc3:v8 --no-cache
PYTHON=/d/work/tools/miniconda3/python.exe bash docker/build.sh   # 指定解释器
```

内部顺序：`stage_signatures.py` → `check_context.py` → `docker build -t <TAG> .`（`set -e`，任一步失败即停）。

> ⚠️ 构建上下文路径 `.` 必须补在**引号外、命令最后**（`docker build [OPTIONS] PATH`，buildx 同样要求 PATH 在末位）。
> 写成 `"${TAG} ."` 会把空格并进 tag 名，报 `docker buildx build requires 1 argument`。脚本已 `cd "$ROOT"` 处理。

---

## 7. 环境变量速查（脚本相关）

| 变量 | 作用 | 默认 |
|---|---|---|
| `BASE_URL` | `test_api.sh` 被测地址 | `http://localhost:8000` |
| `TIMEOUT` | `test_api.sh` 单请求超时（秒） | `90` |
| `CURL_NOPROXY` | `test_api.sh` 绕过代理的地址列表；`''` 表示不绕过 | `localhost,127.0.0.1,::1` |
| `PYTHON` | `build.sh` 解释器 | 依次探测 `python3` / `python` / `py` |
| `CODEFENDER_ROOT` | `check_model_imports.py` 仓库根 | 脚本的父目录 |
| `CODEFENDER_ENV` | 服务档位 `dev` / `prod` | — |

## 8. 最短排障路径

```
打不通 /livez      → ① docker ps  ② docker run 有没有 -p 8000:8000
                      ③ 从 Windows 打要用 VM 的 IP  ④ 502 upstream connect failed = 被代理截走
/readyz 503        → 见 docs/TEST-RECORD-2026-10-14.md 缺陷 D1（模型懒加载）
/health 慢          → 正常，要统计三库条数，3~6s
/docs 白屏          → 静态资源来自 cdn.jsdelivr.net，离线环境改用 /openapi.json
结果只有 PASS/FAIL → 看脚本末尾手动列出的 curl，或 docs/TESTING.md §3 逐条测
```
