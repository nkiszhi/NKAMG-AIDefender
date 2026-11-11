# CoDefenderC3 启动与接口说明

核对日期：2026-11-11。[全部文档索引](INDEX.md)。

CoDefenderC3 是 PE 文件检测服务。当前部署模型包含 33 个模型、15 个视图组；配置/注册表还保留 V11 候选模型，不能按源码目录数推断部署数量。实际参与推理的模型取决于特征是否可用，以 `/model-info` 和模型覆盖统计为准。

## 1. 服务入口

推荐统一执行 `python -m engine.serve`：三个入口共享同一进程、模型实例和扫描运行时，不要分别启动多个 Uvicorn worker。

| 入口 | ASGI 应用 | 默认监听地址 | 用途 |
|---|---|---|---|
| Web 兼容 | `engine.web_compat:app` | `0.0.0.0:8000` | 原 Web 返回结构，支持流式检测 |
| 生产精简 | `engine.app:app` | `127.0.0.1:18001` | 仅返回业务必需字段 |
| 开发诊断 | `engine.dev.app:app` | `127.0.0.1:18002` | 保留分数、漂移和模型诊断，默认不开启 |

**环境配置与返回协议是两件事**：`CODEFENDER_ENV=dev/prod` 控制运行配置；请求哪个入口决定返回结构。把生产入口的环境改为 `dev`，不会变成开发响应。

以下命令从仓库根目录进入 `CoDefenderC3/` 执行；Web 前后端命令除外。开发和生产示例均将 Web 兼容入口映射到本机 `8001`，以匹配现有 Web 配置。

## 2. 开发环境启动

### 2.1 安装依赖

准备 Python 环境（本机验证使用 Python 3.11），并确保 `CoDefenderC3/ensemble.pkl` 存在；其他模型路径可通过 `CODEFENDER_MODEL_PATH` 指定。

```powershell
cd CoDefenderC3
python -m venv .venv
./.venv/Scripts/Activate.ps1
python -m pip install "torch>=2.0" torchvision --index-url https://download.pytorch.org/whl/cpu
python -m pip install torch_geometric
python -m pip install -r requirements.txt
```

Linux 激活命令为 `source .venv/bin/activate`。已有可用环境时可跳过创建虚拟环境。PyTorch、torchvision、torch_geometric 需单独安装；SMDA 已在 `requirements.txt` 中，无需商业授权。使用 BinaryNinja 时需另行安装并提供有效许可证。

### 2.2 启动共享模型服务（推荐）

本例关闭哈希预检，全部样本走模型；同时禁用运行时覆盖文件，避免旧的 `runtime_config.json` 覆盖启动参数。

**Windows PowerShell：**

```powershell
$env:PYTHONIOENCODING = "utf-8"
$env:CODEFENDER_ENV = "dev"
$env:CODEFENDER_DISASM_BACKEND = "smda"
$env:CODEFENDER_HASH_DB_ENABLED = "0"
$env:CODEFENDER_FUZZY_DB_ENABLED = "0"
$env:CODEFENDER_REQUIRE_HASH_DB = "0"
$env:CODEFENDER_RUNTIME_CFG_DISABLE = "1"
$env:CODEFENDER_WEB_COMPAT_HOST = "127.0.0.1"
$env:CODEFENDER_WEB_COMPAT_PORT = "8001"
$env:CODEFENDER_PRODUCTION_HOST = "127.0.0.1"
$env:CODEFENDER_PRODUCTION_PORT = "18001"
$env:CODEFENDER_ENABLE_DEV_API = "1"
$env:CODEFENDER_DEV_PORT = "18002"
python -m engine.serve
```

**Linux / Bash：**

```bash
CODEFENDER_ENV=dev CODEFENDER_DISASM_BACKEND=smda \
CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 \
CODEFENDER_REQUIRE_HASH_DB=0 CODEFENDER_RUNTIME_CFG_DISABLE=1 \
CODEFENDER_WEB_COMPAT_HOST=127.0.0.1 CODEFENDER_WEB_COMPAT_PORT=8001 \
CODEFENDER_PRODUCTION_HOST=127.0.0.1 CODEFENDER_PRODUCTION_PORT=18001 \
CODEFENDER_ENABLE_DEV_API=1 CODEFENDER_DEV_PORT=18002 \
python -m engine.serve
```

只需开发模型接口时，可改用 `dev_model_only.cmd`（Windows）或 `bash dev_model_only.sh`（Linux）。脚本默认监听 `18002`，**不提供 Web 兼容/流式入口**，不要与共享服务重复占用端口。

另开终端检查就绪状态：

```bash
curl http://127.0.0.1:8001/readyz
curl http://127.0.0.1:18001/readyz
curl http://127.0.0.1:18002/readyz
```

以 HTTP 200 且 `ready=true` 为准；`/health` 用于查看配置和服务状态，不能代替就绪探针。

### 2.3 启动 Web 前后端（可选）

在独立终端从仓库根目录启动后端：

```powershell
cd web
if (-not (Test-Path config.ini)) { Copy-Item config.example.ini config.ini }
cd FastAPI
python -m pip install -r requirements.txt
python main.py
```

Linux 可用 `test -f config.ini || cp config.example.ini config.ini` 创建配置。检查 `web/config.ini`：`server.port=5006`、`codefender.api_base=http://127.0.0.1:8001`、`scan_endpoint` 留空，`include_de=true`。

另开终端启动前端（需可运行 Vite 6 的 Node.js/npm）：

```bash
cd web/Vue
npm ci
npm run dev
```

访问 `http://127.0.0.1:9528`；前端将 `/api-backend` 代理到 `127.0.0.1:5006`。未配置 MySQL 时可验证模型检测，但数据库查询、历史和统计数据不代表真实数据库结果。

**现有 Web 必须连接 Web 兼容入口**，不能直接改接生产精简入口，否则会缺少逐模型分数及流式接口。

## 3. 生产环境启动

### 3.1 标准全引擎镜像

准备：Docker、基础镜像 `multiscan_basic_v3:with_binja`、有效的 `license.txt`、`ensemble.pkl`，以及完整的 SHA256 / MD5 / fuzzy 签名库。构建脚本会解析当前签名库并暂存到 `.docker_build/signatures/`。

```bash
cd CoDefenderC3
bash docker/build.sh codefender-c3:prod --progress=plain

docker run -d --name codefender-c3-prod --restart unless-stopped \
  -p 127.0.0.1:8001:8000 -p 127.0.0.1:18001:18001 \
  -e CODEFENDER_PRODUCTION_HOST=0.0.0.0 \
  -e CODEFENDER_ENABLE_DEV_API=0 \
  codefender-c3:prod
```

镜像及 Supervisor 配置固定为 `CODEFENDER_ENV=prod`、哈希/模糊预检开启、`CODEFENDER_REQUIRE_HASH_DB=1`、运行时覆盖文件禁用。必需签名库缺失时拒绝启动。统一启动默认选择 SMDA；标准镜像虽含 BN 环境和许可证，仍需显式 `CODEFENDER_DISASM_BACKEND=bn` 才选择 BN。

代码、模型和签名库已打进镜像，无需挂载；不要随意挂卷覆盖 `/app/signatures`。容器内部生产入口默认只监听回环地址，因此上例显式设为 `0.0.0.0` 才能进行端口映射；宿主端口仍仅本机可访问。

### 3.2 SMDA 纯模型镜像（评估/对照）

不依赖 BinaryNinja 和签名库；构建仍需 `ensemble.pkl` 及 Dockerfile COPY 所需源码（含本地 `insn_categories.py`）：

```bash
docker build -f Dockerfile.smda -t codefender-c3:smda --progress=plain .
docker run -d --name codefender-c3-smda --restart unless-stopped \
  -p 127.0.0.1:8001:8000 -p 127.0.0.1:18001:18001 \
  -e CODEFENDER_PRODUCTION_HOST=0.0.0.0 \
  -e CODEFENDER_ENABLE_DEV_API=0 \
  codefender-c3:smda
```

与标准镜像二选一，避免端口冲突。`Dockerfile.smda` 同样使用 `prod` 配置和生产响应入口，但关闭哈希预检、`engine_mode=model_only`；**不能把它当成完整签名库生产部署**。

### 3.3 检查与更新

```bash
curl http://127.0.0.1:18001/readyz
curl http://127.0.0.1:18001/health
docker logs --tail 100 codefender-c3-prod
docker exec codefender-c3-prod tail -n 100 /var/log/supervisor/codefender_err.log
```

标准镜像检查 `env=prod`、`engine_mode=hash_db+model`、`require_hash_db=true`。代码、模型或镜像内签名库更新后需**重建镜像并重建容器**，仅 `docker restart` 不会载入新镜像内容。

生产默认不开开发接口。对外部署请通过鉴权反向代理暴露所需业务路由，不要公开 `/admin/config`、`/reload-model`、`/update-signatures` 或完整诊断入口。

## 4. 接口返回数据差异

以下对照主要适用于 `/predict-single` 和 `/predict-directory`；管理、探针及 `/model-info` 沿用共享契约，不因生产入口而自动裁剪。

| 数据/能力 | 生产精简（18001） | 开发诊断（18002） | Web 兼容（本例 8001） |
|---|---|---|---|
| `MD5`、`SHA256`、`IsMalicious`、`Packed` | 保留 | 保留 | 保留 |
| `ScanResult.VirusName` | 统一业务命名 | 与生产一致 | 沿用原 Web 契约，不保证包含 |
| `CRC32`、`FileName`、`FileSize`、`Score`、`Status`、`StatusLabel` | 移除 | 保留 | 保留 |
| `ScanResult.PerModelScores` | 移除 | 保留成功参与集成的模型分数 | 保留 |
| `ScanResult.PerModelPreds`、`PerModelDetails` | 移除 | 移除 | 保留（按结果提供） |
| `ScanResult.ModelStats` | 移除 | 保留统计/排除原因，移除 `AggregatedModels` | 沿用原结构 |
| 漂移证据、异常分数、哈希命中信息及耗时 | 移除 | 按检测路径提供；并非每个结果都有 | 沿用原结构 |
| 目录汇总 | 仅 5 个计数，超时并入 `ErrorCount` | 保留计数、`TimeoutCount`、目录和耗时 | 沿用原结构 |
| `/predict-stream` | 不提供 | 不提供 | 提供 NDJSON 流 |

开发接口明确删除的字段路径是 `ScanResult.PerModelPreds`、`ScanResult.PerModelDetails`、`ScanResult.ModelStats.AggregatedModels`，字段直接不存在，不是返回 `null`。

生产/开发的 `VirusName`：哈希命中为 `Malicious`，模型良性为 `Benign`，模型恶意为 `Generic.ML.Low/Medium/High`。开发状态还可为 `Status=2`（`DriftSuspect`），不要仅按状态码是否非零判断恶意，以 `IsMalicious` 为准。

### 4.1 生产单文件返回

```json
{
  "MD5": "f9cec765e2b106c5e4e91e3e5b4d9d68",
  "SHA256": "f21b30a4d1f441b89da6fc75b575a5417a70cfbefa2413d6b4de911531e30727",
  "IsMalicious": false,
  "ScanResult": {
    "VirusName": "Benign",
    "Packed": {
      "IsPacked": false,
      "PackerName": "",
      "IsArchive": false,
      "ArchiveName": ""
    }
  }
}
```

目录返回为 `{ "Summary": {...}, "Results": [...] }`。Summary 仅有 `TotalFiles`、`ScannedFiles`、`MaliciousCount`、`BenignCount`、`ErrorCount`；成功条目在上述结构上增加 `FilePath`，失败条目用 `Error` 代替 `ScanResult`，不能把失败条目的 `IsMalicious=false` 当成良性。

### 4.2 开发单文件返回（节选）

除生产业务字段外，保留以下诊断结构；示例省略其他模型和字段，数值仅用于展示结构：

```json
{
  "Status": 0,
  "StatusLabel": "Benign",
  "IsMalicious": false,
  "Score": 0.4280683398246765,
  "ScanResult": {
    "VirusName": "Benign",
    "PerModelScores": { "MalConv": 0.28502440452575684 },
    "DriftEvidence": { "surface": 0, "structure": 0, "global": 0 },
    "SampleDriftType": "none",
    "AnomalyScore": 0,
    "IsDriftCandidate": false,
    "ModelStats": { "TotalModels": 33, "OkModels": 23, "SkippedModels": 10, "ErrorModels": 0 }
  }
}
```

## 5. API 速查

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/livez`、`/readyz` | 存活/就绪探针 |
| GET | `/health`、`/metrics`、`/model-info` | 状态、运行指标、模型信息 |
| POST | `/predict-single` | multipart 上传 `file`；`include_de` 为查询参数 |
| POST | `/predict-directory` | 查询参数 `directory` 必填，`recursive=true`、`include_de=false` 默认 |
| POST | `/predict-stream` | 仅 Web 入口，multipart 上传，NDJSON 进度及结果 |
| GET / POST | `/admin/config` | 查询/调整共享运行配置 |
| POST | `/reload-model`、`/update-signatures` | 重载模型/更新签名库，限内部运维 |

```bash
# 完整特征检测；Windows PowerShell 建议使用 curl.exe
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@sample.exe"

# directory 是模型服务所在机器/容器可访问的绝对路径，不是客户端路径
curl -X POST -G "http://127.0.0.1:18001/predict-directory" \
  --data-urlencode "directory=/data/samples" --data-urlencode "recursive=true" \
  --data-urlencode "include_de=true"

# Web 流式检测
curl -N -X POST "http://127.0.0.1:8001/predict-stream?include_de=true" -F "file=@sample.exe"
```

- 检测按内容识别 PE，不依赖扩展名；`include_de=false` 会跳过依赖反汇编/图特征的模型，不能视为全部 33 个模型已执行。
- 同步接口非法文件返回 HTTP 错误；流式接口可能已返回 HTTP 200，再用终止 `error` 事件报告失败。客户端必须检查 NDJSON 的 `progress`、`result`、`heartbeat`、`error` 事件，不能只看 HTTP 状态。
- 三个入口共享配置及重载状态：在开发入口修改配置也会影响同进程的生产/Web 入口。
- 开发默认支持 `runtime_config.json`，优先级为运行时 API > 覆盖文件 > 环境变量 > 默认值。上面的共享启动例禁用了文件；如需落盘覆盖，去掉 `CODEFENDER_RUNTIME_CFG_DISABLE`。标准生产配置禁止文件读写，`persist`/`reload_file` 请求返回 409；内存修改不持久化。
- 各入口的 `/docs` 和 `/openapi.json` 可查看请求参数；生产裁剪及开发诊断字段以本节和对应投影代码为准。

## 6. 延伸文档

- [全部文档索引](INDEX.md)

- [开发响应字段](DEV_RESPONSE_FIELDS.md)
- [SMDA 后端](SMDA_BACKEND.md)
- [测试指南](TESTING.md) / [Docker 测试脚本](DOCKER_TEST_SCRIPTS_USAGE.md)
- [训练说明](../train/README.md) / [模型论文](PAPERS.md)
