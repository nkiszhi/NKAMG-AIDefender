# CoDefenderC3 Docker 部署与接口测试指南

---

## 1. 导入镜像

```bash
docker load -i codefender_latest.tar.gz
```

导入后确认镜像已加载：

```bash
docker images codefender
```

---

## 2. 启动容器

镜像**已内嵌代码 + 签名库 + ensemble.pkl**，不做任何挂载即可直接跑（全引擎）。

```bash
docker run -d --name codefender \
  -p 8000:8000 --ulimit nofile=65535:65535 \
  codefender-c3:v8
```

需要扫描宿主样本时再挂样本目录（只读）：

```bash
docker run -d --name codefender \
  -v /mnt/hgfs/VM_Share/testsamples:/data/samples --ulimit nofile=65535:65535 \
  -p 8000:8000 \
  codefender-c3:v8
```

| 参数 | 说明 |
|------|------|
| `-d` | 后台运行 |
| `--name codefender` | 容器名称 |
| `-v /mnt/hgfs/VM_Share/testsamples:/data/samples:ro` | 挂载宿主机样本目录（只读，可选） |
| `-p 8000:8000` | 端口映射 |
| `codefender-c3:v8` | 镜像名:标签 |

> ✅ **签名库随镜像内嵌，零挂载**：镜像里 `/app/signatures` 已是可用的**扁平**布局
> （`<base>.db.shards|bloom`，无 `current`/`releases`），开箱即用，`docker run` 不需要任何 `-v`。
> **不要**给 `/app/signatures` 挂卷 —— 那会让容器读到与镜像版本脱钩的旧库；也**严禁**把
> VMware 共享目录（hgfs）挂上去（SQLite 分片库的 POSIX 锁在 hgfs 上不可靠）。
>
> `POST /update-signatures`（见 3.9）的发布结果会落在 **容器可写层**：容器重启仍在，
> `docker rm` 即回滚到镜像里那一版。要**固化**就走「换库 = 换镜像」：
> `python docker/stage_signatures.py && docker build -t codefender-c3:v8.1 .`

### 等待模型加载

模型加载约需 30~60 秒，使用 `/readyz` 就绪探针轮询等待：

```bash
while ! curl -s http://localhost:8000/readyz | grep -q '"ready":true'; do
  echo "waiting for model to load..."
  sleep 5
done
echo "Model ready!"
```

---

## 3. 接口测试

支持 Swagger UI 文档，访问以下地址查看 API 文档：
http://localhost:8000/docs

全部 11 个端点：

| 分类 | 端点 | 测试章节 |
|------|------|----------|
| 探针/指标 | `GET /livez` | 3.1 |
| 探针/指标 | `GET /readyz` | 3.2 |
| 探针/指标 | `GET /metrics` | 3.3 |
| 探针/指标 | `GET /health` | 3.4 |
| 业务 | `POST /predict-single` | 3.5 |
| 管理 | `GET /model-info` | 3.6 |
| 管理 | `POST /reload-model` | 3.7 |
| 业务 | `POST /predict-directory` | 3.8 |
| 管理 | `POST /update-signatures` | 3.9 |
| 管理 | `GET\|POST /admin/config` | 3.10 |

### 3.1 存活探针 `/livez`

```bash
curl -s http://localhost:8000/livez | python -m json.tool
```

预期输出：
```json
{
  "alive": true,
  "uptime_sec": 60,
  "uptime_human": "00:01:00"
}
```

> 该端点不接触模型，即使模型加载失败也会返回 `alive: true`。仅用于检测进程是否存活。

---

### 3.2 就绪探针 `/readyz`

```bash
curl -s http://localhost:8000/readyz | python -m json.tool
```

**模型已加载时 (HTTP 200)**：
```json
{
  "ready": true,
  "model_count": 33,
  "view_count": 16
}
```

**模型未加载时 (HTTP 503)**：
```json
{
  "ready": false,
  "reason": "model not loaded",
  "model_path": "/app/ensemble.pkl"
}
```

> K8s `readinessProbe` 应指向 `/readyz`，HTTP 503 时调度器不会将流量路由到该 Pod。

---

### 3.3 运行时指标 `/metrics`

```bash
curl -s http://localhost:8000/metrics | python -m json.tool
```

预期输出（字段含义见下表）：

| 字段 | 说明 |
|------|------|
| `total_requests` | 服务启动以来总请求数 |
| `predict_single_ok` / `predict_single_error` | 单文件检测成功/失败计数 |
| `predict_dir_ok` / `predict_dir_error` | 目录扫描成功/失败计数 |
| `scan_files_total` | 累计扫描文件数 |
| `scan_files_malicious` | 累计检出恶意文件数 |
| `scan_files_benign` | 累计检出正常文件数 |
| `last_predict_ms` | 最近一次预测耗时 (ms) |
| `unhandled_errors` | 未处理异常计数 |
| `uptime_sec` | 服务运行时长 (秒) |
| `models_loaded` | 模型是否已加载 |
| `model_count` | 集成子模型数量 |

---

### 3.4 健康检查

```bash
curl -s http://localhost:8000/health | python -m json.tool
```

预期输出：

```json
{
  "status": "ok",
  "model_path": "/app/ensemble.pkl",
  "model_count": 33,
  "view_count": 16,
  "malgraph": {
    "enabled": true,
    "status": "ready",
    "device": "cpu"
  }
}
```

---

### 3.5 单文件检测

```bash
curl -s -X POST "http://localhost:8000/predict-single?include_de=false" \
  -F "file=@/mnt/hgfs/VM_Share/testsamples/<样本文件名>" | python -m json.tool
```

> 将 `<样本文件名>` 替换为实际样本文件名。
>
> ⚠️ `include_de` 是 **query 参数**，必须写成 `?include_de=false`。
> 写成 `-F "include_de=false"`（旧文档的写法）**不报错但会被静默忽略**，
> D/E 特征照跑 → 单样本耗时从 2~3s 涨到 30~130s（BinaryNinja）。

预期输出（关键字段）：

```json
{
  "MD5": "...",
  "SHA256": "...",
  "FileName": "...",
  "FileSize": ...,
  "Status": 1,
  "StatusLabel": "Malicious",
  "IsMalicious": true,
  "Score": 0.8734,
  "ScanResult": {
    "VirusName": "...",
    "Packed": {
      "IsPacked": false,
      "PackerName": ""
    },
    "PerModelScores": { ... },
    "PerModelPreds": { ... },
    "DriftEvidence": {
      "surface": 0.0,
      "structure": 0.0,
      "global": 0.0
    },
    "SampleDriftType": "normal",
    "AnomalyScore": 0.0,
    "IsDriftCandidate": false,
    "ModelStats": {
      "TotalModels": 33,
      "OkModels": 30,
      "SkippedModels": 3,
      "ErrorModels": 0,
      "MaliciousVotes": 28,
      "BenignVotes": 2,
      "AgreementRate": 0.9333,
      "EnsembleScore": 0.8734,
      "EnsemblePred": 1
    }
  }
}
```

| 核心字段 | 含义 |
|----------|------|
| `Status` | 0=Benign, 1=Malicious, 2=DriftSuspect |
| `IsMalicious` | 集成判定结果 |
| `Score` | 集成模型恶意度得分 (0~1) |
| `ModelStats.AgreementRate` | 子模型投票一致率 |
| `DriftEvidence` | 三层次漂移证据 |

---

### 3.6 病毒库信息 `/model-info`

```bash
curl -s http://localhost:8000/model-info | python -m json.tool
```

预期输出包含 `file.md5`、`ensemble.model_count`、`models[]` 等字段。
`file.md5` 用于校验模型文件完整性。

---

### 3.7 模型热更新 `/reload-model`

```bash
# 原地重载
curl -s -X POST http://localhost:8000/reload-model | python -m json.tool

# 切换到新模型
curl -s -X POST "http://localhost:8000/reload-model?model_path=/data/models/ensemble.pkl" | python -m json.tool
```

---

### 3.8 批量目录扫描

```bash
curl -s -X POST "http://localhost:8000/predict-directory?directory=/data/samples&recursive=true&include_de=false" | python -m json.tool
```

预期输出（顶层固定两块：`Summary` 统计 + `Results` 逐文件明细）：

```json
{
  "Summary": {
    "TotalFiles": 100,
    "TotalFilesInDirectory": 102,
    "SkippedNonPE": 2,
    "ScannedFiles": 98,
    "MaliciousCount": 73,
    "BenignCount": 25,
    "ErrorCount": 0.0,
    "TimeoutCount": 0.0,
    "Directory": "/data/samples",
    "Timing": {
      "TotalTime": 61.234,
      "ModelLoadTime": 0.0,
      "BatchScanTime": 61.234,
      "AvgSampleTime": 0.625,
      "MedianSampleTime": 0.611,
      "MinSampleTime": 0.412,
      "MaxSampleTime": 1.204,
      "Throughput": 1.633
    }
  },
  "Results": [
    {
      "MD5": "2c31796a3334a3797243ae0d2f83e458",
      "SHA256": "0004381360553d67780bfef0b61fa6a0caef43b9533f7586033fcef93d9cc769",
      "CRC32": "b3d1c452",
      "FileName": "sample1.exe",
      "FileSize": 23738,
      "Status": 1.0,
      "StatusLabel": "Malicious",
      "IsMalicious": true,
      "Score": 0.550718,
      "ScanResult": {
        "VirusName": "Trojan.PEs.00043813",
        "Packed": {
          "IsPacked": false,
          "PackerName": "",
          "IsArchive": false,
          "ArchiveName": ""
        },
        "PerModelScores": {
          "MalConv": 0.5,
          "MalConv2": 0.54017,
          "ByteTransformer": 0.968524,
          "SaxeBerlinDNN": 0.641813,
          "EmberDNN": 0.798209,
          "NatarajKNN": 0.238401,
          "DrebinSVM": 0.554038,
          "DL4MD": 1.0,
          "PEMinerRF": 0.691002,
          "DrebinImport": 0.473582,
          "ALOHANet": 0.39014,
          "EmberGBDT_Import": 0.474975,
          "RaffFeatureNet": 0.454618,
          "DrebinString": 0.409904,
          "OpcodeLSTM": 0.5,
          "OpcodeTransformer": 0.5,
          "OpcodeStatNet": 0.5,
          "AsmEmbedNet": 0.5,
          "MalGraph": 0.5,
          "CFGGAT": 0.5,
          "CFGGCN": 0.5,
          "CFGDGCNN": 0.5,
          "CallGraphGNN": 0.5,
          "GraphStatNet": 0.5,
          "GrayscaleCNN": 0.468996,
          "InceptionV3": 0.473481,
          "IMCFN": 0.5,
          "ColorCNN": 0.5,
          "MarkovCNN": 0.17313,
          "EntropyMapCNN": 0.44659,
          "HashEmbedNet": 0.887563,
          "MetadataNet": 0.472179,
          "ResourceNet": 0.507532
        },
        "PerModelPreds": {
          "MalConv": 0.0,
          "MalConv2": 1.0,
          "ByteTransformer": 1.0,
          "SaxeBerlinDNN": 1.0,
          "EmberDNN": 1.0,
          "NatarajKNN": 0.0,
          "DrebinSVM": 1.0,
          "DL4MD": 1.0,
          "PEMinerRF": 1.0,
          "DrebinImport": 0.0,
          "ALOHANet": 0.0,
          "EmberGBDT_Import": 1.0,
          "RaffFeatureNet": 0.0,
          "DrebinString": 0.0,
          "OpcodeLSTM": 0.0,
          "OpcodeTransformer": 0.0,
          "OpcodeStatNet": 0.0,
          "AsmEmbedNet": 0.0,
          "MalGraph": 0.0,
          "CFGGAT": 0.0,
          "CFGGCN": 0.0,
          "CFGDGCNN": 0.0,
          "CallGraphGNN": 0.0,
          "GraphStatNet": 0.0,
          "GrayscaleCNN": 0.0,
          "InceptionV3": 0.0,
          "IMCFN": 0.0,
          "ColorCNN": 0.0,
          "MarkovCNN": 0.0,
          "EntropyMapCNN": 0.0,
          "HashEmbedNet": 1.0,
          "MetadataNet": 0.0,
          "ResourceNet": 1.0
        },
        "DriftEvidence": {
          "surface": 0.0,
          "structure": 0.0,
          "global": 0.0
        },
        "SampleDriftType": "none",
        "AnomalyScore": 0.0,
        "IsDriftCandidate": false,
        "ModelStats": {
          "TotalModels": 33,
          "OkModels": 33,
          "SkippedModels": 0.0,
          "ErrorModels": 0.0,
          "MaliciousVotes": 9,
          "BenignVotes": 24,
          "AgreementRate": 0.2727,
          "EnsembleScore": 0.550718,
          "EnsemblePred": 1.0,
          "ScoreRange": [0.2384, 1.0]
        }
      },
      "FilePath": "/data/samples/sample1.exe",
      "ProcessingTime": 0.625
    }
  ]
}
```

#### `ScanResult` 字段说明

| 字段 | 类型 | 含义 |
|------|------|------|
| `VirusName` | str | 恶意家族标签，格式 `<类型>.<家族>.<SHA256 前 8 位>`（如 `Trojan.PEs.00043813`）。**仅 `Status > 0` 时生成**，良性样本为 `""` |
| `Packed.IsPacked` | bool | 是否被加壳/保护 |
| `Packed.PackerName` | str | 壳名称（`UPX` / `VMProtect` / `Themida` / `ASPack` / `PECompact` / `Enigma` / `MPRESS` / `NSIS` / `Unknown(.节名)`），未加壳为 `""` |
| `Packed.IsArchive` | bool | 是否为自解压归档（SFX）安装包 |
| `Packed.ArchiveName` | str | SFX 技术类型标签（`NSIS` / `7-Zip SFX` / `Inno Setup` / `WinRAR SFX`）。**是"哪种制作工具"，不是压缩包文件名**；未识别为 `""` |
| `PerModelScores` | object | 每个子模型的恶意度得分 (0~1)，键为模型名，共 33 项 |
| `PerModelPreds` | object | 每个子模型的 0/1 硬判定，键与 `PerModelScores` 完全一致、同序 |
| `DriftEvidence.surface` | float | 表层漂移证据 |
| `DriftEvidence.structure` | float | 结构漂移证据 |
| `DriftEvidence.global` | float | 全局漂移证据 |
| `SampleDriftType` | str | 漂移类型：`none` / `perturbation` / `structural` / `paradigm_shift` |
| `AnomalyScore` | float | 漂移异常分（= `max(DriftEvidence)`） |
| `IsDriftCandidate` | bool | 是否被判为漂移候选 |
| `ModelStats.TotalModels` | int | 集成内模型总数（当前 33） |
| `ModelStats.OkModels` | int | 成功推理出分的模型数 |
| `ModelStats.SkippedModels` | int | 因视角缺失被跳过的模型数（`include_de=false` 时 D/E 视角的图模型全部计入） |
| `ModelStats.ErrorModels` | int | 推理报错/维度不符的模型数 |
| `ModelStats.MaliciousVotes` | int | ok 模型中判为恶意的票数 |
| `ModelStats.BenignVotes` | int | ok 模型中判为良性的票数 |
| `ModelStats.AgreementRate` | float | 一致率 = `MaliciousVotes / OkModels` |
| `ModelStats.EnsembleScore` | float | 集成得分 = 各 ok 模型分数的均值 (0~1) |
| `ModelStats.EnsemblePred` | int | 集成判定 (0/1)，`EnsembleScore > 0.5` → 1 |
| `ModelStats.ScoreRange` | [float, float] | ok 模型分数的 `[最小值, 最大值]` |

> ⚠️ **判定口径**：`Status` 由集成均值决定，`MaliciousVotes` 只是投票统计，不决定结论。
> 恶意样本可能是 9/33 票恶意但均值 0.5507 → Malicious；良性样本 3/33 票恶意、均值 0.3986 → Benign。
> 哈希命中路径的 `Score` 恒为 `1.0`（非模型分），与模型路径不同量纲，不要混用。

#### `Results[]` 的三种条目形态

**① 模型推理路径** —— 上面展示的完整结构。

**② 哈希库命中短路**（sha256 / md5 / fuzzy 任一级命中即直出，不占模型批量额度）：

```json
{
  "MD5": "...", "SHA256": "...", "CRC32": "...",
  "FileName": "sample2.exe", "FileSize": 51200,
  "Status": 1, "StatusLabel": "Malicious", "IsMalicious": true, "Score": 1.0,
  "Source": "sha256_db",
  "ScanResult": {
    "VirusName": "KnownMalware",
    "Packed": { "IsPacked": false, "PackerName": "", "IsArchive": false, "ArchiveName": "" },
    "PerModelScores": {}, "PerModelPreds": {},
    "DriftEvidence": { "surface": 0.0, "structure": 0.0, "global": 0.0 },
    "SampleDriftType": "normal", "AnomalyScore": 0.0, "IsDriftCandidate": false,
    "HashMatch": { "engine": "Hash DB", "type": "hash", "detail": "SHA256 命中: <hex>" }
  },
  "FilePath": "/data/samples/sample2.exe",
  "ProcessingTime": 0.625
}
```

差异点：`Source` ∈ `sha256_db` / `md5_db` / `fuzzy_db`；`PerModelScores` / `PerModelPreds` 为**空对象**；
无 `ModelStats`；`Score` 恒 `1.0`；`VirusName` 为库内签名名，v4 库不存名时统一 `KnownMalware`。
fuzzy 命中的 `HashMatch` 额外带 `fuzzy_type`（`ssdeep`/`imphash`/`authentihash`/`tlsh`）与 `sha256`。

**③ 失败条目**（特征提取或批量推理失败，无 `ScanResult`）：

```json
{
  "FileName": "broken.exe",
  "FilePath": "/data/samples/broken.exe",
  "Status": -1,
  "StatusLabel": "Error",
  "IsMalicious": false,
  "Error": "feature_extraction_failed"
}
```

`Error` 取值：`feature_extraction_failed` / `batch_inference_failed` / `format_result_failed`。

#### 校验要点

- `Summary.MaliciousCount + BenignCount + ErrorCount + TimeoutCount` 应等于 `Results` 条目数。
- `Summary.TotalFiles` 只统计 **PE 文件**（按文件头 `MZ`+`PE\0\0` 判定，不看扩展名）；
  非 PE 文件计入 `TotalFilesInDirectory` 与 `SkippedNonPE`。
- `Results` 顺序 = **哈希命中在前 + 模型结果在后**，不是按路径排序。
- `ProcessingTime` 是**整批的平均单样本耗时**（`BatchScanTime / 成功数`），同一批里所有成功条目的值相同，
  失败条目没有该字段——它不是单文件真实耗时。
- `Summary.Timing.ModelLoadTime` 为 `0.0` 表示模型此前已加载（懒加载，进程内只加载一次）。
- HTTP 错误分支：`directory` 不存在 → `400`；目录内无任何文件 → `404`；无 PE 文件 → `404`；
  文件数超限 → `400`（上限 `MAX_BATCH_FILES`，默认 500）。

> `directory` 是**服务端路径**，需挂载进容器（如 `-v /mnt/hgfs/VM_Share/testsamples:/data/samples:ro`）。

---

### 3.9 签名库一条龙更新 `/update-signatures`

一次请求完成：**导入 → 计数校验 → VACUUM → 发布 `releases/v<ts>` → 热切换**，
不重启进程、不触碰在线旧库（全程在 staging 副本上操作，失败自动保留旧库）。

源格式**逐文件自动探测**：日更 CSV / hashBase 9 字段 hdb / ClamAV hdb；也支持 `.zip` 打包上传。
`file`（上传）与 `dir_path`（服务器本地目录）**二选一**。

```bash
# ① 上传单个日更 CSV
curl -s -X POST "http://localhost:8000/update-signatures?week_id=2026W40" \
  -F "file=@/mnt/hgfs/VM_Share/hdb/2026W40.csv" | python -m json.tool

# ② 指向服务器本地目录（一批 00.hdb~ff.hdb或者.csv）
curl -s -X POST "http://localhost:8000/update-signatures?dir_path=/data/hdb&week_id=2026W40&vacuum=true" | python -m json.tool

# ③ 上传 .zip（内含多个 .csv/.hdb，自动解包逐个导入）
curl -s -X POST "http://localhost:8000/update-signatures?week_id=2026W40" \
  -F "file=@sigs_2026W40.zip" | python -m json.tool
```

**请求参数**：

| 参数 | 位置 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `file` | form | 否 | — | `.csv` / `.hdb` / `.zip`，与 `dir_path` 二选一 |
| `dir_path` | query | 否 | — | 服务器本地目录（含日更 CSV 或 `00.hdb`~`ff.hdb`），与 `file` 二选一 |
| `week_id` | query | 否 | 时间戳 | 周/日标识（如 `2026W40`），**每次必须换新**（记录以 `<week_id>__<文件名>` 登记） |
| `malicious_only` | query | 否 | `true` | CSV 源专用：跳过无任何威胁标注的行 |
| `vacuum` | query | 否 | `true` | 是否对受影响分片执行 `VACUUM` |

**预期输出（有新签名，`status=published`）**：

```json
{
  "status": "published",
  "files": 1,
  "week": "2026W40",
  "formats": { "csv": 1 },
  "rows_inserted": { "sha256": 118340, "md5": 118340, "fuzzy": 96421 },
  "counts": {
    "before": { "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578 },
    "after":  { "sha256": 3684924, "md5": 3553823, "fuzzy": 5768999 }
  },
  "release": "/app/signatures/releases/v20261008-091530",
  "active_dir": "/app/signatures/releases/v20261008-091530",
  "vacuum": { "sha256": { "vacuumed_shards": 12, "seconds": 3.4 } },
  "note": "已热切换，无需重启。回滚：将 current 指回上一版本目录后重启进程。"
}
```

**预期输出（重复投递，`status=no_new_rows`，不发布）**：

```json
{
  "status": "no_new_rows",
  "detail": "所有输入均未产生新签名（行级去重），未发布新版本",
  "files": 1,
  "week": "2026W40",
  "formats": { "csv": 1 },
  "counts": { "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578 }
}
```

> 同一份数据**重复喂是安全的**（行级 `INSERT OR IGNORE`），返回 `no_new_rows` 属正常结果；
> 但 `week_id` 请每次换新，否则导入记录会按 `<week_id>__<文件名>` 把同名文件去重掉。

**验证更新是否生效**（无需重启）：

```bash
# 三库条数应变成发布后的 after 值，engine_mode 仍为 hash_db+model
curl -s http://localhost:8000/health | python -c "import json,sys;d=json.load(sys.stdin);print(d['engine_mode'], d['hash_db'])"

# 发布目录 / current 指针
docker exec codefender ls -l /app/signatures/
docker exec codefender readlink /app/signatures/current
```

**错误码**：

| HTTP | 含义 |
|------|------|
| 400 | `HASH_DB_ENABLED=0`；`file` / `dir_path` 未二选一；`dir_path` 非目录；非法文件名；非 `.csv/.hdb/.zip`；输入无有效文件；zip 损坏 |
| 409 | 某族计数**回退**（新库 `<` 在线旧库），拒绝发布 |
| 500 | 发布 / 热切换失败（**旧库保留**，服务不受影响） |

---

### 3.10 运行时配置 `/admin/config`

与 `/update-signatures`、`/reload-model` 一样**不做鉴权**。用于**免重启**改配置，优先级：
`POST /admin/config` > `runtime_config.json` > 环境变量 > 默认值。

**查看**：

```bash
curl -s http://localhost:8000/admin/config | python -m json.tool
```

关键字段：`pid` / `started_at`（判断请求是否打到你以为的那个进程）、`env_profile`（dev/prod）、
`engine_mode`、`items{}`（每项的 `value` / `origin` / `hot_reload`）、`hash_db`。

**改配置**：

```bash
# 关闭过滤引擎 → 全部走模型（约 0.2s 生效）
curl -s -X POST http://localhost:8000/admin/config \
  -H "Content-Type: application/json" -d '{"hash_db_enabled": false}' | python -m json.tool

# 重新开启（需装载三库，实测 0.2~9s；装载期间仍由旧状态服务，完成后原子切换）
curl -s -X POST http://localhost:8000/admin/config \
  -H "Content-Type: application/json" -d '{"hash_db_enabled": true, "fuzzy_db_enabled": true}'

# 落盘（重启后仍生效）—— 仅 dev 档允许
curl -s -X POST http://localhost:8000/admin/config \
  -H "Content-Type: application/json" -d '{"persist": true, "hash_db_enabled": false}'

# 复位到 env/默认基线；重读覆盖文件
curl -s -X POST http://localhost:8000/admin/config -H "Content-Type: application/json" -d '{"reset": ["HASH_DB_ENABLED"]}'
curl -s -X POST http://localhost:8000/admin/config -H "Content-Type: application/json" -d '{"reload_file": true}'
```

**验证生效**：

```bash
# engine_mode 应变为 model_only；pid 不变（没重启）
curl -s http://localhost:8000/health | python -c "import json,sys;d=json.load(sys.stdin);print(d['pid'], d['engine_mode'], d['hash_db']['enabled'])"
```

**错误码 / 档位差异**：

| HTTP | 触发条件 |
|------|----------|
| 400 | 配置项名不支持（响应会返回可用项列表）；`reset` 含非法项；覆盖文件格式错误 |
| 409 | 生产档位（容器 / `CODEFENDER_ENV=prod`）下发 `persist: true` 或 `reload_file: true` |
| 500 | 应用失败（整批原子失败，内存不被改一半） |

> ⚠️ 生产档位下**允许纯内存热切换**（重启进程即恢复全引擎，日志记 WARNING），但**禁止落盘** ——
> 免得容器里留下跨重启的调试开关。要长期固化请改 `codefender.ini` 的 `environment=` 行后重启。

---

## 4. 一键测试脚本

仓库里就有：**`docker/test_api.sh`**（不依赖 `jq`，自带 PASS/FAIL 汇总与「我到底在访问谁」判据）。

```bash
# 在 VM 里打容器（默认 http://localhost:8000）
bash docker/test_api.sh

# 从 Windows 打 VM 里的容器（先确认能路由到 VM 的 IP）
BASE_URL=http://192.168.x.x:8000 bash docker/test_api.sh

# 追加真实推理（样本路径按**执行脚本的那一侧**给）
bash docker/test_api.sh --sample /mnt/hgfs/VM_Share/testsamples/benign/<文件名>
bash docker/test_api.sh --dir /data/samples        # 见下方说明：得先 docker cp 进去

# 要求必须是容器档位：env 不是 prod 直接判 FAIL（防误测到宿主 dev 实例）
bash docker/test_api.sh --expect-prod

# 单请求超时（默认 90s）。/health 要数三库，实测 3~6s，别调太小
TIMEOUT=180 bash docker/test_api.sh
```

> **`predict-directory` 的 `directory` 是容器内路径**（零挂载只针对签名库，样本目录可以挂）：
> ```bash
> # 方式 A：起容器时就把样本目录挂进去（推荐，见第 2 节）
> docker run -d --name codefender -v /mnt/hgfs/VM_Share/testsamples:/data/samples:ro -p 8000:8000 codefender-c3:v8
> # 方式 B：已经起来了，拷一份进去
> docker cp /mnt/hgfs/VM_Share/testsamples codefender:/data/samples
>
> bash docker/test_api.sh --dir /data/samples
> ```
> `predict-single` 不受影响（文件是 HTTP 上传的，路径按执行脚本那一侧给）。

**脚本自动覆盖（只读）**：`/livez` `/readyz` `/metrics` `/health` `/model-info` `/admin/config`
**不纳入**（会改状态，手工执行）：`/update-signatures`、`/reload-model`

**签名库更新（3.9，手工执行）**：

```bash
curl -s -X POST "http://localhost:8000/update-signatures?week_id=2026W40" \
  -F "file=@/mnt/hgfs/VM_Share/hdb/2026W40.csv" | python -m json.tool
```

---

## 5. 常用管理命令

```bash
# 查看日志
docker logs -f codefender

# 进入容器
docker exec -it codefender bash

# 停止容器
docker stop codefender

# 删除容器
docker rm codefender
```

---

## 6. 故障排查

| 症状 | 排查命令 |
|------|----------|
| 容器一直重启 | `docker logs codefender --tail 50` |
| 启动即退，日志含「要求以 ['sha256','md5','fuzzy'] 全部就绪，但缺失」 | 生产档位 `REQUIRE_HASH_DB=1` 的**刻意行为**；确认 `/app/signatures` 有库，或把 `CODEFENDER_REQUIRE_HASH_DB` 改 `0` |
| `/health` 返回 error | 检查 `ensemble.pkl` 是否在容器 `/app/` 目录下 |
| `/readyz` 返回 503 | 模型仍在加载中，等待 30~60s 后重试 |
| 端口被占用 | `lsof -i :8000` 或 `netstat -tlnp \| grep 8000` |
| 挂载目录不可见 | `docker exec codefender ls /data/samples` |
| 并发打满/请求排队 | 查看 `/metrics` 中 `last_predict_ms` 和错误计数；调整 `CODEFENDER_MAX_CONCURRENT` |
| 模型文件损坏 | 比对 `/health` 返回的 `model_md5` 与本地文件的 MD5 |
| 改了配置没生效 | 看 `/health` 的 `pid` / `started_at`（重启后必然变化）；`docker restart` **不重读 `-e`**，须 `docker rm` 后重跑 |
| 样本总是走模型（预检没生效） | `/health` 的 `engine_mode`：`model_only` = 三库全关/不可用；查 `hash_db.sha256/md5/fuzzy` 是否 `null` |
| `/update-signatures` 返回 409 | 有族计数回退（新库 < 旧库）→ 输入数据不完整，拒绝发布；旧库未受影响 |
| `/update-signatures` 返回 `no_new_rows` | 正常：输入已在库中（行级去重），未发布新版本。换新 `week_id` 或确认源数据已更新 |
| `docker rm` 后库变回旧版 | 在线发布只落容器可写层（设计如此）。要固化：`python docker/stage_signatures.py && docker build -t codefender-c3:v8.1 .` 后换镜像重建容器。**不要**靠挂卷解决 |
| `/admin/config` 落盘返回 409 | 生产档位不允许 `persist`/`reload_file`；改用纯内存热切换，或改 `codefender.ini` 的 `environment=` 行 |
