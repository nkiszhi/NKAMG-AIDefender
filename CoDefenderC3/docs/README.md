# CoDefenderC3

**Multi-Model Collaborative Malware Concept Drift Defense via Spectral Drift Decomposition and LLM-Assisted Analysis**

多模型集成恶意软件检测系统，基于 PyTorch 的多视角异构模型集成架构，覆盖 PE 文件 **8 大分析维度**，集成 **33 个已发表子模型** + **SDD 谱漂移检测引擎** + **LLM 辅助分析层**。

---

## 目录

- [项目架构](#项目架构)
- [环境要求](#环境要求)
- [开发环境运行](#开发环境运行)
- [生产环境部署 (Docker)](#生产环境部署-docker)
- [API 接口](#api-接口)
- [测试指南](#测试指南)
- [训练管线](#训练管线)
- [配置参考](#配置参考)
- [项目结构](#项目结构)

---

## 项目架构

```
四层架构:
┌─────────────────────────────────────────────────┐
│ Layer 4: 自适应推断层    DSIR + DACP + 策略选择  │
├─────────────────────────────────────────────────┤
│ Layer 3: LLM辅助分析层   ATT&CK映射 + 策略推荐   │
├─────────────────────────────────────────────────┤
│ Layer 2: SDD漂移检测     谱分解 + 漂移证据量化    │
├─────────────────────────────────────────────────┤
│ Layer 1: 多模型集成层    33模型 × 16视角组        │
└─────────────────────────────────────────────────┘
```

**16 个视角组 (View Groups)**:

| 视角 | 特征维度 | 代表模型 |
|------|----------|----------|
| V1_byte | 字节级 | MalConv, MalConv2, ByteTransformer |
| V2_byte_stat | 字节统计 | SaxeBerlinDNN, EmberDNN, NatarajKNN |
| V3_pe_struct | PE 结构 | DrebinSVM, DL4MD, PEMinerRF |
| V4_import | 导入表 | DrebinImport, ALOHANet, EmberGBDT_Import |
| V5_string | 字符串 | RaffFeatureNet, DrebinString |
| V6_opcode_seq/stat/func_embed | 操作码 | OpcodeLSTM, OpcodeStatNet, AsmEmbedNet |
| V7_graph | 图结构 | MalGraph, CFGGAT, CFGGCN, DGCNN, CallGraphGNN |
| V8_gray/color/markov/entropy | 可视化 | GrayscaleCNN, IMCFN, MarkovCNN, EntropyMapCNN |
| V9_hash | 哈希 | HashEmbedNet |
| V10_metadata | 元数据 | MetadataNet, ResourceNet |
| V11_ensemble | 全量 | Ember_NDF, EmberGBDT |

---

## 环境要求

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| Python | ≥ 3.10 | 开发环境当前使用 3.13.13 |
| numpy / scipy | ≥ 1.21 / ≥ 1.7 | 全链路基础；scipy 服务 SDD 漂移引擎；numpy 2.x 已验证兼容 |
| FastAPI + uvicorn + starlette | ≥ 0.110 / ≥ 0.29 / ≥ 0.27 | API 服务层 |
| python-multipart | ≥ 0.0.9 | `/predict-single` 的 form-data 上传（缺失则启动即报错） |
| pefile | ≥ 2023.2.7 | EMBER 静态特征、壳检测、imphash/authentihash |
| ppdeep / yara-python | ≥ 20200505 / ≥ 4.3 | 模糊哈希（ssdeep/CTPH）预检 / 壳检测 YARA 扩展规则；缺失自动降级 |
| tqdm | ≥ 4.60 | MalGraph 生产模型：`models/MalGraph_2022/` 顶层导入 |
| PyTorch 栈 | torch ≥ 2.0 / torchvision / torch_geometric | **不由 requirements.txt 安装**：Dockerfile 从 PyTorch CPU 源单独装（省 ~2GB） |
| BinaryNinja | (可选) | PE 深度特征提取（D/E 特征）+ MalGraph；商业许可证，基础镜像自带 |
| ensemble.pkl | 736 MiB | 预训练的多模型集成权重文件 |
| — **以下仅训练 / 数据集构建需要（`requirements.txt` 中已注释）** — | | |
| scikit-learn | ≥ 1.0 | **仅训练期**（`train/run_all.py` 的 metrics），推理链路不用 |
| Pillow / matplotlib | ≥ 9.0 / ≥ 3.5 | 仅离线图像视图提取（`unified.py` GRAY_IMAGE/COLOR_IMAGE）；生产推理走 BinaryNinja 的 F01/F02，不需要二者 |
| pandas / requests / gdown / datasets / boto3 / botocore / thrember | — | 仅 `train/build_dataset.py` 构建数据集时用，脚本会自行 pip install |

> [`requirements.txt`](../requirements.txt) **只收录生产环境必需项**：训练 / 数据集构建依赖全部注释，
> 开发调试依赖已整条删除（文末 §5 有说明）。代码改动后想确认清单没漏项，
> 跑 `python docker/check_requirements.py`（严格模式，退出码 0 即通过）。

### 依赖安装

```bash
# 1. 先装 PyTorch CPU-only（注意 >= 必须加引号，否则被 shell 当成重定向）
pip install "torch>=2.0" torchvision --index-url https://download.pytorch.org/whl/cpu
pip install torch_geometric

# 2. 安装其余依赖
pip install -r requirements.txt
```

---

## 开发环境运行

### 1. 确保 ensemble.pkl 就位

```bash
# 检查模型文件是否在项目根目录
ls -lh ensemble.pkl
# 预期: ensemble.pkl (834 MB)

# 或通过环境变量指定路径
export CODEFENDER_MODEL_PATH=/path/to/ensemble.pkl
```

### 2. 启动 API 服务

```bash
# 方式一：在项目根目录执行
uvicorn engine.app:app --host 0.0.0.0 --port 8000

# 方式二：Python 模块方式
python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000

# 方式三：带热重载（开发调试推荐）
uvicorn engine.app:app --host 0.0.0.0 --port 8000 --reload

# 方式四：关闭过滤引擎，全部检测走模型（详见下节「方式四说明」）
CODEFENDER_ENV=dev CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 \
  CODEFENDER_REQUIRE_HASH_DB=0 \
  python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000

# 方式四（推荐）：直接用脚本，免记忆环境变量、额外带端口占用预检
#   Windows:  dev_model_only.cmd
#   Ubuntu:   ./dev_model_only.sh
```

#### 方式四说明：关闭过滤引擎（纯模型检测）

> **本机开发专用。** 生产容器请用 Docker（默认全引擎 + 缺库拒绝启动）：这套隔离由
> `CODEFENDER_ENV` 档位 + `.dockerignore` + `CODEFENDER_REQUIRE_HASH_DB` 三层保证，
> 详见「方式六：开发 / 生产档位隔离」。

「过滤引擎」指四级哈希签名库预检链：`sha256 库 → md5 库 → fuzzy 库（ssdeep / imphash / authentihash）→ tlsh 库`。
任一命中即毫秒短路返回 `Malicious`，**不再进入 33 模型集成**；四级全部未命中才走模型。

设置 `CODEFENDER_HASH_DB_ENABLED=0` 后 `_init_hash_dbs()` 直接返回，`_sha256_db` / `_md5_db` / `_fuzzy_db`
三个全局引用恒为 `None`，`_hash_precheck()` 与 `_hash_precheck_file()` 首行即 `return None`
→ **所有样本无条件走模型**。`FUZZY_DB_ENABLED=0` 一并显式设置是为了语义清晰（前者已短路，fuzzy 不会被加载）。

**Windows（CMD）**——⚠️ CMD **不支持** bash 的行内 `VAR=value 命令` 写法（会把变量名当命令执行报
「不是内部或外部命令」）。每条 `set` 必须独占一行：

```bat
set CODEFENDER_HASH_DB_ENABLED=0
set CODEFENDER_FUZZY_DB_ENABLED=0
python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
```

单行链式写法可用 `set "VAR=0" &&`（**`0` 后严禁有空格**：`set X=0 && ` 会把值设成 `"0 "`，
`config.py` 判 `!= "0"` 反而当成开启）：

```bat
set "CODEFENDER_HASH_DB_ENABLED=0" && set "CODEFENDER_FUZZY_DB_ENABLED=0" && python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
```

**Windows（PowerShell）**：

```powershell
$env:CODEFENDER_HASH_DB_ENABLED="0"; $env:CODEFENDER_FUZZY_DB_ENABLED="0"
python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
```

**生效确认**：启动日志 + `/health` 双通道（`app.py` 已为 `codefender.*` 命名空间挂 StreamHandler，
否则 uvicorn 下这些 INFO 日志**不会输出**，无法据此判断）：

开启时（默认，三库依次加载）：

```
[hashdb] SHA256 签名库就绪: 3,566,584 条
[hashdb] MD5 签名库就绪: 3,435,483 条
[hashdb] Fuzzy 模糊哈希库就绪: 5,672,578 条 {'ssdeep': 2751153, 'tlsh': 2921199, ...}
[hashdb] 过滤引擎已启用: sha256=3,566,584 md5=3,435,483 fuzzy=5,672,578
[startup] 环境档位=dev 运行时覆盖文件=启用
[startup] 过滤引擎要求=允许降级为纯模型
```

关闭后（只有这两行，且无任何「签名库就绪」）：

```
[hashdb] 哈希库预检已禁用 (CODEFENDER_HASH_DB_ENABLED=0)
[hashdb] 过滤引擎未启用 → 所有样本走模型集成（纯模型模式）
```

**最可靠的确认方式**（不依赖日志）：`GET /health` 的 `hash_db` 段 + `engine_mode`——

```bash
curl -s http://localhost:8000/health | python -c "import json,sys;d=json.load(sys.stdin);print(d['env'],d['engine_mode'],d['hash_db'])"
```

```json
dev model_only {"enabled": false, "fuzzy_enabled": false, "mode": "model_only",
 "dir": ".../signatures/releases/v20260924-140028",
 "sha256": null, "md5": null, "fuzzy": null}
```

**判定"某个样本的恶意结论来自库还是模型"**：POST `/predict-single` 看 `ScanResult`——
`Source` 为 `sha256_db`/`fuzzy_db` 且 `ScanResult.PerModelScores` 为空 = 预检短路；
无 `Source` 且 `PerModelScores` 有值 = 走模型集成。

`enabled=false` + 三个计数为 `null` = 开关已生效。开启时则是 `enabled=true` 与三个正整数计数。
`GET /metrics` 亦提供 `hash_db_enabled` / `hash_db_sha256` / `hash_db_md5` / `hash_db_fuzzy`。

**三个高频踩坑**：

| 坑 | 现象 | 处理 |
|----|------|------|
| 在 **PowerShell** 里用 `set VAR=0` | `set` 是 `Set-Variable` 的别名，只建了个 PowerShell 变量，**环境变量根本没设**，且不报错 | 用 `$env:CODEFENDER_HASH_DB_ENABLED="0"` |
| 旧进程还占着 8000 端口 | 新命令启动失败（`address already in use`）或你以为已重启，实际请求仍打到**旧进程**（引擎照旧开着） | `netstat -ano \| findstr :8000` 查 PID，`taskkill /F /PID <pid>` 后再启动；对比 `/health` 的 `pid`/`started_at` 确认是同一进程 |
| 容器里 `docker restart` | env 在 `docker run` 时固化，restart **不会**重读 `-e`，现象是"改了没生效" | `docker rm` + 重跑，或 `docker compose up -d --force-recreate`；代码若 `COPY` 进镜像则须重建镜像 |

`set` 只对**当前 CMD 窗口**有效：换窗口、双击脚本、VS Code 任务里启动都不会继承。

**典型用途**：

| 场景 | 说明 |
|------|------|
| 模型真实性能评估 | 避免测试集里已知哈希被预检短路（`Malicious` 不来自模型），使 AUC / F1 / FPR 虚高 |
| 误报溯源 | 排查「某样本被判恶意」时，区分是库命中还是模型判定 |
| 特征 / 模型调试 | 集中观察 33 模型集成行为与耗时，排除库查询干扰 |
| 训练集打标 | 对样本批量打分时保证分数完全由模型产生 |

> ⚠️ 该模式下单样本耗时显著上升（无毫秒短路，每个样本都要跑完整特征提取 + 集成推理）。生产环境**不要**默认关闭。

#### 方式五：不重启进程改配置（运行时覆盖）

上面四种方式都绕不开一个事实：`config.py` 的常量在 **import 时** 从 `os.environ` 读一次并固化，
所以"改配置"要生效，必须让**真正在跑的那个进程**重新加载。托管环境会额外添乱：

| 场景 | 为什么改了没用 |
|------|----------------|
| `docker restart` | env 在 `docker run` 时固化，restart **不会**重读 `-e` |
| 代码是 `COPY` 进镜像的 | 改宿主机 `config.py` 与容器内进程无关，必须重建镜像 |
| supervisord 托管 | kill 后按自己的 `environment=` 拉起，shell 里 `set` 的变量不进新进程 |
| 端口被旧进程占着 | 新进程起不来、或请求打到旧进程 → 现象就是"改了没生效" |

为此提供**与 env 完全解耦**的旁路，优先级：
**运行时 API > `runtime_config.json` > 环境变量 > 默认值**。

**① 运行时 API（瞬时生效，推荐）**

```bash
# 关闭过滤引擎 → 全部走模型（约 0.2s 生效，无需重启）
curl -X POST http://localhost:8000/admin/config \
     -H "Content-Type: application/json" -d '{"hash_db_enabled": false}'

# 重新开启（需装载三库，实测 0.2~9s；装载期间仍由旧状态服务，完成后原子切换）
curl -X POST http://localhost:8000/admin/config \
     -H "Content-Type: application/json" \
     -d '{"hash_db_enabled": true, "fuzzy_db_enabled": true}'

# 顺带落盘：重启后仍生效
curl -X POST http://localhost:8000/admin/config -d '{"persist": true, "hash_db_enabled": false}'

# 回到环境变量 / 默认值基线（不带 names 则复位全部）
curl -X POST http://localhost:8000/admin/config -d '{"reset": ["HASH_DB_ENABLED"]}'

# 每一项的当前值 / 来源 / 能否热生效
curl http://localhost:8000/admin/config
```

`origin` 字段取值：`env`（来自环境变量）/ `default`（默认值）/ `runtime:api`（本次接口改的）/
`runtime:file`（覆盖文件改的）。非法项名会被 400 拒绝，`cold_keys_pending_restart` 列出"改了但要重启才生效"的项。

**② 覆盖文件（不用记 env 语法）**

编辑项目根目录的 `runtime_config.json`（路径可用 `CODEFENDER_RUNTIME_CFG_FILE` 覆盖）：

```json
{ "overrides": { "HASH_DB_ENABLED": false, "FUZZY_DB_TLSH_MAX_BYTES_OFFLINE": 4194304 } }
```

重启进程即生效；不想重启就 `curl -X POST .../admin/config -d '{"reload_file": true}'`。
文件不存在 = 无覆盖；内容非法 = **整份忽略**（不会"改一半"），原因见 `/health` 的 `runtime_cfg_error`。

> ⚠️ 覆盖文件是**开发期便利**，不是生产机制。项目根若存在 `runtime_config.json`，
> 只有**本机开发档位**（`CODEFENDER_ENV=dev`，即未设置且不在容器内）才会加载它；
> 容器内 / `CODEFENDER_ENV=prod` 时它既不加载也不落盘（详见下面「方式六」）。
> 即便如此，打包镜像前仍建议清掉本地调试内容 —— `.dockerignore` 已排除该文件。

可覆盖项（以 `GET /admin/config` 输出为准）：

| 配置项 | 环境变量 | 热生效 |
|--------|----------|--------|
| `HASH_DB_ENABLED` | `CODEFENDER_HASH_DB_ENABLED` | ✅ 关闭瞬时；开启需装载三库 |
| `FUZZY_DB_ENABLED` | `CODEFENDER_FUZZY_DB_ENABLED` | ✅ |
| `HASH_DB_DIR` | `CODEFENDER_HASH_DB_DIR` | ✅（自动重载三库） |
| `FUZZY_DB_MAX_BYTES` | `CODEFENDER_FUZZY_DB_MAX_BYTES` | ✅ |
| `FUZZY_DB_TLSH_MAX_BYTES` | `CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES` | ✅ |
| `FUZZY_DB_TLSH_MAX_BYTES_OFFLINE` | `CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES_OFFLINE` | ✅ |
| `VIEWS_REQUIRE_ALL` | `CODEFENDER_VIEWS_REQUIRE_ALL` | ❌ 仅启动期（数据集构建）读取 |

> ⚠️ 注意 `CODEFENDER_ENV` / `CODEFENDER_REQUIRE_HASH_DB` **不在**可覆盖白名单里 —— 它们是
> 档位与启动策略，只能由环境变量决定，避免"用开发手段把生产降级掉"。

**③ 判断"我改的配置到底进没进到正在跑的那个进程"**

```bash
curl -s http://localhost:8000/health | python -c "import json,sys;d=json.load(sys.stdin);print(d['pid'],d['started_at'],d['env'],d['engine_mode'],d['hash_db'],d['runtime_cfg_applied'])"
```

`pid` / `started_at` 是重启后**必然变化**的两个值 —— 若没变，说明改的配置根本没进这个进程。
`runtime_cfg_applied` 列出本次启动从覆盖文件吃到的项。

验证脚本：`python _probe_runtime_cfg.py`（20 项断言：覆盖/复位/落盘/原子性/热切换/命中链路）。

---

#### 方式六：开发 / 生产档位隔离（本机纯模型，容器全引擎）

**需求**：本机开发经常要"只走模型链路"做对照（模型真实性能评估、误报溯源、训练集打标），
但**生产容器绝不允许**因为一份被一起带进去的调试配置就悄悄退化成纯模型 —— 那是漏检，
而当前实现的缺库行为恰好是**静默降级**（服务照常 200、只是预检不再命中），日志里只有一行 info。

于是引入**环境档位**，三层防护，任一层单独成立即生效：

| 层 | 机制 | 挡住什么 |
|----|------|----------|
| ① 构建期 | `.dockerignore` 排除 `runtime_config.json`；Dockerfile 只 `COPY` 指定文件 | 文件根本没进镜像 |
| ② 运行期 | 容器内 / `CODEFENDER_ENV=prod` → 覆盖文件**不加载也不落盘** | 镜像里带着它、或把项目目录挂进容器，都不生效 |
| ③ 启动期 | `CODEFENDER_REQUIRE_HASH_DB=1` → 三库缺一即**拒绝启动** | 镜像里签名库缺失/打包不全，不再静默跑纯模型 |

**档位判定**（`GET /health` 的 `env` 字段）：

| 条件 | 档位 | `runtime_config.json` |
|------|------|----------------------|
| `CODEFENDER_ENV=dev` | dev | ✅ 加载 / 可落盘 |
| `CODEFENDER_ENV=prod` | prod | ❌ 忽略 |
| 未设置 + 不在容器内（本机） | dev | ✅ |
| 未设置 + 在容器内（`/.dockerenv` 或 cgroup 含 docker/kubepods） | prod | ❌ |

**本机开发怎么跑纯模型**（推荐脚本，零残留）：

```bash
# Windows（CMD，双击或在已打开的 CMD 窗口里运行）
dev_model_only.cmd

# Ubuntu / VM
./dev_model_only.sh

# 或手动（等价），仅作用于当前窗口的进程
CODEFENDER_ENV=dev CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 \
  PYTHONIOENCODING=utf-8 python -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
```

脚本做的事：设 `CODEFENDER_ENV=dev` + 关三库 + 关硬要求，另加一道**端口占用预检**
（旧进程占着端口 → 请求打到旧实例，正是"配置改了没生效"最经典的假象，直接拒绝启动并给出 PID）。
脚本只影响该进程环境、不写任何文件 → **没有任何途径进入镜像**。

> 脚本用 `CODEFENDER_PYEXE`（默认 `D:\work\tools\miniconda3\python.exe`）指定解释器，
> `CODEFENDER_PORT`（默认 8000）指定端口。
> ⚠️ `dev_model_only.cmd` **刻意只用 ASCII**：`.cmd` 里出现非 ASCII 字符时，一旦
> 切换控制台代码页，CMD 解析器会错位 —— 注释行被当成命令执行、脚本只跑一半。
> 中文说明放在文档里，脚本内保持英文。

**生产容器怎么保证全引擎**（Dockerfile + `codefender.ini` 已固化）：

```bash
ENV CODEFENDER_ENV=prod              # 生产档位：不读 runtime_config.json
ENV CODEFENDER_RUNTIME_CFG_DISABLE=1 # 双保险：覆盖文件既不加载也不落盘
ENV CODEFENDER_HASH_DB_ENABLED=1     # 显式开启四级预检（不依赖"没设=开"）
ENV CODEFENDER_FUZZY_DB_ENABLED=1    # 显式开启 fuzzy/tlsh
ENV CODEFENDER_REQUIRE_HASH_DB=1     # 缺库拒绝启动（响的失败）
```

`REQUIRE_HASH_DB=1` 的失败长这样（`docker logs` 一眼可见，不是静默）：

```
RuntimeError: [hashdb] CODEFENDER_REQUIRE_HASH_DB=1：要求以 ['sha256','md5','fuzzy'] 全部就绪，
但缺失 ['sha256','md5','fuzzy']。
  签名库目录=/app/signatures
  · Docker：签名库已在构建期打进镜像，容器内 /app/signatures 应直接含 sha256.db.shards /
    md5.db.shards / fuzzy.db.shards（**不要**用 -v 挂宿主机目录，挂载会让容器读到与镜像
    脱钩的旧库）；镜像不对就重新构建：python docker/stage_signatures.py && docker build
  · 首次部署：靠 /update-signatures 完成一次发布（releases/v<ts> + current）
  · 确实想允许降级：把 CODEFENDER_REQUIRE_HASH_DB 设为 0
```

> ⚠️ 三族签名库（sha256 / md5 / fuzzy）已在**构建期**打进镜像，正常情况下不会看到这条报错；
> 一旦看到，说明镜像里的库没打全（暂存步骤没跑，或 `--build-arg SIG_STAGE` 指错了），
> 而不是"忘了挂卷"。这是刻意的**响的失败**：没有签名库的"生产环境"其实一直在跑纯模型
> （漏检）却无人察觉。想临时降级就把 `codefender.ini` 里的 `CODEFENDER_REQUIRE_HASH_DB` 改成 `"0"`。

**生产档位下还能不能临时做纯模型对照？** 能，但只能走内存内热切换、且不落盘：

```bash
# ✅ 允许（重启进程即恢复全引擎，不留痕）—— 日志会记 WARNING
curl -X POST localhost:8000/admin/config -d '{"hash_db_enabled": false}'

# ❌ 409 拒绝：生产档位不允许落盘（免得容器里留下跨重启的调试开关）
curl -X POST localhost:8000/admin/config -d '{"persist": true, "hash_db_enabled": false}'
```

**验证**：`curl -s localhost:8000/health` → `"env":"dev"`（或 `prod`）+
`"engine_mode":"model_only"`（或 `hash_db+model` / `hash_db_partial+model`）；
回归探针 `python _probe_env_profile.py`（41 项断言：档位判定 / 文件可见性 / 容器自检 / 拒绝落盘 / 启动强校验）。

### 3. 验证服务启动

支持 Swagger UI 文档，访问以下地址查看 API 文档
http://localhost:8000/docs

```bash
# 健康检查
curl http://localhost:8000/health
```

预期返回：

```json
{
  "status": "ok",
  "pid": 6648,
  "started_at": "2026-09-24 16:20:57",
  "env": "dev",
  "engine_mode": "hash_db+model",
  "runtime_cfg_file": ".../runtime_config.json",
  "runtime_cfg_file_enabled": true,
  "runtime_cfg_disabled_reason": "",
  "runtime_cfg_applied": [],
  "runtime_cfg_error": "",
  "require_hash_db": false,
  "model_path": "/path/to/ensemble.pkl",
  "model_count": 33,
  "view_count": 15,
  "views": ["V1_byte", "V2_byte_stat", ...],
  "malgraph": { "enabled": true, ... },
  "hash_db": {
    "enabled": true,
    "fuzzy_enabled": true,
    "mode": "hash_db+model",
    "dir": ".../signatures/releases/v20260924-140028",
    "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578
  }
}
```

> **`engine_mode` 一眼回答"预检到底生效没有"**：`model_only`（纯模型）/ `hash_db+model`（齐备）/
> `hash_db_partial+model`（部分族降级）。`env` 是档位（`dev` 可读写覆盖文件，`prod` 忽略它）。
> `hash_db.enabled=false` 时三个计数为 `null` —— 这是判断开关是否生效最直接的方式。
> `pid` / `started_at` 用于判断请求是否打到了你以为的那个进程（改配置不生效的第一现场证据）。

### 4. 开发环境变量参考

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `CODEFENDER_MODEL_PATH` | `./ensemble.pkl` | 模型文件路径 |
| `CODEFENDER_INCLUDE_DE` | `true` | 是否默认启用 D/E 特征提取 |
| `CODEFENDER_ENABLE_MALGRAPH` | `true` | 是否启用 MalGraph 图神经网络 |
| `CODEFENDER_MAX_UPLOAD_BYTES` | `134217728` (128MB) | 最大上传文件大小 |
| `CODEFENDER_MAX_BATCH_FILES` | `500` | 批量扫描最大文件数 |
| `CODEFENDER_MAX_CONCURRENT` | `4` | 预测接口最大并发数 (asyncio.Semaphore) |

**档位与开发/生产隔离**（见「方式六」）：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `CODEFENDER_ENV` | 容器内 `prod`，否则 `dev` | 环境档位。`prod` 时 `runtime_config.json` 不加载也不落盘 |
| `CODEFENDER_RUNTIME_CFG_DISABLE` | `0` | 置 `1` 无条件禁用覆盖文件（Dockerfile 已设，双保险） |
| `CODEFENDER_RUNTIME_CFG_ALLOW` | `0` | 生产档位下的逃生阀：置 `1` 允许覆盖文件生效 |
| `CODEFENDER_REQUIRE_HASH_DB` | `0`（**Dockerfile 设为 `1`**） | 过滤引擎硬要求：三库缺一或被关闭即**拒绝启动**，不再静默降级为纯模型 |

**过滤引擎（哈希签名库预检）相关**：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `CODEFENDER_HASH_DB_ENABLED` | `1` | 哈希库过滤引擎总开关。`0` = **关闭全部四级预检，所有样本走模型** |
| `CODEFENDER_FUZZY_DB_ENABLED` | `1` | fuzzy 模糊哈希预检（ssdeep / imphash / authentihash / tlsh）单独开关 |
| `CODEFENDER_HASH_DB_DIR` | `./signatures` | 签名库目录；启动时经 `current` symlink（或 `releases/CURRENT` 指针）解析到当前生效版本 |
| `CODEFENDER_HASH_DB_LAYOUT` | `hex` | 分片布局，**必须与建库时一致**，否则触发全量重分片 |
| `CODEFENDER_HASH_DB_FP_RATE` | `0.01` | Bloom 误报率，**必须与建库时一致** |
| `CODEFENDER_HASH_DB_MAX_OPEN` | `16` | 分片 SQLite 连接 LRU 上限 |
| `CODEFENDER_FUZZY_DB_MAX_BYTES` | `262144` (256KB) | 计算 ssdeep 的文件大小上限，超限只算 PE 类哈希 |
| `CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES` | `1048576` (1MB) | 在线单文件 tlsh 计算上限（纯 Python ≈0.53 MB/s） |
| `CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES_OFFLINE` | `2097152` (2MB) | `/predict-directory` 批量路径 tlsh 上限 |
| `CODEFENDER_RUNTIME_CFG_FILE` | `./runtime_config.json` | 运行时覆盖文件路径，**仅 dev 档** import 时自动加载；不存在则无覆盖 |

> ⚠️ `config.py` 在 **import 时**读取环境变量 → 用 env 改配置必须让**真正在跑的那个进程**重启。
> CMD 用 `set VAR=0`（仅当前窗口有效）；**PowerShell 必须用 `$env:VAR="0"`**
> （`set` 是 `Set-Variable` 的别名，不设环境变量且不报错）。
> 不想折腾 env / 不想重启：用 `POST /admin/config` 或 `runtime_config.json`（见「方式五」）。
> 是否生效看 `GET /health` 的 `engine_mode` + `hash_db` 段 + `pid`/`started_at`。

---

## 生产环境部署 (Docker)

### 构建镜像

```bash
# 在项目根目录（推荐用包装脚本：暂存签名库 → 上下文预检 → docker build）
bash docker/build.sh codefender-c3:v8
# 等价的手工两步：
#   python docker/stage_signatures.py     # 解析 signatures/current → 暂存 .docker_build/signatures/
#   docker build -t codefender-c3:v8 .
```

**构建说明**:
- 基础镜像: `multiscan_basic_v3:with_binja` (CentOS, 预装 Python3 + BinaryNinja)
- `ensemble.pkl` (736 MiB) **与 sha256/md5/fuzzy 三族签名库**均在构建期打包进镜像，**无需任何运行时挂载**
- 层序按「改动频率从低到高」：`base → pip → 模型(736MB) → 签名库(~1GB) → 代码 → 自检`
  （缓存失效会向下传染，所以最常改的代码排在两个大件之后 → 改一行 `.py` 不必重做 1.7GB）
- **只打包生产代码（≈2.8MB）**：只 `COPY` 运行期 import 闭包内的
  `config.py` / `model_registry.py` 与 `engine/ core/ models/ scaner/ feature_extraction/`；
  `train/`（训练工具链）、`_tools/`（ember 回退，内容为残缺 `.git` + 无法解压的 zip）、
  `update/`（示例 CSV）、`docs/`、`README.md`，以及 MalGraph 的
  `features.jsonl` 训练缓存（103MB）等**都不进镜像**（由 `.dockerignore` 挡在上下文之外）。
  判定依据：`docker/check_requirements.py` 对 `engine/app.py` 做 AST 导入闭包分析
  （注意 `models/` 内的实现类由 `model_registry.py` 动态加载，故 `models/` 仍需整目录在位）
- supervisor 管理 uvicorn 进程，`autostart=true`
- 健康检查: 每 30s 检查 `/health` 端点

### 启动容器

```bash
# 生产启动（推荐）：零挂载 —— 代码 / 模型 / 三族签名库都已在镜像里
# 镜像已固化 CODEFENDER_ENV=prod + 全引擎 + 缺库拒绝启动
docker run -d -p 8000:8000 --ulimit nofile=65535:65535 --name codefender codefender-c3:v8

# 指定环境变量
docker run -d -p 8000:8000 --name codefender --ulimit nofile=65535:65535 \
  -e CODEFENDER_ENABLE_MALGRAPH=false \
  codefender-c3:v8

# 临时做纯模型对照（仅调试用；去掉 REQUIRE_HASH_DB 否则与 ENABLED=0 冲突会拒绝启动）
docker run -d -p 8000:8000 --name codefender \
  -e CODEFENDER_REQUIRE_HASH_DB=0 \
  -e CODEFENDER_HASH_DB_ENABLED=0 \
  -e CODEFENDER_FUZZY_DB_ENABLED=0 \
  codefender-c3:v8
```

> ✅ **不要再挂 `/app/signatures`**（也不要用 `-v /data/signatures:...`）：三族签名库已经在
> 构建期打进镜像，容器内的 `/app/signatures` 是**扁平**布局（`<base>.db.shards|bloom`，无
> `current`/`releases`）—— 这正是 `_active_sig_dir()` 的「首次部署 / 未做版本化发布」分支。
> 挂宿主机目录只会让容器读到**与镜像版本脱钩**的旧库；且 `signatures/` 是 SQLite 分片库，
> **严禁**挂到 VMware 共享目录（hgfs）上（POSIX 锁不可靠）。
>
> 万一仍看到 `要求以 ['sha256','md5','fuzzy'] 全部就绪，但缺失 [...]`，说明**镜像里的库没打全**
> （暂存步骤没跑 / `SIG_STAGE` 指错），重新构建即可 —— 这是刻意的"响的失败"：没有签名库的
> "生产环境"其实一直在跑纯模型（漏检），以前是静默的，现在是响的。

**日志确认**（`docker logs -f codefender`）—— 生产档位应看到：

```
[hashdb] 过滤引擎已启用: sha256=3,566,584 md5=3,435,483 fuzzy=5,672,578
[hashdb] 硬要求校验通过：['sha256', 'md5', 'fuzzy'] 全部就绪
[startup] 环境档位=prod 运行时覆盖文件=禁用（CODEFENDER_RUNTIME_CFG_DISABLE=1）
[startup] 过滤引擎要求=硬要求（缺库拒绝启动）
```

若需**固化到镜像/容器配置**而非每次 `-e`，改 `/etc/supervisord.d/codefender.ini` 的 `environment=` 行
（supervisor 只会覆盖该行列出的键，其余环境变量照常继承；仓库里的 `codefender.ini` 已带生产档位三项）：

```ini
environment=CODEFENDER_ENV="prod",CODEFENDER_RUNTIME_CFG_DISABLE="1",CODEFENDER_HASH_DB_ENABLED="1",CODEFENDER_FUZZY_DB_ENABLED="1",CODEFENDER_REQUIRE_HASH_DB="1",...
```

改后 `supervisorctl restart codefender` 生效（无需重建镜像）。

### 查看日志

```bash
# supervisor 日志
docker logs -f codefender

# 进入容器
docker exec -it codefender bash

# 应用日志
docker exec codefender cat /var/log/supervisor/codefender.log
```

### 管理容器

```bash
docker stop codefender
docker start codefender
docker restart codefender
docker rm -f codefender
```

### 容器内改配置：什么时候要重建、什么时候不用

| 改的东西 | 最小代价的生效方式 |
|----------|--------------------|
| 只想临时切开关（过滤引擎 / tlsh 限流 / 库目录） | `curl -X POST http://<host>:8000/admin/config -d '{"hash_db_enabled":false}'` —— 免重建、免重启 |
| 想固化开关 | 改 `/etc/supervisord.d/codefender.ini` 的 `environment=` 行 → `supervisorctl restart codefender`（**无需重建镜像**） |
| 想固化在文件里 | 容器内写 `/app/runtime_config.json` → `curl -X POST .../admin/config -d '{"reload_file":true}'`（下次启动也会自动加载） |
| 改 `docker run -e` 的环境变量 | ❌ `docker restart` / `docker start` **不会**重读 `-e`，必须 `docker rm` 旧容器后重新 `docker run`（compose：`docker compose up -d --force-recreate`） |
| 改 `config.py` / `engine/*.py` 等源码 | 代码是 `COPY` 进镜像的 → 改宿主机文件对容器无影响，**必须 `docker build` 重建镜像** |

> 判断"容器里的进程到底吃了哪份配置"：
> `docker exec codefender supervisorctl status` + `curl -s localhost:8000/health` →
> 看 `pid` / `started_at`（重启后必然变化）、`runtime_cfg_applied`、`hash_db`。
> 注意 supervisor 只管 `codefender` 这一个进程，直接 `kill` 掉 uvicorn 会被它按**自己的**
> `environment=` 拉起 —— 你在 shell 里 `export` 的变量不会进新进程。

---

## API 接口

共 11 个端点：3 个探针/指标类（`/livez`、`/readyz`、`/metrics`）
+ 3 个业务类（`/health`、`/predict-single`、`/predict-directory`）
+ 5 个管理类（`/model-info`、`/reload-model`、`/update-signatures`、`GET|POST /admin/config`）。

| 端点 | 方法 | 用途 | 章节 |
|------|------|------|------|
| `/livez` | GET | 存活探针（不碰模型） | [探针与运维端点](#探针与运维端点) |
| `/readyz` | GET | 就绪探针（模型是否可服务，503 = 未就绪） | [探针与运维端点](#探针与运维端点) |
| `/metrics` | GET | 运行时指标（含过滤引擎状态） | [探针与运维端点](#探针与运维端点) |
| `/health` | GET | 健康检查 + 档位/引擎形态/模型 MD5 | [业务端点](#业务端点) |
| `/predict-single` | POST | 单文件检测 | [业务端点](#业务端点) |
| `/predict-directory` | POST | 目录批量扫描 | [业务端点](#业务端点) |
| `/model-info` | GET | 模型/病毒库档案（含 MD5 校验） | [管理端点](#管理端点) |
| `/reload-model` | POST | 集成模型热更新 | [管理端点](#管理端点) |
| `/update-signatures` | POST | **哈希签名库一条龙更新（导入→校验→发布→热切换）** | [管理端点](#管理端点) |
| `/admin/config` | GET | 查看运行时配置（值/来源/能否热生效） | [管理端点](#管理端点) |
| `/admin/config` | POST | 运行时改配置（免重启，生产不落盘） | [管理端点](#管理端点) |

> `/model-info`、`/reload-model`、`/update-signatures`、`/admin/config` **均不做鉴权**，
> 生产环境请置于内网或网关之后。

### 探针与运维端点

#### GET `/livez` — 存活探针

不接触模型，仅检查进程是否存活。适合 K8s `livenessProbe`。

```bash
curl http://localhost:8000/livez
```

**响应示例**:
```json
{
  "alive": true,
  "uptime_sec": 3600,
  "uptime_human": "01:00:00"
}
```

#### GET `/readyz` — 就绪探针

检查模型是否已加载并可服务。未就绪返回 HTTP 503。适合 K8s `readinessProbe`。

```bash
curl http://localhost:8000/readyz
```

**就绪时 (200)**:
```json
{
  "ready": true,
  "model_count": 33,
  "view_count": 16
}
```

**未就绪时 (503)**:
```json
{
  "ready": false,
  "reason": "model not loaded",
  "model_path": "/app/ensemble.pkl"
}
```

#### GET `/metrics` — 运行时指标

返回 Prometheus 兼容的运行时统计，用于监控面板或告警。

```bash
curl http://localhost:8000/metrics
```

**响应示例**:
```json
{
  "total_requests": 142,
  "predict_single_ok": 80,
  "predict_single_error": 3,
  "predict_dir_ok": 5,
  "predict_dir_error": 1,
  "scan_files_total": 520,
  "scan_files_malicious": 410,
  "scan_files_benign": 110,
  "last_predict_ms": 234.5,
  "unhandled_errors": 0,
  "uptime_sec": 3600,
  "models_loaded": true,
  "model_count": 33
}
```

| 指标字段 | 含义 |
|----------|------|
| `total_requests` | 服务启动以来总请求数 |
| `predict_single_ok` | 单文件检测成功次数 |
| `predict_single_error` | 单文件检测失败次数 |
| `predict_dir_ok` | 目录扫描成功次数 |
| `predict_dir_error` | 目录扫描失败次数 |
| `scan_files_total` | 累计扫描文件总数 |
| `scan_files_malicious` | 累计检出恶意文件数 |
| `scan_files_benign` | 累计检出正常文件数 |
| `last_predict_ms` | 最近一次预测耗时 (ms) |
| `unhandled_errors` | 全局异常处理器捕获的未处理错误数 |
| `uptime_sec` | 服务运行时长 (秒) |
| `models_loaded` / `model_count` | 模型是否已加载 / 集成子模型数量 |
| `hash_db_enabled` | 过滤引擎总开关当前状态 |
| `hash_db_mode` | 检测链路形态（`model_only` / `hash_db+model` / `hash_db_partial+model`） |
| `hash_db_sha256` / `hash_db_md5` / `hash_db_fuzzy` | 三库条数（关闭或不可用时为 `0`） |

> `hash_db_mode` = `model_only` 时说明当前所有样本都走模型集成（预检未生效），
> 排查方式见 [方式四/方式五](#方式四关闭过滤引擎纯模型检测)。

---

### 业务端点

#### GET `/health` — 健康检查

```bash
curl http://localhost:8000/health
```

**响应示例**:
```json
{
  "status": "ok",
  "pid": 6648,
  "started_at": "2026-10-08 09:17:04",
  "env": "prod",
  "engine_mode": "hash_db+model",
  "runtime_cfg_file": "/app/runtime_config.json",
  "runtime_cfg_file_enabled": false,
  "runtime_cfg_disabled_reason": "prod profile",
  "runtime_cfg_applied": [],
  "runtime_cfg_error": "",
  "require_hash_db": true,
  "model_path": "/app/ensemble.pkl",
  "model_md5": "a1b2c3d4e5f6...",
  "model_count": 33,
  "view_count": 16,
  "views": ["V1_byte", "V2_byte_stat", "V3_pe_struct", ...],
  "malgraph": {
    "enabled": true,
    "status": "ready",
    "device": "cpu",
    "checkpoint": "/app/models/MalGraph_2022/best_model.pt",
    "vocab": "/app/models/MalGraph_2022/saved/train_external_function_name_vocab.jsonl"
  },
  "hash_db": {
    "enabled": true,
    "fuzzy_enabled": true,
    "mode": "hash_db+model",
    "dir": "/app/signatures",
    "sha256": 3566584,
    "md5": 3435483,
    "fuzzy": 5672578
  }
}
```

> `model_md5` 字段用于校验模型文件完整性，由生产加固模块新增。

#### POST `/predict-single` — 单文件检测

```bash
# 快速检测（不提取 D/E 特征）
curl -X POST "http://localhost:8000/predict-single?include_de=false" \
  -F "file=@sample.exe"

# 完整检测（含反汇编/图特征，需要 BinaryNinja）
curl -X POST "http://localhost:8000/predict-single?include_de=true" \
  -F "file=@sample.exe"
```

> ⚠️ `include_de` 是 **query 参数**（`?include_de=false`），不是表单字段。
> 写成 `-F "include_de=false"` 不会报错但**会被静默忽略** → D/E 特征照跑，
> 单样本耗时从 2~3s 变成 30~130s。`recursive` / `directory` 同理。

**请求参数**:

| 参数 | 位置 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|------|--------|------|
| `file` | body (multipart) | UploadFile | 是 | — | 上传的 PE 样本文件 |
| `include_de` | **query** | bool | 否 | `true` | 是否提取反汇编/图(D/E)特征 |

**响应摘要**:
```json
{
  "FileName": "sample.exe",
  "FileSize": 123456,
  "Status": 1,
  "StatusLabel": "Malicious",
  "IsMalicious": true,
  "EnsembleScore": 0.8723,
  "ModelStats": {
    "TotalModels": 33,
    "OkModels": 30,
    "MaliciousVotes": 28,
    "BenignVotes": 2,
    "AgreementRate": 0.9333
  },
  "DriftEvidence": { "anomaly_score": 0.12, "is_drift_candidate": false },
  "PerModelScores": [...]
}
```

**错误码**:
| HTTP 状态码 | 含义 |
|-------------|------|
| 200 | 检测成功 |
| 400 | 文件为空 / PE 格式无效 |
| 413 | 文件过大 (>64MB) |
| 500 | 服务端内部异常 |

#### POST `/predict-directory` — 目录批量扫描

```bash
# 递归扫描（默认）
curl -X POST "http://localhost:8000/predict-directory?directory=/samples/malware&recursive=true&include_de=false"

# 仅扫描顶层目录
curl -X POST "http://localhost:8000/predict-directory?directory=/samples/malware&recursive=false"
```

**请求参数**:

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `directory` | str | 是 | — | 服务器端目录的绝对路径 |
| `recursive` | bool | 否 | `true` | 是否递归扫描子目录 |
| `include_de` | bool | 否 | `false` | 批量模式默认关闭 D/E 以加速 |

**响应示例**:
```json
{
  "Summary": {
    "TotalFiles": 100,
    "ScannedFiles": 98,
    "MaliciousCount": 85,
    "BenignCount": 13,
    "ErrorCount": 2,
    "Directory": "/samples/malware"
  },
  "Results": [
    { "FileName": "sample_01.exe", "Status": 1, "IsMalicious": true, ... },
    { "FileName": "sample_02.dll", "Status": 0, "IsMalicious": false, ... }
  ]
}
```

---

### 管理端点

#### GET `/model-info` — 模型/病毒库档案

返回当前集成模型的完整档案信息，包括文件完整性校验 (MD5)。

```bash
curl http://localhost:8000/model-info
```

**响应字段**:

| 字段 | 含义 |
|------|------|
| `file.path` | 模型文件路径 |
| `file.size_mb` | 文件大小 (MB) |
| `file.last_modified` | 文件最后修改时间 |
| `file.md5` | 模型文件 MD5 哈希 (完整性校验) |
| `ensemble.model_count` | 集成子模型总数 |
| `ensemble.view_count` | 视角组数量 |
| `models[]` | 逐模型加载状态列表 |
| `views{}` | 视角组详情 (label/ATT&CK映射/模型列表) |
| `sdd.initialized` | SDD 漂移检测引擎是否初始化 |
| `malgraph.*` | MalGraph 图模型状态 |

#### POST `/reload-model` — 病毒库热更新

不传参则原地重载当前模型文件；传参 `model_path` 则切换到新路径并加载。

```bash
# 原地重载
curl -X POST http://localhost:8000/reload-model

# 切换到新模型
curl -X POST "http://localhost:8000/reload-model?model_path=/path/to/new_ensemble.pkl"
```

**请求参数**:

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `model_path` | str | 否 | 新模型文件绝对路径，不传则重载当前路径 |

#### POST `/update-signatures` — 签名库一条龙更新

过滤引擎四级哈希签名库（`sha256` / `md5` / `fuzzy`）的**在线更新入口**。上传或指向签名源后：

```
探测格式 → 复制 staging 副本 → 导入(逐文件) → finalize 重算 Bloom
        → 计数校验 → VACUUM 受影响分片 → os.rename 发布 releases/v<ts>
        → current 指向 → 从发布目录重建实例 → 原子热切换全局引用
```

全程只在 **staging 副本**上操作，不触碰在线旧库；任一步失败都**保留旧库**（服务不受影响，无需重启）。

**源格式自动探测（逐文件，以首个有效行为准）**：

| 源格式 | 结构 | 入库方式 |
|--------|------|----------|
| 日更 CSV | 22 列，表头含 `sha256` / `md5` / `ssdeep` | 按列分别喂 sha256 / md5 / fuzzy 库 |
| hashBase 9 字段 | `sha256:size:name:ssdeep:tlsh:md5:rich:authentihash:imphash:` | 同上（第 6 字段为 32 位 hex 即判定） |
| ClamAV hdb | `sha256:size:name[:ssdeep:vhash:authentihash:imphash:rich[:tlsh]]` | 3 字段行喂 sha256·md5；带 ssdeep 等字段的行喂 fuzzy |

```bash
# ① 上传单个日更 CSV
curl -X POST "http://localhost:8000/update-signatures?week_id=2026W40" \
  -F "file=@cn_vt_2026W40.csv"

# ② 指向服务器本地目录（挂载的 hashBase，或一批 00.hdb~ff.hdb）
curl -X POST "http://localhost:8000/update-signatures?dir_path=/data/hdb&week_id=2026W40"

# ③ 上传 .zip（内含多个 .csv/.hdb，自动解包逐个导入）
curl -X POST "http://localhost:8000/update-signatures?week_id=2026W40" \
  -F "file=@sigs_2026W40.zip"
```

**请求参数**（`file` 与 `dir_path` **必须二选一**）：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `file` | UploadFile | 否 | — | 上传 `.csv` / `.hdb` / `.zip`；与 `dir_path` 二选一 |
| `dir_path` | str | 否 | — | 服务器本地目录（含日更 CSV 或 `00.hdb`~`ff.hdb`）；与 `file` 二选一 |
| `week_id` | str | 否 | 时间戳 | 周/日标识（如 `2026W40`、`20260923`）。导入记录以 `<week_id>__<文件名>` 登记，**每次必须换新** |
| `malicious_only` | bool | 否 | `true` | CSV 源专用：跳过无任何威胁标注（category / family / kav / defender / vt）的行 |
| `vacuum` | bool | 否 | `true` | 是否对受影响分片执行 `VACUUM`（增量更新建议开） |

**响应示例（有新签名 → 发布并热切换）**：

```json
{
  "status": "published",
  "files": 1,
  "week": "2026W40",
  "formats": { "csv": 1 },
  "csv_stats": {
    "rows_total": 120000, "rows_ok": 118340,
    "skip_no_sha256": 0, "skip_unlabeled": 1660,
    "has_md5": 118340, "has_ssdeep": 96421, "has_tlsh": 88120,
    "has_imphash": 102233, "has_authentihash": 102233,
    "has_rich": 118340, "has_vhash": 0
  },
  "release": "/app/signatures/releases/v20261008-091530",
  "active_dir": "/app/signatures/releases/v20261008-091530",
  "rows_inserted": { "sha256": 118340, "md5": 118340, "fuzzy": 96421 },
  "counts": {
    "before": { "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578 },
    "after":  { "sha256": 3684924, "md5": 3553823, "fuzzy": 5768999 }
  },
  "vacuum": { "sha256": { "vacuumed_shards": 12, "seconds": 3.4 } },
  "note": "已热切换，无需重启。回滚：将 current 指回上一版本目录后重启进程（重启会经 _active_sig_dir 解析回旧版）。"
}
```

**响应示例（重复投递 / 输入已全在库中 → 不发布）**：

```json
{
  "status": "no_new_rows",
  "detail": "所有输入均未产生新签名（行级去重），未发布新版本",
  "files": 1,
  "week": "2026W40",
  "formats": { "csv": 1 },
  "csv_stats": { "rows_total": 120000, "rows_ok": 118340 },
  "counts": { "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578 }
}
```

**错误码**：

| HTTP | 含义 |
|------|------|
| 400 | `HASH_DB_ENABLED=0`；`file` / `dir_path` 未二选一；`dir_path` 不是目录；非法文件名；非 `.csv/.hdb/.zip`；输入中无非空签名文件；zip 损坏 |
| 409 | 某族计数**回退**（新库 `<` 在线旧库），拒绝发布 |
| 500 | staging / 发布 / 热切换失败（**旧库保留**，服务不受影响） |

**语义要点**：

| 要点 | 说明 |
|------|------|
| 幂等 | 行级 `INSERT OR IGNORE`；同名文件重复投递**不会**被按文件名去重误跳（`week_id` 前缀 + 行级幂等双保险） |
| 原子 | 发布前全程在 staging 副本；`os.rename` 同卷原子；校验不过不换引用 |
| 热切换 | 发布后从 `releases/v<ts>` 重建实例并核对计数，通过才换全局引用；旧库在新实例就位后才关闭 |
| 回滚 | 把 `current` 指回上一版本目录 + 重启进程即可（重启经 `_active_sig_dir()` 解析回旧版） |
| 鉴权 | **不做鉴权**（与 `/reload-model`、`/admin/config` 一致），生产须置于内网或网关之后 |

> ⚠️ **目录布局**：容器内 `/app/signatures` 出厂是**扁平**布局（`<fam>.db.shards` / `<fam>.db.bloom`
> 直接在其下），首次更新会自动创建 `releases/` 与 `current`，此后 `_active_sig_dir()` 走版本化分支。
>
> ⚠️ **持久化**：本镜像**零挂载**，`/app/signatures` 落在容器可写层 —— 所以在线更新的结果
> 容器重启仍在，但 `docker rm` 即回滚到镜像里那一版。要**固化**请走「换库 = 换镜像」：
> `python docker/stage_signatures.py && docker build -t codefender-c3:v8.1 .`（可回滚、可追溯、
> 多副本一致）。**不建议**给 `/app/signatures` 挂卷 —— 会让容器读到与镜像版本脱钩的旧库。

#### GET `/admin/config` — 查看运行时配置

返回每个可覆盖项的当前值、来源（`env` / `default` / `runtime:api` / `runtime:file`）、
是否支持热生效，以及进程 `pid` / `started_at`（判断请求是否打到你以为的那个进程）。

```bash
curl -s http://localhost:8000/admin/config | python -m json.tool
```

```json
{
  "pid": 6648,
  "started_at": "2026-09-24 16:20:57",
  "env_profile": "dev",
  "engine_mode": "hash_db+model",
  "config_file": "/app/runtime_config.json",
  "config_file_exists": false,
  "config_file_enabled": true,
  "config_file_disabled_reason": "",
  "config_file_error": "",
  "config_file_applied": [],
  "require_hash_db": false,
  "items": {
    "HASH_DB_ENABLED": {"value": true, "origin": "default", "env": "CODEFENDER_HASH_DB_ENABLED",
                        "env_raw": null, "baseline": true, "hot_reload": true, "type": "bool"}
  },
  "hash_db": {"enabled": true, "fuzzy_enabled": true, "mode": "hash_db+model",
              "sha256": 3566584, "md5": 3435483, "fuzzy": 5672578}
}
```

`config_file_enabled=false` 表示当前是生产档位（容器 / `CODEFENDER_ENV=prod`）：
覆盖文件被忽略、`persist` 会被 409 拒绝。`engine_mode` 见「方式六」。

#### POST `/admin/config` — 运行时改配置（免重启）

```bash
# 关闭 / 开启过滤引擎
curl -X POST http://localhost:8000/admin/config -H "Content-Type: application/json" \
     -d '{"hash_db_enabled": false}'
curl -X POST http://localhost:8000/admin/config -H "Content-Type: application/json" \
     -d '{"hash_db_enabled": true, "fuzzy_db_enabled": true}'

# 改完落盘（重启后仍生效）
curl -X POST http://localhost:8000/admin/config -d '{"persist": true, "hash_db_enabled": false}'

# 复位到环境变量/默认值基线；reload_file 重新读取覆盖文件
curl -X POST http://localhost:8000/admin/config -d '{"reset": ["HASH_DB_ENABLED"]}'
curl -X POST http://localhost:8000/admin/config -d '{"reload_file": true}'
```

**请求体字段**:

| 字段 | 说明 |
|------|------|
| `<配置项名小写>` | 如 `hash_db_enabled`；大小写不敏感，也可嵌套在 `{"overrides": {...}}` 内 |
| `persist` | `true` = 同时写入 `runtime_config.json`，重启后仍生效。**生产档位下 409 拒绝**（见下） |
| `reset` | 配置项名数组（或单个字符串），恢复为 env/默认值基线；不传则不动 |
| `reload_file` | `true` = 重新读取 `runtime_config.json` 并应用。**生产档位下 409 拒绝**（该文件本就被忽略） |

非法配置项名 / 非法值 → HTTP 400（**整批拒绝，不会改一半**）。
`hash_db_enabled` / `fuzzy_db_enabled` / `hash_db_dir` 变更会自动重建三库引用
（关闭瞬时；开启需装载，装载期间旧状态继续服务，完成后原子切换）。
响应含 `cold_keys_pending_restart`，列出"已改但需重启才生效"的项。

**档位差异（开发 vs 生产）**：

| 动作 | dev（本机） | prod（容器） |
|------|-------------|--------------|
| 内存内热切换（默认） | ✅ 生效 | ✅ 生效，**重启即恢复**；若在 `REQUIRE_HASH_DB=1` 下关预检，日志记 WARNING |
| `persist: true` 落盘 | ✅ | ❌ 409（不让容器里留下跨重启的调试开关；要固化请改 `codefender.ini`） |
| `reload_file: true` | ✅ | ❌ 409（该文件在生产档位本就不加载） |

> ⚠️ 与 `/reload-model`、`/update-signatures` 一致，本端点**不做鉴权**，生产请置于内网或网关之后。

---

### 生产加固特性

| 特性 | 机制 | 环境变量 |
|------|------|----------|
| 并发限制 | `asyncio.Semaphore` 包裹 `/predict-single` 和 `/predict-directory` | `CODEFENDER_MAX_CONCURRENT` (默认 4) |
| 请求追踪 | HTTP 中间件注入 `X-Request-ID` 响应头 + 结构化日志 | — |
| 全局异常处理 | `@app.exception_handler(Exception)` 捕获未处理异常 + 计数 | — |
| MD5 完整性校验 | `_file_md5()` → `/health` 和 `/model-info` 均返回 `model_md5`/`md5` | — |
| 安全临时文件 | `_tmp_upload` contextmanager 替代手动 `tempfile`，异常路径下也确保清理 | — |

---

## 测试指南

### 1. 快速功能验证

使用项目自带的 `testsamples/` 目录中的测试样本：

```bash
# 1. 启动服务
uvicorn engine.app:app --host 0.0.0.0 --port 8000

# 2. 健康检查
curl -s http://localhost:8000/health | python -m json.tool

# 3. 单文件检测（使用测试样本）
curl -s -X POST "http://localhost:8000/predict-single?include_de=false" \
  -F "file=@testsamples/013b241f57afe80f51b5a681774b7aa875b7c676865320ed3ae508a7ba4b9b04" \
  | python -m json.tool
```

### 2. 批量目录扫描测试

```bash
# 扫描整个 testsamples 目录
curl -s -X POST "http://localhost:8000/predict-directory?directory=$(pwd)/testsamples&recursive=false&include_de=false" \
  | python -m json.tool
```

### 3. Python 客户端测试脚本

```python
import requests

BASE = "http://localhost:8000"

# 健康检查
resp = requests.get(f"{BASE}/health")
print(f"Health: {resp.json()['status']}")

# 单文件检测
with open("testsamples/013b241f57afe80f51b5a681774b7aa875b7c676865320ed3ae508a7ba4b9b04", "rb") as f:
    resp = requests.post(
        f"{BASE}/predict-single",
        files={"file": f},
        data={"include_de": "false"},
    )
    result = resp.json()
    print(f"File: {result['FileName']}")
    print(f"Label: {result['StatusLabel']} (score: {result['EnsembleScore']:.4f})")
    print(f"Malicious votes: {result['ModelStats']['MaliciousVotes']}/{result['ModelStats']['OkModels']}")
```

### 4. 压力测试（可选）

```bash
# 使用 Apache Bench
ab -n 100 -c 10 http://localhost:8000/health

# 使用 wrk
wrk -t4 -c10 -d30s http://localhost:8000/health
```

### 5. 预期行为

| 场景 | 预期结果 |
|------|----------|
| 合法 PE 文件 | 返回预测分数 + 标签，per-model scores |
| 非 PE 文件（如 .txt） | HTTP 400: "文件结构不对，或者文件格式损坏" |
| 超过 64MB 文件 | HTTP 413: "file too large" |
| 服务未就绪 | `/health` 返回 `status: "error"` + reason |

---

## 训练管线

> **2026-09-16 目录整理**：训练侧脚本已统一移入 `CoDefenderC3/train/`，
> 说明文档移入 `CoDefenderC3/docs/`。所有命令请从**项目根**执行，
> 并带上新的 `CoDefenderC3/train/` 前缀。详细用法见 `CoDefenderC3/train/README.md`。

`train/run_all.py` 提供完整的实验管线，支持双模式架构：

### 主进程模式（默认）

```bash
python CoDefenderC3/train/run_all.py
```

自动完成:
1. 数据加载（支持年份子目录 `malicious_sample/{2019~2024}/`）
2. 训练 33 个子模型
3. 校准 SDD 漂移检测 + 7 个基线方法
4. 逐月评估 + 漂移检测 + DACP + DSIR
5. 消融实验（可选）
6. 生成图表 + HTML 报告 + JSON/CSV 结果

### 子进程模式

```bash
python CoDefenderC3/train/run_all.py --single <data_dir>
```

⚠ `--single` 会把 `config.MODEL_PATH` 改写成 `results/<dataset>/ensemble.pkl`，
**不会**覆盖仓库根的 `ensemble.pkl`。

### 前置条件

1. 修改 `config.py` 中的 `DATA_DIR` 指向样本目录
2. 确保样本目录结构: `DATA_DIR/{year}/` (如 2019, 2020, ...)
3. 对于 EMBER 数据，需要 `metadata.json` 包含 `feature_ranges` 字段

---

## 配置参考

核心配置文件: `config.py`

```python
# 路径配置
DATA_DIR    = os.environ.get("CODEFENDER_DATA_DIR", r"D:\VM_Share\testsamples\CoDefenderC3_data")
MODEL_PATH  = os.path.join(ROOT, "ensemble.pkl")   # 默认: ./ensemble.pkl

# 实验参数
RUN_ABLATION = True    # 是否运行消融实验
SAVE_MODEL   = True    # 是否保存训练好的模型
N_WORKERS    = 16      # 并行工作线程数
SEED         = 42      # 随机种子

# 视图组定义: VIEW_GROUPS (16 个视角组 × 33 个模型)
```

---

## 项目结构

```
CoDefenderC3_v8/
├── engine/                      # API 服务层
│   ├── app.py                   # FastAPI 应用 (11 个端点 + 生产加固)
│   ├── inference.py             # 推理核心 + PE 验证
│   ├── result_formatter.py      # 结果格式化
│   └── packer_detector.py       # 加壳检测
├── core/                        # SDD 漂移检测引擎
│   ├── sdd_engine.py            # 谱漂移分解核心
│   ├── baselines.py             # 7 个基线方法
│   ├── stats.py                 # 统计分析
│   ├── llm_module.py            # LLM 辅助分析
│   └── slfe_verify.py           # 自验证模块
├── models/                      # 33 个子模型 (模型名_年份/)
│   ├── ensemble.py              # MultiModelEnsemble 集成类
│   ├── MalConv_2017/
│   ├── MalConv2_2021/
│   ├── EmberGBDT_2018/
│   ├── MalGraph_2022/
│   └── ... (共 30+ 模型目录)
├── feature_extraction/          # 特征提取层（引擎与训练共用 → 保留在根）
│   ├── unified.py               # 15 种 FeatureType 统一入口
│   └── extract_feature.py       # BinaryNinja 48 项底层特征
├── train/                       # ← 训练侧（2026-09-16 自仓库根整理至此）
│   ├── run_all.py               # 训练 / 实验主管线
│   ├── train_minimal.py         # 增量训练 + 逐模型 checkpoint
│   ├── build_minimal_dataset.py # 与基线视角对齐的数据集构建
│   ├── verify_trained_ensemble.py  # 候选 pkl 与基线等价性校验（门禁）
│   ├── build_dataset.py         # 数据集构建（EMBER / RAW PE）
│   ├── build_rawpe.py           # 裸 PE 数据集构建
│   ├── data_loader.py           # PELoader：特征提取 / 月度缓存
│   ├── dataset_utils.py         # 数据集收尾工具
│   ├── ember_vectorizer.py      # 纯 NumPy EMBER 向量化
│   ├── _probe_ensemble.py       # 容错拆解 ensemble.pkl
│   ├── _verify_ensemble_load.py # 验证 load / 推理链路
│   ├── _inspect_ensemble.py     # 只读拆解各模型输入约定
│   ├── apply_bn_optimizations.py / benchmark_bn_optimization.py
│   ├── logs/                    # 历史运行日志
│   └── README.md                # 训练侧使用说明
├── docs/                        # ← 说明文档（2026-09-16 自仓库根整理至此）
│   ├── README.md                # 本文件（架构 / API 端点 / 配置参考）
│   ├── TESTING.md               # Docker 部署与接口测试指南
│   ├── PAPERS.md                # 模型论文与架构参考
│   ├── BINARYNINJA_OPTIMIZATION_GUIDE.md
│   └── 增量训练与Checkpoint技术方案.md
├── docker/                      # 镜像构建工具链（2026-09-30 新增）
│   ├── build.sh                 # 一键：暂存签名库 → 上下文预检 → docker build
│   ├── stage_signatures.py      # 解析 current/releases → 硬链接暂存到 .docker_build/
│   ├── check_context.py         # 构建上下文预检（COPY 源 / .dockerignore 误挡 / 体积）
│   └── check_requirements.py    # 依赖核查：导入闭包分析 ↔ requirements.txt 比对（2026-10-08）
├── scaner/                      # 哈希库扫描器（与 nkrepo 项目同步）
├── signatures/                  # 哈希签名库分片（sha256 / md5 / fuzzy）
├── runs/                        # 训练产物 runs/<run_id>/
├── config.py                    # 全局配置 (路径/参数/视图组/档位)  ← 引擎与训练共用
├── model_registry.py            # 模型中心注册表               ← 引擎与训练共用
├── ensemble.pkl                 # 预训练模型权重 (834 MB)
├── requirements.txt             # Python 依赖
├── Dockerfile                   # Docker 构建文件（固化 prod 档位：全引擎 + 缺库拒绝启动）
├── .dockerignore                # 排除 runtime_config.json / signatures/ 等开发期与大数据
├── supervisord.conf             # Supervisor 主配置
├── codefender.ini               # Supervisor program 配置（生产档位环境变量在此）
├── dev_model_only.cmd           # 【本机开发】纯模型链路启动（Windows，ASCII-only）
├── dev_model_only.sh            # 【本机开发】纯模型链路启动（Linux/VM）
├── _probe_env_profile.py        # 档位隔离回归探针（41 项断言）
├── _probe_runtime_cfg.py        # 运行时配置热切换探针（20 项断言）
└── testsamples/                 # 测试样本 (SHA256 命名)
```

> **为什么 `config.py` / `model_registry.py` / `feature_extraction/` 不搬进 `train/`**：
> 这三者被引擎侧（`engine/app.py`、`models/ensemble.py`）与训练侧共同依赖，
> 属于共享基础设施，移动会同时打断推理服务。`train/` 内的脚本通过
> 「把 `train/` 的上一级加回 `sys.path`」来继续 `import config`。

---

## 常见问题

**Q: 启动时报 `FileNotFoundError: model file not found`**
A: 检查 `ensemble.pkl` 是否在项目根目录，或设置 `CODEFENDER_MODEL_PATH` 环境变量指向正确路径。

**Q: MalGraph 加载失败**
A: 确保 `models/MalGraph_2022/` 下有 `best_model.pt` checkpoint 和 `train_external_function_name_vocab.jsonl` 词汇表文件；或在 Docker 启动时设置 `CODEFENDER_ENABLE_MALGRAPH=false` 禁用它。

**Q: Docker 镜像太大**
A: 主要体积来自 sha256/md5/fuzzy 三族签名库（~1GB）、`ensemble.pkl`（736 MiB）和 PyTorch（~800MB，CPU-only 已优化），合计约 2.5~3GB。
这三样都是**刻意内嵌**的（自包含镜像，`docker run` 零挂载、可回滚、多副本一致），**不建议**改成卷挂载。
真要瘦身，优先看这几处：① `models/MalGraph_2022/saved/features.jsonl`（104MB，仅训练脚本引用，
`.dockerignore` 加一条即可挡掉）；② 签名库按需裁剪族（但生产要求三族齐备）；③ PyTorch 已用 CPU 源。

**Q: 如何在 CUDA 环境下使用 GPU 加速？**
A: 将 Dockerfile 中 PyTorch 安装的 `--index-url` 改为 GPU 版本，并设置 `CODEFENDER_MALGRAPH_DEVICE=cuda`。开发环境直接安装 GPU 版 PyTorch 即可。
