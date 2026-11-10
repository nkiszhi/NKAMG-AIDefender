# SMDA 反汇编后端（替代 BinaryNinja）

SMDA 与可选 BN 后端都先生成 ProgramIR，再由同一特征层计算 D/E 和 MalGraph 图输入。
SMDA 不依赖 BinaryNinja 商业许可；两种后端的函数发现与反汇编结果仍可能不同，
**相同维度/算法不代表跨后端特征值相同，也不自动保证旧模型权重兼容**。

2026-11-09 修复三个集成缺口：默认值、普通安装依赖加载、旧统一特征入口；
同时修复 Windows 训练批处理将 CRLF 成功状态误判为未报告并删除 IR 的问题。
验证范围和结果见第 6 节；未用本次本机测试代替实际 Docker 镜像验收。

## 1. 开关

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `CODEFENDER_DISASM_BACKEND` | `smda` | `smda` / `bn`；未设置、空值或无效值均回到 SMDA |
| `CODEFENDER_SMDA_PKGS` | 未设置 | 可选依赖目录；显式指定时优先，目录无效直接报错 |
| `CODEFENDER_ANALYSIS_TIMEOUT` | `180` | 隔离分析 worker 的预算（秒），启动配置可覆盖 |
| `CODEFENDER_ANALYSIS_TIMEOUT_MAX` | `3600` | 隔离分析允许的预算上限（秒） |

后端调度与 MalGraph 产物指纹检查的默认值保持一致。开发启动脚本 `dev_model_only.cmd/sh`
默认设置 SMDA，尊重已有后端环境变量；BN 专用脚本 `dev_bn.cmd` 显式设置 BN。
修改后端或依赖目录后需重启进程，不在运行中替换已导入的原生扩展。

## 2. SMDA 依赖加载

加载顺序：

1. 设置了 `CODEFENDER_SMDA_PKGS`：检查并优先使用该目录，不静默改用其他来源。
2. 未设置：先直接导入当前解释器可用的 `lief`、`capstone`、`smda.Disassembler`。
   **普通 pip 安装不再要求项目旁边有 `_tools`**。
3. 普通导入失败：尝试项目上一级的 `_tools/py<major><minor>_pkgs`，如 Python 3.11
   只发现 `py311_pkgs`，不尝试其他 ABI 目录。vendor 缺少 lief/capstone 时可用解释器安装的版本。

会实际导入依赖并报告失败模块（包括原生扩展 ABI 错误），而非仅检查目录是否存在。
失败的 vendor 路径不会残留在 sys.path；失败中新加载的 SMDA 子模块会清理，避免污染回退。

## 3. 特征入口与口径

| 入口 | 当前路径 / 输出 |
|---|---|
| `extract_de_only` | PE → 后端 → ProgramIR → D01–D07 / E03 / E04 |
| `engine.analysis_worker` | SMDA 一次带调用点分析同时供给 D/E 和 MalGraph；BN 保留 basic/full 两档 |
| 训练 `generate_irs_batch` / `extract_de_from_ir_batch` | PE → .ir.json.gz → .npz；后者不再需要反汇编后端 |
| `unified.OPCODE_SEQ` | 参数化 D01；默认 4096，IR 顺序，crc32 % 511 + 1，零填充，int64 |
| `unified.FUNC_EMBEDDINGS` | 参数化 D07；默认 48 × 128，每函数助记符哈希直方图，**L2** 归一化，float32 |
| `unified.GRAPH_STAT` | **E03（12）+ E04（10）**，与主图统计视图一致，float32 |
| `unified.PYG_GRAPH` | 仍明确抛 NotImplementedError，请使用 MalGraph 专用 Dataset/图入口 |

旧 unified 入口不再直接导入 BinaryNinja。反汇编失败直接抛错，**禁止字节近似操作码、
随机函数嵌入、EMBER 近似图统计**，也不再由 UnifiedDataset 将这些 IR 失败变成带标签的零向量。
成功分析为空 IR 时的统计零值/填充零值仍是合法结果，与分析异常不同。

**迁移兼容性：** 主 D01/D07/E03/E04 算法不变；旧 unified 的函数嵌入从 L1 改为 D07 的 L2，
旧 GRAPH_STAT 的布局改为 E03/E04（旧实现错误地把 CFG 后继当调用边）。
使用旧 unified 特征训练的模型必须重建特征并重训/重新验证，不能只看维度相同就复用权重。
BN 与 SMDA 的 MalGraph 产物也必须满足 `artifact_guard` 的 backend/feature_schema 指纹检查；
不能承诺旧 BN 词表经名称处理后就能直接复用。

## 4. 缓存隔离

三种统一 IR 特征的缓存键现在包含：文件 SHA256、特征类型、后端、ProgramIR schema、
特征 schema（`unified-ir/1`）和输出参数（seq_len / n_funcs / embed_dim）。
旧 `<sha>_<feature>.npy` 不会被当作新 IR 特征缓存读取；历史占位缓存无需手动删除才能生效。
原始字节、EMBER 和图像特征的缓存策略未改变。

这次隔离只覆盖 unified 的三种 IR 特征；已有训练 NPZ/IR 等产物不能因为改了默认值就认为兼容。
切换后端/特征口径时仍需按原有训练流程重建对应产物。

## 5. 部署与自检

在**运行服务的同一个解释器**中安装依赖（通常由 requirements.txt 完成）：

```bash
python -m pip install 'smda>=4.3.10' lief capstone pefile
python -c "from feature_extraction.backend import current_backend; from feature_extraction.backend_smda import _smda_import; print(current_backend(), _smda_import())"
```

Docker 的 pip 安装布局无需复制项目外的 `_tools`。镜像配置仍显式设置
`CODEFENDER_DISASM_BACKEND=smda`；代码变更后需要重新构建并重启容器。
可选 BN 模式仍需安装 BinaryNinja、配置有效许可并使用匹配的训练产物。

隔离 worker 自检：

```bash
python -m engine.analysis_worker /path/sample.exe /tmp/out.pkl
python -c "import pickle; r=pickle.load(open('/tmp/out.pkl','rb')); print(sorted(r['features']),r['errors'],r['timing']); print(r['malgraph'] and r['malgraph']['function_number'])"
```

## 6. 本次验收（2026-11-09）

本机解释器 Python 3.11，SMDA 5.0.2；只做静态分析，不执行 PE 样本。

```bash
python -X utf8 -m unittest discover -s tests -p test_smda_integration.py -v
python -X utf8 tests/test_ir_contract.py
python -X utf8 tests/test_stable_hash.py
python -X utf8 -m unittest discover -s tests -p test_dev_prediction_aggregation.py -v

# 清除后端和依赖目录覆盖后，验证真正的默认值：
python -X utf8 tests/verify_smda_backend.py /path/sample32.bin /path/sample64.bin --output-dir /path/results
python -X utf8 tests/verify_dev_prediction_aggregation.py /path/sample32.bin /path/sample64.bin --include-de --output /path/endpoints.json
```

验证脚本覆盖三种 unified 特征与主层逐值一致、缓存命中、无 BN 导入、普通可导入但无
vendor 邻接目录的布局、分析 worker、训练 PE→IR→NPZ 及开发单双接口一致性。
回归测试 **83/83** 通过（SMDA 集成 33、IR 契约 17、稳定哈希 11、开发聚合 22）。
两个真实 PE 的三种 unified 特征与主层逐值一致，训练 IR/NPZ 均成功，分析 worker errors 为空；
主 D/E 全部特征与修改前实现逐值不变。默认 SMDA 下双接口分数约为 0.454764 / 0.575435，
每个样本均为 30 个成功模型，MalGraph 参与；仍有 MalConv、InceptionV3、IMCFN 三个已有输入尺寸错误，
它们不属于 SMDA 提取失败，也没有被以 0.5 占位加入聚合。

本次结果保存在工作区 `test_results/smda_gap_fix_20261109`。
**未实际构建或启动 Docker 镜像**；安装布局测试是本机的等价模拟，不是容器运行记录。

## 7. hash() 随机性与 hash 优化

### 7.1 问题

D01/D02/D03/D07 的序列 id 与 n-gram 分桶由 Python 内置 `hash()` 生成，而 `str.__hash__`
**每进程随机**（镜像与 supervisor 配置均未设置 `PYTHONHASHSEED`）。训练期的 D/E 特征由多个
独立子进程（`feature_extraction/_de_worker_persistent.py`）提取 ⇒ 训练集本身就是多套随机
映射的混合，推理端无论用哪种确定性映射都无法与之对齐。

### 7.2 SMDA 后端的处理

`feature_extraction/_stable_hash.py` 用 `zlib.crc32` 替代 `hash()`，
使 D02/D03/D07 的分桶在进程间稳定（BN 与 SMDA 两个后端共用这一份）。注意：**这只保证"同一份代码每次运行一致"**，
并不等于与旧权重训练时的随机映射一致 —— 依赖这些维度的旧权重仍然需要重训。

### 7.3 推理期掩码开关（实验 A）

环境变量 `CODEFENDER_MASK_VIEWS`（逗号分隔的视图名，默认空 = 关闭）：

```bash
# 把 V6_opcode_stat 里的哈希依赖特征段 D02/D03 整段置零，
# 模型只能依赖 D04 指令类别分布 / D05 函数统计 / D06 基本块统计
CODEFENDER_MASK_VIEWS=V6_opcode_stat
```

- 只影响推理期的视图拼装：**不改权重、不改视图维度**，可随时开关做 A/B 对比；
- 生效后 `/predict-single` 的视图元信息会出现 `masked(D02,D03)` 标记；
- 实现见 `engine/view_masking.py`（含自检：`python -m engine.view_masking`）。

实测：OpcodeStatNet 的 ROC-AUC 由 0.5478 提升到 0.6108（+0.042），
且 14 个未受影响模型的分数逐位一致（证明补丁只作用于目标视图）。

## 8. GPU 镜像（两个变体）

### 8.1 为什么分两个版本

| 变体 | `--target` | 哈希预检 | 签名库 | 用途 |
|---|---|---|---|---|
| 训练 / 离线测评 | `train` | sha256 / md5 / fuzzy **全关** | 不打进镜像 | 训练、测评——所有样本真正走模型打分 |
| 线上生产 | `serve` | **全开** | 构建期内嵌 `/app/signatures` | 生产——命中签名库直接短路返回 |

两者**反汇编后端、特征口径、模型权重、引擎逻辑完全一致** ⇒ 分数可比。
唯一差异是"哈希预检是否短路"。

> 生产档位与训练档位的区别由 `CODEFENDER_REQUIRE_HASH_DB` 决定：
> `=1` 时签名库缺失或损坏会**拒绝启动**（响的失败优于静默降级）；
> `=0` 时哈希库不参与，缺库也能起（纯模型模式）。
> 所以训练版必须是 `REQUIRE_HASH_DB=0`，否则引擎启动即报错。

### 8.2 构建

```bash
cd CoDefenderC3

# ① 训练 / 测评版（不需要签名库）
docker build -f Dockerfile.smda.gpu --target train -t codefender-c3:gpu-train .

# ② 线上生产版（必须先暂存签名库）
python docker/stage_signatures.py
docker build -f Dockerfile.smda.gpu --target serve -t codefender-c3:gpu-serve .

# 导出（拷到服务器）
docker save codefender-c3:gpu-train | gzip > codefender-c3-gpu-train.tar.gz
docker save codefender-c3:gpu-serve | gzip > codefender-c3-gpu-serve.tar.gz
```

### 8.3 CUDA 版本与驱动要求

默认 `torch 2.5.1+cu121 / torchvision 0.20.1+cu121` → **CUDA 12.1 runtime，驱动 >= 525.60.13**
（3090 / 4090 / A10 都可以）。驱动较新（>= 550）想换 cu124 时不用改文件：

```bash
docker build -f Dockerfile.smda.gpu --target serve \
  --build-arg TORCH_INDEX_URL=https://download.pytorch.org/whl/cu124 \
  --build-arg TORCH_VERSION=2.6.0+cu124 \
  --build-arg TORCHVISION_VERSION=0.21.0+cu124 \
  -t codefender-c3:gpu-serve .
```

服务器需装 **NVIDIA Container Toolkit**，否则 `docker run --gpus all` 会报 "could not select device driver"。

### 8.4 运行

```bash
docker run -d --name codefender -p 8000:8000 --gpus all \
    -e CUDA_VISIBLE_DEVICES=0 \
    -e CODEFENDER_MAX_CONCURRENT=4 \
    codefender-c3:gpu-serve
```

- `CUDA_VISIBLE_DEVICES=0`：**必须指定**，否则 N 个 worker 会散到多张卡上各占一份上下文；
- `CODEFENDER_MAX_CONCURRENT`：每个并发 worker 会各自加载一份 ensemble → 各占一份 CUDA 上下文
  （约 300~500MB 显存/份）。24GB 卡上 4~8 个没问题；再高就先降 `CODEFENDER_MODEL_DEVICE=cpu`。
- 推理设备：`CODEFENDER_MODEL_DEVICE` = `auto`（默认，有 CUDA 就用）/ `cuda` / `cuda:N` / `cpu`；
  `cuda` 不可用时**自动降级 CPU** 并打日志，不会启动失败。
  `CODEFENDER_MALGRAPH_DEVICE` 同理（只管 MalGraph）。

### 8.5 GPU 的实际收益边界（重要，别高估）

单样本耗时构成（6160 样本实测，CPU 版）：

| 阶段 | p50 | 能否被 GPU 加速 |
|---|---:|---|
| SMDA 反汇编（capstone，纯 CPU） | **6.28 s** | ❌ 瓶颈在这 |
| fast 模型前向 | 1.22 s | ✅ |
| slow 模型前向（D/E 模型） | 1.89 s | ✅ |

⇒ **GPU 只能加速那 ~3.1 s 的模型前向，端到端理论上限约 20~30%**；
真正的吞吐杠杆是**并发**（80 核机器上 `CODEFENDER_MAX_CONCURRENT` 还能往上调，
但每个 worker 一份 CUDA 上下文，所以要用 `CUDA_VISIBLE_DEVICES` 把它们钉到同一张卡上，
或 `CODEFENDER_MODEL_DEVICE=cpu` 让模型留在 CPU、只让 MalGraph 用 GPU）。

### 8.6 与 CPU 版的关系

`Dockerfile.smda`（CPU）与 `Dockerfile.smda.gpu`（GPU）的**引擎代码完全相同**，
只有 torch 轮子与哈希开关不同 ⇒ 两个版本产出的分数可直接比对。
