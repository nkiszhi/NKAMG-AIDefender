# SMDA 反汇编后端（替代 BinaryNinja）

- 目的：用 SMDA（https://github.com/danielplohmann/smda）替代 BinaryNinja 承担 D/E 特征与
  MalGraph CFG 提取，解决三个问题：**不需要商业授权**、**不会在畸形样本上挂死**、**快 5~10 倍**。
- 状态：2026-10-19 实现并实测通过（容器路径 `python -m engine.analysis_worker`）。

---

## 1. 开关

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `CODEFENDER_DISASM_BACKEND` | `smda` | `smda` / `bn`（BinaryNinja 旧路径保留） |
| `CODEFENDER_SMDA_TIMEOUT` | `120` | 单样本 SMDA 分析墙钟预算（秒） |
| `CODEFENDER_SMDA_API_NAME_STYLE` | `short` | `short` 去掉导入名的 `dll!` 前缀（复用现有 MalGraph 词表）；`raw` 保留原名 |
| `CODEFENDER_ANALYSIS_TIMEOUT_MAX` | `3600` | BN 分析超时上限（原代码硬编码 600，已放开） |

## 2. 改动清单

| 文件 | 改动 |
|---|---|
| `feature_extraction/smda_extract.py` | **新增**：SMDA 后端，产出 D01–D07 / E03 / E04 与 MalGraph 同构的 CFG/FCG |
| `insn_categories.py` | **新增**：x86 指令类别表（15 类），BN 与 SMDA 共用 |
| `feature_extraction/extract_feature.py` | `extract_de_only` 按后端开关分发；类别表改为共用顶层模块；BN 导入保持惰性 |
| `models/MalGraph_2022/utils.py` | `extract_cfg_and_fcg` 按后端开关分发；BN 导入改为**可选**（无 BN 环境也能导入） |
| `engine/analysis_worker.py` | 新增 SMDA 分支（一次分析同时产出 D/E 与 MalGraph），BN 分支保留 |
| `engine/staged_scan.py` | `analysis_timeout()` 上限由硬编码 600 改为 `CODEFENDER_ANALYSIS_TIMEOUT_MAX`（默认 3600） |
| `requirements.txt` | 增加 `smda>=4.3.10` |

## 3. 实测（ida_env smda 5.0.1 / torch-cpu smda 4.3.10，两版 API 兼容）

| 样本 | SMDA 耗时 | BN 耗时（对照） | SMDA 产出 |
|---|---:|---:|---|
| notepad.exe (360 KB) | 1.2–3.7 s | 30–130 s | 522 函数 / 6,515 块 / 37,750 指令 |
| cmd.exe (340 KB) | 18–22 s | 30–130 s | 831 函数 |
| kernel32.dll (862 KB) | 5.8–19 s | 30–130 s | 2,638 函数 |

特征维度与 BN 版**逐位对齐**：D01 4096 / D02–D03 256 / D04 15 / D05 12 / D06 10 / D07 6144 /
E03 12 / E04 10；MalGraph 输入的 `block_features` 全部 11 维、`function_edges`、`acfg_list`、
`function_names`（本地名规范化为 `sub_<addr>`）结构一致。

## 4. 与 BN 版的有意差异（需要配套重训）

1. **哈希改为稳定 crc32**：BN 版 D01/D02/D03/D07 用进程随机的 `hash()`，每次进程结果都不同；
   SMDA 版改用 `zlib.crc32`（稳定、可复现）。→ **依赖这些特征的模型（Opcode\*、AsmEmbedNet）必须重训**。
2. **导入名格式**：SMDA 为 `dll.dll!Func`，BN 多为 `Func`；默认去掉前缀以**复用现有 MalGraph 词表**，
   需要原名时设 `CODEFENDER_SMDA_API_NAME_STYLE=raw`。
3. **MalGraph 词表**：若历史上是用 BN 建的词表，前缀规范化后一般可直接复用；否则需重建并重训 MalGraph。

## 5. 镜像部署

```dockerfile
# 在 CoDefenderC3/Dockerfile 的 pip 段加入
RUN pip install --no-cache-dir smda>=4.3.10
```

启动时指定后端（默认值已是 smda，显式写更清楚）：

```bash
docker run -d --name codefender -p 8000:8000 \
  -e CODEFENDER_DISASM_BACKEND=smda \
  -e CODEFENDER_ANALYSIS_TIMEOUT=240 \
  -e CODEFENDER_REQUEST_TIMEOUT=600 \
  -e CODEFENDER_HARD_TIMEOUT=660 \
  -e CODEFENDER_MAX_CONCURRENT=8 \
  codefender-c3:v8.1
```

> 不需要再安装/授权 BinaryNinja；镜像里保留 BN 代码只是留了回退路径（`CODEFENDER_DISASM_BACKEND=bn`）。

## 6. 验收

```bash
# 容器内单样本自检
docker exec codefender python -m engine.analysis_worker /path/sample.exe /tmp/out.pkl
python3 - <<'EOF'
import pickle
r = pickle.load(open('/tmp/out.pkl','rb'))
print(sorted(r['features']), r['errors'], r['timing'])
print(r['malgraph'] and (r['malgraph']['function_number'], len(r['malgraph']['acfg_list'])))
EOF
```

## 7. hash() 随机性与 hash 优化

### 7.1 问题

D01/D02/D03/D07 的序列 id 与 n-gram 分桶由 Python 内置 `hash()` 生成，而 `str.__hash__`
**每进程随机**（镜像与 supervisor 配置均未设置 `PYTHONHASHSEED`）。训练期的 D/E 特征由多个
独立子进程（`feature_extraction/_de_worker_persistent.py`）提取 ⇒ 训练集本身就是多套随机
映射的混合，推理端无论用哪种确定性映射都无法与之对齐。

### 7.2 SMDA 后端的处理

`feature_extraction/smda_extract.py` 用 `zlib.crc32` 替代 `hash()`（`_stable_bucket`），
使 D02/D03/D07 的分桶在进程间稳定。注意：**这只保证"同一份代码每次运行一致"**，
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
