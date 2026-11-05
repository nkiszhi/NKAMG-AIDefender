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
