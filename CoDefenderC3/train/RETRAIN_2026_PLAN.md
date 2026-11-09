# CoDefenderC3 · 2026 数据重训计划

> 版本：v1（2026-11-09）　基线代码：`main` @ `840ffac`
> 基线数据：`test2_eval/eval_output/`（2026-11 快照，6160 有效样本）
> 适用目标：用 **2026 年新样本**重建训练集、重训受影响的子模型，使引擎在**时间外推**场景下的
> 低误报率指标恢复到可用水平，并使**训练侧与推理侧特征口径完全同源**。

---

## 0. 决策摘要（一页读完）

**总体结论**：重训是必要的，但**不能只做"换数据重训"**。当前 33 个模型里有 14 个的输入特征
在训练期与推理期**不是同一套语义**，直接用 2026 数据重训仍然会训出"对不上"的权重。必须先完成
§2 的 4 项前置改造，再进入数据与训练阶段。

**四条关键事实**

1. **哈希失效是全局性的，不是 opcode 专属**：`A06`（导入）、`C01/C04`（字符串）、`D01/D02/D03/D07`
   （opcode）都用 Python 内置 `hash()`，每进程随机 → 训练与推理分处不同进程 ⇒ 同一字符串落到不同桶。
   受影响的 9 个模型旧权重**全部作废**。
2. **换 SMDA 本身没有让引擎整体变差**：同批 2417 样本上，快通道集成 AUC 0.9124→**0.9350**
   （+0.0225，CI [+0.0168,+0.0287]），全 33 模型 0.9261→**0.9345**；代价集中在 D/E 族
   （0.7539→**0.5323**，−0.2215）。
3. **训练侧阻塞已于 2026-11-09 解除**：训练流水线默认后端已切到 SMDA
   （`train/data_loader.py` 新增 SMDA 分支 + `extract_feature.py::extract_de_smda_batch`），
   训练与推理现在共用同一套 `smda_extract` 与同一套稳定哈希。**BN 路径完整保留**，
   需要回退时设 `CODEFENDER_DISASM_BACKEND=bn`。
4. **"图模型"目前是扁平特征 MLP**：5 个图模型（CFGGAT/GCN/DGCNN/CallGraphGNN/GraphStatNet）在
   训练与推理两端都只吃 22 维统计向量，**从未接触真实图拓扑**。文献 [1] 指出：扁平特征模型
   在同分布内最强、跨时间边界最差——这与我们的观测完全一致，说明**图分支必须真正启用**，
   否则重训也补不回跨时间性能。

**建议节奏**（两轮，勿一次动太多）

| 轮次 | 内容 | 周期 | 目标 |
|---|---|---|---|
| **轮次 1** | 前置改造（§2）+ 特征库重建 + 14 个受影响模型重训 | 2~3 周 | 证明"口径统一能救回模型" |
| **轮次 2** | 数据切分/平衡/去重 + 图分支真正启用 + 权重拟合 + 校准 | 3~4 周 | 冲低 FPR 指标 |

---

## 1. 项目现状分析

### 1.1 训练链路全图

```
裸 PE 源目录
   │
   ├─① 构建数据集   train/build_minimal_dataset.py
   │     1:1 取样 → imphash 分组 → 整组分月(--months/--train-months)
   │     → 落盘(--link 硬链接) → 特征提取 → D/E 覆盖检查 → per_month → 四方校验
   │        └─ 特征提取: feature_extraction/extract_feature.py::extract_fast
   │                     + D/E: ext.extract_de_from_bndb_batch()  ← ⚠ 仍是 BN 路线
   │
   ├─② 训练         train/train_all.py  (--mode scratch|finetune, 逐模型 checkpoint + --resume)
   │     └─ models/ensemble.py::MultiModelEnsemble.fit(views, y)   权重 = ones(K)/K（等权）
   │        产物: CoDefenderC3/runs/<run_id>/ensemble.pkl（默认不碰生产模型）
   │
   ├─③ 门禁         train/verify_trained_ensemble.py --candidate ... --baseline ...
   │
   └─④ 上线（可选）  train_all.py --in-place → POST /reload-model 热加载（~5s，无需重启）
```

**辅助工具**（train/README.md §2）：`build_flat_dataset_meta.py`（只改分月/分组，不重提特征）、
`_probe_de_coverage.py` / `_fix_de_gap.py`（D/E 覆盖率诊断与修复）、`_probe_ensemble.py` /
`_cmp_ensemble.py`（pkl 拆解与数值指纹比对）、`_probe_device.py`（pkl 设备标签检查）。

### 1.2 关键参数（现成的能力，务必用上）

| 脚本 | 参数 | 意义 |
|---|---|---|
| build_minimal_dataset | `--months / --train-months` | 分月数与训练月数（当前惯例 10/7） |
| | 分组固定为 imphash | **按 imphash 分组整组分月**，避免同族跨 split 泄漏；`--group-key` 是 `build_flat_dataset_meta.py` 的参数（改切分时才用） |
| | `--mal-ratio` | 恶意/良性配比（默认 1:1） |
| | `--views full|fast` | full=15 视角（含 D/E，需 BN/SMDA）；fast=11 视角 |
| | `--exclude-sha256` | 跨数据集去重 |
| | `--link` | 同盘硬链接落盘（5000 规模省 ~25GB） |
| | `--allow-partial-de / --drop-per-sample` | D/E 缺失样本的两种处置（**慎用**，等于丢样本） |
| train_all | `--weighting equal\|auc` | **集成权重：等权 or 按 AUC 加权**（默认 equal ⇒ 9 个坏模型占 30% 权重） |
| | `--threshold-grid 0.3..0.8` | 判定阈值网格调优 |
| | `--models / --exclude` | 分批训练（如先只训 opcode 族） |
| | `--resume` | 断点续训（逐模型 checkpoint） |
| | `--mode finetune` | 微调（比 scratch 更省时，适合增量数据） |

### 1.3 33 个模型 × 视图 × 受影响面

| 视图 | 组成 | 模型 | 哈希失效 | SMDA 语义漂移 | 决策 |
|---|---|---|---|---|---|
| V1_byte | B01 | MalConv, MalConv2, ByteTransformer | — | — | **保留** |
| V2_byte_stat | B02-B05 | SaxeBerlinDNN, EmberDNN, NatarajKNN | — | — | **保留**（NatarajKNN 低 FPR 无效，另行处理） |
| V3_pe_struct | A01-A05 | PEMinerRF, DrebinSVM, DL4MD | — | — | **保留**（DrebinSVM/DL4MD 重训或下线） |
| V4_import | A06+A07+A08_A15 | DrebinImport, ALOHANet, EmberGBDT_Import | **是**（A06） | — | **必须重训** |
| V5_string | C01-C04 | RaffFeatureNet, DrebinString | **是**（C01/C04） | — | **必须重训** |
| V6_opcode_seq | D01 | OpcodeLSTM, OpcodeTransformer | **是**（100%） | — | **必须重训** |
| V6_opcode_stat | D02-D06 | OpcodeStatNet | **是**（512/549 维） | 部分（D05/D06） | **必须重训** |
| V6_func_embed | D07 | AsmEmbedNet | **是**（100%） | — | **必须重训** |
| V7_graph | E03+E04 | CFGGAT, CFGGCN, CFGDGCNN, CallGraphGNN, GraphStatNet | — | **是**（全部 22 维） | **必须重训**（且要真正用图） |
| V7_graph | 独立管线 | MalGraph | — | 轻微（ρ=0.80） | **保留 + 扩量** |
| V8_gray/color/markov/entropy | F01-F04 | GrayscaleCNN, InceptionV3, IMCFN, ColorCNN, MarkovCNN, EntropyMapCNN | — | — | InceptionV3/IMCFN **修或下线** |
| V9_hash | G01-G04 | HashEmbedNet | — | — | **保留** |
| V10_metadata | H01-H03 | MetadataNet, ResourceNet | — | — | 重训（当前无实用阈值） |

**合计必须重训 14 个**：DrebinImport, ALOHANet, EmberGBDT_Import, RaffFeatureNet, DrebinString,
OpcodeLSTM, OpcodeTransformer, OpcodeStatNet, AsmEmbedNet, CFGGAT, CFGGCN, CFGDGCNN,
CallGraphGNN, GraphStatNet。**可沿用旧权重 19 个**（含 PEMinerRF / MalConv2 / MalConv /
SaxeBerlinDNN / EmberDNN / HashEmbedNet / MalGraph 等）。

### 1.4 基线快照（2026-11，6160 样本，de 通道）

| 集成口径 | ROC-AUC | TPR@1e-2 | TPR@1e-3 | TPR@1e-4 | FPR@TPR95 | ECE |
|---|---:|---:|---:|---:|---:|---:|
| flat_mean（**引擎当前**） | 0.9571 | 0.5363 | 0.1036 | 0.0055 | 0.2184 | 0.2846 |
| family_weighted | **0.9595** | 0.5448 | 0.1424 | 0.0326 | **0.2028** | 0.2882 |
| 仅快通道 23 模型 | 0.9577 | 0.5738 | 0.1720 | 0.0189 | 0.2278 | 0.2715 |
| **Top5（低 FPR 优选）** | 0.9541 | 0.5816 | **0.3115** | **0.1176** | 0.2549 | 0.1783 |
| Top5（按 AUC 优选） | 0.9592 | 0.6109 | 0.2183 | 0.0186 | **0.2071** | 0.1122 |
| max_score（**不可用**） | 0.4995 | 0.0000 | 0.0000 | 0.0000 | 0.9977 | 0.5015 |

**重训验收线（建议）**：Top5 口径 TPR@1e-3 ≥ 0.3115（不低于当前最优），且 TPR@1e-4 ≥ 0.1176；
全集成 flat_mean 的 TPR@1e-3 ≥ 0.1720（剔除失效模型后应达到的水平）。

### 1.5 已解决 / 未解决清单

| # | 问题 | 状态 | 证据 |
|---|---|---|---|
| ✅ | 反汇编后端去商业授权依赖 | 已完成 | SMDA 后端，p50 6.28s vs BN 30~130s |
| ✅ | 维度推断截断导致 3 个模型不出分 | 已完成 | MalConv/InceptionV3/IMCFN 报错 3741→0 |
| ✅ | 内置 `hash()` → 确定性 crc32 | 已完成（main `f32caa3`） | 10 处调用点统一到 `feature_extraction/hashing.py` |
| ✅ | 推理期哈希维掩码开关 | 已完成 | `CODEFENDER_MASK_VIEWS`，OpcodeStatNet +0.042 |
| ✅ | 集成等权拖累 | 工具已具备 | `train_all.py --weighting auc` |
| ⚠️ | **训练侧 D/E 提取仍是 BN** | **未解决** | `data_loader.py:541/571` |
| ⚠️ | 后端默认值两条路径不一致 | 未解决 | `_disasm_backend()` 默认 smda vs `selected_backend()` 默认 bn |
| ⚠️ | 图模型从未使用图拓扑 | 未解决 | `forward(x, edge_index=None)` 恒走 MLP |
| ⚠️ | 良性集 83% 是 DLL ⇒ 恶意 DLL 检出被压 | 未解决 | dll64 0.404 / dll32 0.615 vs exe32 0.943 |
| ⚠️ | 加壳捷径学习 | 未解决 | packed 0.977 vs unpacked 0.797 |
| ⚠️ | 集成口径等于"等权平均" | 运行时未修 | `ensemble.py:131` 写死 `ones(K)/K` |

---

## 2. 重训前必须完成的前置改造（阻塞项）

### B1 · 训练侧 D/E 提取切到 SMDA（**最高优先级**）✅ 已完成 2026-11-09

- **证据**：`train/data_loader.py:541/571` 调用 `ext.extract_de_from_bndb_batch(have_bndb, [bndb路径], [npz路径], n_workers=...)`；
  该实现依赖 `.bndb` 缓存与 4 个长驻 worker 子进程（`_de_worker_persistent.py`）。
- **后果**：训练得到的是 BN 域特征、推理是 SMDA 域特征 ⇒ 重训后权重依旧对不上。
- **实际改法（路线 A 已落地）**
  - `feature_extraction/extract_feature.py`：新增 `append_to_npz()`（增量写盘）、进程池 worker
    （`_smda_worker_init` / `_smda_extract_one`）与 `extract_de_smda_batch()`
    ——**不生成 .bndb**，PE→D/E 一步到位，返回契约与 BN 路径一致（`(ok_set, fail_reasons)` + `on_ok` 回调）。
  - `train/data_loader.py`：`extract_features()` 增加后端分支，**默认 SMDA**；
    新增 `_extract_de_stage_smda()`，日志契约与 BN 路径一致
    （成功→`de_done`，硬失败→`de_fail`，超时→软失败留待重跑）。
  - `feature_extraction/smda_extract.py`：新增 `de_features_are_empty()` 守卫 ——
    SMDA 对解不出的文件会返回**全零**特征而不报错，守卫把它判为抽取失败并抛错，
    避免脏样本被当成有效样本写进数据集（worker 侧双保险）。
  - 路线 B（ProgramIR）仍是更彻底的方案，见 `test_lm` 分支，本轮未采用。
- **验收**：① 同一批 PE，SMDA 路径与 BN 路径的 D/E 特征**逐位一致或差异可解释**；
  ② 同一批样本连抽两次，npz **逐位相同**（跨进程验证 hash 稳定性）。

### B2 · 哈希编码在训练侧同样生效（已修复，需确认落地）

- `feature_extraction/hashing.py::stable_bucket` 已在 main；`extract_feature.py` 10 处已替换。
- **待确认**：训练侧 worker 进程是否也走同一实现（worker 只把 `feature_extraction/` 放进 sys.path，
  已加 `sys.path` 回退与 `from hashing import stable_bucket` 兜底）。
- **兜底**：worker 启动时设 `PYTHONHASHSEED=0`（防止将来新增特征又用回 `hash()`）。

### B3 · 图模型真正使用图拓扑（决定图族能否跨时间）

- **证据**：`CFGGAT.forward(x, edge_index=None)` 只有 `edge_index is not None` 才走 GAT；
  引擎唯一构造 PyG 图的位置（`engine/app.py:544~565`）是**给 MalGraph 用的**；
  训练侧 `MultiModelEnsemble.fit` 用 `views[vname]`（22 维矩阵）⇒ **训练与推理两端都是扁平 MLP**。
- **文献支撑** [1]：在严格时间切分下，"只看节点特征、不看拓扑"的扁平模型**同分布内最好、跨时间边界最差**；
  且**重新校准与集成都不能替代算子（架构）选择**。⇒ 只做校准/重训 MLP 救不回图族。
- **改法**：训练侧为每个样本落一份 CFG/FCG 图（节点特征 + 边），推理侧把 `edge_index` 传给这 5 个模型；
  节点特征维度固定（当前 `node_dim=11`），并把 E01/E02 补齐为图结构来源。
- **代价**：特征库体积与抽取时间显著上升（需先做小样本试跑测吞吐）。
- **备选（低风险）**：接受"图族 = 22 维 MLP"，在文档中如实标注其能力边界，把资源投到
  MalGraph（跨后端稳定，ρ=0.80）与 D04/D05/D06 统计增强上。

### B4 · 集成权重与阈值在运行时可配

- 训练侧已有 `--weighting auc` / `--threshold-grid`，但**引擎运行时仍按 `ensemble.py:131` 的等权**执行。
- **改法**：引擎读取 pkl 里的 `weights`（已存在）并支持运行时排除清单（`CODEFENDER_EXCLUDE_MODELS`），
  线上可按 filetype 或开关切换口径。

---

## 3. 2026 数据方案

### 3.1 数据来源与现状

| 数据 | 位置 | 规模 | 备注 |
|---|---|---|---|
| 恶意样本 | `malware.csv`（VT_KAV 来源，字段含 platform/family/packer/filetype/date） | 95,650 条索引 | 评测用到 3,069 恶意 |
| 良性样本 | `benign.csv`（软件名/路径/filetype/platform=windows） | 40,000 条索引 | 评测用到 3,091 良性 |
| 样本实体 | 测评服务器 `/home/zeh/{malware,benign}/samples` | — | sha256→路径索引 `sample_index.json` |

**当前评测集的已知偏差**（重训必须纠正）：
- 良性 100% `platform=windows`，且 **83% 是 DLL**（dll32 1406 + dll64 975 / 2865）⇒ 模型学到"DLL→高分"先验；
- 恶意侧 **dll32 仅 182、dll64 仅 230**（占 13%）⇒ 恶意 DLL 检出被压到 0.615 / 0.404；
- 加壳样本检出 0.977 vs 未加壳 0.797 ⇒ **加壳特征捷径**。

### 3.2 时间外推切分（out-of-time）

- **现状**：`build_minimal_dataset.py::assign_months_grouped` 是"按 (label, group) 分组后随机分配月份"
  （组内不跨月，避免同族泄漏），**不是按时间线切**。`--group-key imphash` 默认按 imphash 分组。
- **建议**（与文献 [1] 一致）：
  - **训练**：≤ 2025-12 的样本（可含 2026 之前的历史月份分组）；
  - **验证**：2026-01 ~ 2026-06；
  - **测试**：≥ 2026-07（**只评一次**，不允许反复调参）；
  - 同 imphash 组**不跨 split**（沿用现有分组能力）；
  - 切分结果用 `build_flat_dataset_meta.py` 落地，**不重新抽特征**（省一次全量抽取）。
- **必须做**：与现有"随机月份"切分的**同批对照**，否则新旧指标不可比。

### 3.3 类别平衡与良性构成

- 良性集按 `filetype` 分层抽样，使良性 filetype 分布贴近真实用户环境（**不要**照抄当前 83% DLL）；
- 恶意集按 filetype 补足 DLL（至少与良性侧 DLL 占比同量级），并单列 `dll32/dll64` 配额；
- 建议配比：恶意 : 良性 = 1:1（`--mal-ratio 1.0`），DLL 子集另做 1:1 的**专项评测集**，
  单独报指标（避免总体指标掩盖 DLL 短板）。

### 3.4 去重与污染控制（三边）

1. **训练 ↔ 测试**：2026 测试集 sha256 从训练集剔除（`--exclude-sha256`）。
2. **训练 ↔ 签名库**：训练样本若已在签名库中，线上会被短路命中 ⇒ 训练它没有意义，且会高估收益。
3. **样本内重复**：同族/同 imphash 组整体保留或整体剔除，不拆散（沿用 `--group-key imphash`）。
   文献 [2] 给出大规模去重 + 家族过滤的参考做法（83,633 去重矩阵 / 49,204 家族过滤样本）。

### 3.5 数据验收清单

- [ ] 各 split 的样本数、filetype 分布、packer 分布、平台分布表
- [ ] 训练/测试 sha256 交集 = 0；imphash 组交集 = 0
- [ ] D/E 特征覆盖率 100%（`_probe_de_coverage.py` 无缺口；缺口按 `bndb_slow/fail` 分类处理）
- [ ] 二次抽样逐位一致（跨进程）校验通过
- [ ] 特征库体积与抽取耗时统计（用于排期）

---

## 4. 特征口径方案

| 维度 | 决定 | 理由 |
|---|---|---|
| 反汇编后端 | **统一 SMDA**（训练与推理同一后端） | 消除语义漂移；p50 6.28s，重建成本比 BN 低一个数量级 |
| 特征编码 | **crc32 稳定哈希**（已完成） | 跨进程一致；旧权重作废属预期 |
| 中间表示 | **建议 ProgramIR**（路线 B） | 后端可换 + 缓存中立 + 逐位可回归；能一次性消除"训练/推理不同源"这一类问题 |
| 掩码开关 | 训练侧与推理侧**必须同开同关** | 训练掩而推理不掩（或反之）= 新的口径错配 |
| 图结构 | 启用真实图（B3） | 文献 [1]：扁平特征模型跨时间最差 |
| 视觉/元数据/字节 | 不动 | 与后端无关，口径已稳定 |

**关键提醒**：D/E 特征必须由**同一个进程模型**产出（训练 worker 与推理 worker 用同一份代码与同一套
稳定哈希），否则 §2-B1 的改造等于没做。

---

## 5. 模型清单决策与优先级

| 优先级 | 模型 | 动作 | 依据 | 目标区间 |
|---|---|---|---|---|
| P0 | OpcodeStatNet | 重训 | 树分裂 76.7% 落在 D05/D06，SMDA 语义漂移致其低于随机；掩码实验已验证 +0.042 | AUC ≥ 0.80（BN 时代 0.8676） |
| P0 | OpcodeLSTM / OpcodeTransformer / AsmEmbedNet | 重训 | 输入 100% 为哈希维，**从未有效**（BN 侧 CI 覆盖 0.5） | AUC ≥ 0.70 |
| P1 | CallGraphGNN / GraphStatNet / CFGGCN / CFGDGCNN / CFGGAT | 重训（+ 启用真图） | 纯 22 维漂移；BN 时代 0.63~0.73；文献 [1] 警示扁平模型跨时间最差 | 恢复 BN 水平并越过 |
| P1 | ALOHANet / RaffFeatureNet / EmberGBDT_Import / DrebinString / DrebinImport | 重训 | 哈希维依赖 55%~81%，旧权重作废 | ≥ 当前 + 0.05 |
| P2 | MalGraph | 保留 + 扩量 | 跨后端稳定（ρ=0.80，BN↔SMDA 差异不显著 P=21.7%） | AUC ≥ 0.65 |
| P2 | InceptionV3 / IMCFN | 修复或下线 | AUC 0.2915（低于随机）/ 0.6062（std 0.010 近常数） | 下线或 ≥ 0.75 |
| P2 | DL4MD / DrebinSVM | 重训 | 0.4982（近随机）/ 0.5469 | ≥ 0.80 / ≥ 0.70 |
| P3 | MetadataNet / ResourceNet | 重训 + 阈值重定位 | 当前无可用阈值（TPR@0.5=0.0003、FPR@TPR95=1.0） | 有可用工作点 |
| P3 | NatarajKNN / GrayscaleCNN | 分数重标定 | AUC 尚可但 TPR@1e-2 近 0，属阈值分布问题 | TPR@1e-2 ≥ 0.05 |
| — | PEMinerRF / MalConv2 / MalConv / SaxeBerlinDNN / EmberDNN / ByteTransformer / EmberGBDT_Import / MarkovCNN / ColorCNN / EntropyMapCNN / HashEmbedNet / DrebinImport / RaffFeatureNet | 沿用旧权重（或微调） | 特征口径未变 | 保持当前指标 |

**训练顺序建议**：先 P0（4 个）验证"口径统一 ⇒ 模型能救回"这一核心假设，再批量推进；
`--models` / `--exclude` 支持分批，`--resume` 支持断点续训。



---

## 6. 训练、集成与校准

### 6.1 训练流程

```bash
# 分批训练：先 P0 四个 opcode 族验证假设，再铺开
python -u CoDefenderC3/train/train_all.py \
    --dataset "<数据集目录>" --run-id run-2026 --mode scratch --epochs 20 \
    --models OpcodeStatNet,OpcodeLSTM,OpcodeTransformer,AsmEmbedNet \
    --resume                      # 中断后重跑同一命令即续训

# 其余批次
python -u CoDefenderC3/train/train_all.py --dataset "<数据集目录>" \
    --run-id run-2026 --mode scratch --epochs 20 \
    --models ALOHANet,RaffFeatureNet,EmberGBDT_Import,DrebinString,DrebinImport \
    --resume
python -u CoDefenderC3/train/train_all.py --dataset "<数据集目录>" \
    --run-id run-2026 --mode scratch --epochs 20 \
    --models CFGGAT,CFGGCN,CFGDGCNN,CallGraphGNN,GraphStatNet --resume

# 微调（数据量小、想省时时）：--mode finetune --lr 1e-4
```

- **产物**：`CoDefenderC3/runs/run-2026/ensemble.pkl`（默认**不碰**生产 `ensemble.pkl`）+ 逐模型 checkpoint。
- **增量数据**：优先 `--mode finetune`（老模型已学到的通用模式不必重学），但**受哈希变更影响的 14 个模型只能 scratch**
  （输入语义已变，微调会在错位特征上继续偏）。

### 6.2 集成权重与判定阈值

- **权重**：`--weighting auc` 让权重按各模型在验证集上的 AUC 分配，替代等权 1/33。
  这直接针对"9~10 个失效模型占 27~30% 权重"的实测问题（剔除 D/E 后 TPR@1e-3 0.1036→0.1720）。
  **注意**：AUC 加权仍会把低区分度模型留在集成里，建议叠加"权重下限 + 排除清单"（引擎侧支持，见 §2-B4）。
- **阈值**：`--threshold-grid 0.3,0.4,0.5,0.6,0.7,0.8` 在验证集上选工作点。
  **判定目标函数不要用 AUC**（PRISM 论文 [2] 指出二分类任务已饱和，差异集中在**极低 FPR 区间**），
  建议用 `TPR@FPR≤1e-3` 或 `FPR@TPR95` 选阈值。

### 6.3 概率校准

- 每个模型输出做 **Platt scaling**（二分类）/ 等距回归，落到概率语义；
- 集成后再做一次校准（当前集成 ECE 0.2846，远差于单模型最好 0.0208 —— 均值聚合破坏了概率语义）；
- 校准必须在**验证集**上拟合，**测试集只评一次**；
- 文献 [1] 提醒：校准**不能替代**架构选择（图族仍须真正用图）。

### 6.4 上线

```bash
cp CoDefenderC3/ensemble.pkl CoDefenderC3/ensemble.pkl.bak-2026xxxx   # 先备份
cp CoDefenderC3/runs/run-2026/ensemble.pkl CoDefenderC3/ensemble.pkl
curl -X POST http://127.0.0.1:8000/reload-model        # 热加载，~5s，无需重启容器
```

镜像侧保留两个 tag 不覆盖：`codefender-c3:gpu-train`（哈希关，训练/测评）与
`codefender-c3:gpu-serve`（哈希开，上线）。

---

## 7. 评测与门禁

### 7.1 评测口径固化（复用现成 harness）

`test2_eval/` 已实现并固化：低 FPR 指标（TPR@FPR∈{1e-1,1e-2,1e-3,1e-4}）、FPR@TPR95、ECE、
退化检测、逐模型/分族/分 filetype 亚组、**fast/de 通道一致性检查**。重训前后用同一套脚本跑，
表格可直接并排对比。

```bash
python3 test2_eval/run_eval.py --mode de --workers 8 --timeout 900 --limit 3000 \
        --out eval_output/scores_de_2026.jsonl
python3 test2_eval/report.py
python3 test2_eval/backend_swap_impact.py --bn <旧基线> --smda <新基线>   # 同批样本对比
python3 test2_eval/make_final_report_charts.py                              # 出图
```

### 7.2 门禁清单（任一不过则不发布）

| # | 门禁 | 工具 | 通过标准 |
|---|---|---|---|
| G1 | **特征口径一致** | 自检脚本（新增） | 同批样本跨进程两次抽取 npz **逐位相同** |
| G2 | **训练/推理同源** | B1 验收 | 训练侧产出的 D/E 与推理侧产出的 D/E 逐位一致（或差异可解释且已文档化） |
| G3 | D/E 覆盖率 | `_probe_de_coverage.py` / `_fix_de_gap.py` | 缺口为 0；`bndb_slow/fail` 日志清零 |
| G4 | 产物结构 | `verify_trained_ensemble.py` | K=33 / V=15 结构一致，数值指纹差异可解释 |
| G5 | 设备标签 | `_probe_device.py` | 全部 `cpu`（或按部署目标统一），不得混用 |
| G6 | 通道一致性 | `test2_eval/report.py` | fast/de 同名模型逐位一致（0 分歧） |
| G7 | 集成口径 | 评测表 | `max_score` 变体不得启用；全集成不得低于"仅快通道"口径 |
| G8 | 主指标 | 评测表 | Top5 口径 TPR@1e-3 ≥ **0.3115** 且 TPR@1e-4 ≥ **0.1176**；分层（filetype/packer/platform）不得低于基线 |
| G9 | 集成权重 | 评测表 | 采用 `--weighting auc` 或人工审定的权重表；记录每次口径变更 |
| G10 | 发布原子性 | 流程 | **哈希变更的 5 个模型必须与重训同批发布**，不允许"先改编码后补模型" |

### 7.3 指标与验收

| 层级 | 指标 | 验收线 |
|---|---|---|
| 单模型（14 个重训） | ROC-AUC / TPR@1e-3 / TPR@1e-4 / ECE | 相对各自当前值有实质提升；ECE ≤ 0.10 |
| 集成 | TPR@1e-3 / TPR@1e-4 / FPR@TPR95 | Top5 口径 ≥ 0.3115 / ≥ 0.1176 / ≤ 0.2549 |
| 泛化 | 2026 时间外推测试集 | 与 2025 测试集**同时**报，指明退化幅度（文献 [1] 的核心指标） |
| 分层 | filetype / packer / platform | DLL 子集单列；packed 与 unpacked 分别报 |
| 工程 | 单样本耗时 / 产出率 / 峰值显存 | 不劣于基线（分析 p50 ≤ 6.3s、产出率 ≥ 99%） |

---

## 8. 里程碑、工期与算力

### 8.1 里程碑（2 人主力，约 5~6 周）

| 阶段 | 任务 | 依赖 | 工时 | 产出 | 验收 |
|---|---|---|---|---|---|
| **W1** | B1 训练侧 SMDA 路径（或 IR 路线 PoC）；B2 编码确认；G1/G2 门禁脚本 | — | 4~5 人日 | 训练侧能产出与推理同源的 D/E | G1+G2 通过 |
| **W2** | 2026 数据集：out-of-time 切分、类别平衡、三边去重、特征库重建 | W1 | 3 人日 + 机器 1~2 天 | 数据集 + 分布表 | §3.5 清单全绿 |
| **W3** | P0 四模型（opcode 族）scratch 重训 + 对比基线 | W2 | 2 人日 | run-2026 pkl | 单模型 AUC 达标，G8 部分 |
| **W4** | P1 九模型（导入/字符串/图族）重训；图分支启用决策落地 | W3 | 4 人日 | 同上 | 同上 |
| **W5** | 权重拟合、阈值网格、概率校准、集成口径定稿 | W4 | 3 人日 | 权重表 + 校准器 | G7/G8/G9 通过 |
| **W6** | 全量评测、报告与图表、门禁复核、上线与冒烟 | W5 | 3 人日 | 评测报告 + 发布 | G10 + 热加载验证 |

### 8.2 算力与吞吐估算

| 环节 | 依据 | 估算 |
|---|---|---|
| 特征抽取（SMDA） | 实测 p50 6.28s / mean 31.1s / p90 41.5s | 6 万样本、16 并发 ≈ **13~32 小时**（均值口径），8 并发翻倍 |
| 图抽取（若启用真图） | 与特征抽取同源，额外构图开销未实测 | 先用 500 样本试跑标定，再排期 |
| 训练（14 个模型） | torch CPU/GPU；大模型（MalConv/ByteTransformer）单模型分钟级 | 2×3090 上 **< 1 天**（不含图分支） |
| 评测 | 实测 de 通道 6160 样本 8 并发 ≈ 7.8 h | 每轮评测 ~8 小时（可复用特征缓存则更快） |
| 存储 | `--link` 硬链接；npz 含 D/E + 图后体积上升 | 先用 500 样本标定 GB/样本，再乘总量 |

### 8.3 人力分工建议

- **A（引擎/后端）**：B1 后端统一、B3 图分支、引擎权重/排除能力、镜像与上线。
- **B（数据/训练）**：切分与平衡、去重、特征库重建、训练编排、权重与校准。
- **C（评测/门禁）**：harness 口径、G1/G2/G6 门禁脚本、报告与对照分析。

---

## 9. 风险与回滚

### 9.1 风险表

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| **哈希重排后旧权重失效被误上线** | 高 | 5 个模型分数掉到随机 | G10 原子发布；生产 pkl 备份 + `reload-model` 秒级回滚 |
| 训练/推理仍不同源 | 中 | **整轮重训作废** | G1/G2 门禁前置到 W1，先跑通再动数据 |
| 图分支启用后不收敛/显存超 | 中 | 图族重训延期 | 500 样本试跑标定；保留"22 维 MLP"备选并在文档标注能力边界 |
| 2026 数据量/分布不足 | 中 | 指标不可比 | 同时保留 2025 测试集作第二测试集；分层报告 |
| 集成权重改动引入回归 | 中 | 集成指标下降 | 权重在验证集拟合；保留 flat_mean 作对照；权重表入库可回溯 |
| 特征库体积/耗时超预期 | 中 | 排期延长 | `--link` 省盘；测评服务器直接跑批处理；分批重建 |
| 训练样本已在签名库中 | 中 | 高估收益 | 三边去重（§3.4） |
| 数据切分改动导致新旧不可比 | 中 | 无法判断提升 | 保留"随机月份"切分做同批对照 |

### 9.2 回滚

| 层级 | 回滚方式 | 耗时 |
|---|---|---|
| 模型权重 | `runs/<id>/` 天然版本化；换回旧 `ensemble.pkl` + `POST /reload-model` | ~5 s |
| 集成口径 | pkl 内 `weights` 可改；引擎加运行时排除清单 | 秒级 |
| 特征编码 | 旧编码不可复现（旧权重已废）⇒ **不可回滚到旧编码**，只能整体回滚到旧 pkl + 旧镜像 | 一次部署 |
| 镜像 | 保留 `gpu-train` / `gpu-serve` 两个 tag 不覆盖；必要时 `docker run` 旧 tag | 分钟级 |

---

## 10. 附录

### A. 端到端命令清单

```bash
# 0) 环境自检：后端 + 编码
export CODEFENDER_DISASM_BACKEND=smda
python -c "from feature_extraction.hashing import stable_bucket; print(stable_bucket('CreateFileA',256))"
python -c "import sys; sys.path.insert(0,'CoDefenderC3'); import engine.app; print('engine OK')"

# 1) 构建数据集（先 dry-run 预演）
python -u CoDefenderC3/train/build_minimal_dataset.py \
    --source "<2026 PE 源目录>" --out "<数据集目录>" \
    --per-class 0 --months 12 --train-months 8 --views full --link \
    --exclude-sha256 "<测试集 sha 列表>" --dry-run
#   正式跑：去掉 --dry-run

# 2) 只改切分/分组（复用已有特征，不重抽）
python -u CoDefenderC3/train/build_flat_dataset_meta.py \
    --data-dir "<数据集目录>" --months 12 --train-months 8 --group-key imphash --dry-run

# 3) D/E 覆盖率门禁
python -u CoDefenderC3/train/_probe_de_coverage.py "<数据集目录>"
python -u CoDefenderC3/train/_fix_de_gap.py "<数据集目录>" --dry-run
python -u CoDefenderC3/train/_fix_de_gap.py "<数据集目录>"

# 4) 训练（分批 + 续训）
python -u CoDefenderC3/train/train_all.py --dataset "<数据集目录>" \
    --run-id run-2026 --mode scratch --epochs 20 --weighting auc \
    --threshold-grid 0.3,0.4,0.5,0.6,0.7,0.8 \
    --models OpcodeStatNet,OpcodeLSTM,OpcodeTransformer,AsmEmbedNet --resume

# 5) 门禁
python -u CoDefenderC3/train/verify_trained_ensemble.py \
    --candidate CoDefenderC3/runs/run-2026/ensemble.pkl --baseline CoDefenderC3/ensemble.pkl
python -u CoDefenderC3/train/_probe_device.py CoDefenderC3/runs/run-2026/ensemble.pkl

# 6) 评测（test2_eval）
python3 test2_eval/run_eval.py --mode de --workers 8 --timeout 900 --limit 3000 \
        --out eval_output/scores_de_2026.jsonl
python3 test2_eval/report.py
python3 test2_eval/backend_swap_impact.py --bn <旧> --smda <新>

# 7) 发布（先备份，再热加载）
cp CoDefenderC3/ensemble.pkl CoDefenderC3/ensemble.pkl.bak-$(date +%Y%m%d)
cp CoDefenderC3/runs/run-2026/ensemble.pkl CoDefenderC3/ensemble.pkl
curl -X POST http://127.0.0.1:8000/reload-model
```

### B. 代码改动清单（重训需要落到代码的改动）

| 文件 | 改动 | 优先级 | 状态 |
|---|---|---|---|
| `CoDefenderC3/train/data_loader.py` | D/E 提取改 SMDA（新增分支，BN 路径保留） | P0 | **已完成** |
| `CoDefenderC3/feature_extraction/extract_feature.py` | 新增 `extract_de_smda_batch()` + 进程池 worker + `append_to_npz()` | P0 | **已完成** |
| `CoDefenderC3/feature_extraction/smda_extract.py` | 新增 `de_features_are_empty()` 空特征守卫 | P0 | **已完成** |
| `CoDefenderC3/train/_de_worker_persistent.py` | 启动设 `PYTHONHASHSEED=0` 兜底 | P1 | 待做 |
| `CoDefenderC3/train/build_minimal_dataset.py` | 支持**时间线切分**（现仅随机月份） | P1 | 待做 |
| `CoDefenderC3/feature_extraction/extract_feature.py` | `_disasm_backend()` 默认值与 `selected_backend()` 统一 | P1 | 待做 |
| `CoDefenderC3/engine/analysis_worker.py` | 同上 | P1 | 待做 |
| `CoDefenderC3/models/ensemble.py` | 运行时支持 per-model 权重/排除 | P1 | 待做 |
| `CoDefenderC3/engine/app.py` | 图模型接 PyG 图（若启用真图）；掩码与训练侧对齐 | P1/P2 | 待做 |
| `CoDefenderC3/train/train_all.py` | 阈值/权重选择目标改为低 FPR 指标 | P2 | 待做 |
| `CoDefenderC3/feature_extraction/hashing.py` | 确定性哈希公共实现 | — | **已完成** |
| `CoDefenderC3/engine/view_masking.py` | 推理期哈希维掩码 | — | **已完成** |

### C. 参考文献

**外部（arXiv，2025–2026）**

1. *Temporal Generalization and Explanation Stability of Control Flow Graph Neural Networks for Malware Detection.* arXiv:2609.24280 (2026-09-21) — 严格时间切分（459 图训练 / 223 图 2026 评测）；**扁平特征模型同分布内最好、跨时间边界最差**；重新校准与集成都不能替代架构（消息传递算子）选择。
2. *PRISM: PE Relational Inter-Section Matrix. A 2D Section-Aware Dataset for Static PE Malware Detection.* arXiv:2606.27109 (2026-06-25) — EMBER/BODMAS/SOREL-20M 均为扁平特征；83,633 去重样本 / 49,204 家族过滤样本；**二分类任务已饱和**，差异集中在极低 FPR 区间。
3. *Delphi Scanner: efficient and interpretable static malware detection via API sequence modeling.* arXiv:2609.19900 (2026-09-17) — API 序列 CNN；19 万 PE；OOD（MalwareBazaar 5,647）+ 加壳配对 + 三类对抗操纵的鲁棒性评测范式。
4. *Machine Learning Transferability for Malware Detection.* arXiv:2603.26632 (2026-03-27)
5. *Building an Adversarial Malware Dataset by Family and Type.* arXiv:2605.25937 (2026-05-25)
6. *Packed Malware Detection Using Grayscale Binary-to-Image Representations.* arXiv:2512.15414 (2025-12-17)
7. *A Research and Development Portfolio of GNN Centric Malware Detection, Explainability, and Dataset Curation.* arXiv:2511.20801 (2025-11-25)
8. *APT-ClaritySet: A Large-Scale, High-Fidelity Labeled Dataset for APT Malware with Alias Normalization and Graph-Based Deduplication.* arXiv:2512.15039 (2025-12-17)
9. *MalTree: Tracing Malware Evolution from Embeddings at Scale.* arXiv:2606.06570 (2026-06-02)
10. *Bytes to Threats: Byte-Sequence Transformer For Malware Detection.* arXiv:2610.18787 (2026-10-13)
11. *Can We Leverage Predictive Uncertainty to Detect Dataset Shift and Adversarial Examples in Android Malware Detection?* arXiv:2109.09654 (2021)

**本地论文库**：`CoDefenderC3/papers/`（29 篇原始模型论文：EMBER、ByteTransformer、MalConv/MalConv2、
SaxeBerlinDNN、DL4MD、DREBIN、PEMiner、ALOHANet、EmberGBDT、RaffFeatureNet、Asm2Vec、
OpcodeLSTM/StatNet/Transformer、CFG-GCN/GAT/DGCNN、CallGraph-GNN、EntropyMapCNN、IMCFN、
InceptionV3、MarkovCNN、NatarajKNN 等）+ `papers/PAPERS.md`

**项目内文档**：`CoDefenderC3/train/README.md`（哈希稳定性与"必须重训"清单）、
`test_lm` 分支的 `docs/IR_CONTRACT.md` / `docs/FEATURE_HASH_STABILITY.md`、
`test2_eval/eval_output/最终模型详细评估报告.md`（本报告的基线数据来源）。

### D. 基线快照与复现

| 内容 | 位置 |
|---|---|
| 逐样本分数（6160 样本 × 33 模型） | `test2_eval/eval_output/scores_de.jsonl`、`scores_fast.jsonl` |
| BN 时代同批样本（2417 条干净记录） | `test2_eval/eval_output/scores_de_bn_clean.jsonl` |
| 逐模型指标 / 集成变体 / 亚组 | `summary.json`、`summary.csv`、`subgroups.json`、`stage_stats.json` |
| 报告与图表 | `最终模型详细评估报告.md`、`BN_vs_SMDA配对分析.md`、`charts/*.png`（11 张） |
| 复现命令 | `python test2_eval/report.py` → `python test2_eval/make_final_report_charts.py` |
| BN↔SMDA 同批对比 | `python test2_eval/backend_swap_impact.py --bn <bn_clean> --smda <de>` |
| 哈希依赖度审计 | `python test2_eval/weight_side_audit.py --pkl CoDefenderC3/ensemble.pkl` |

> 本报告引用的全部数字均来自上述快照（2026-11 采集，SMDA 修复版镜像 `0c69a360`），
> 重训完成后应能用同一套脚本复算并与本报告 §1.4 的基线表逐行对比。
