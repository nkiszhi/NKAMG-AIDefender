# CoDefenderC3 · 2026 前五个月数据重训计划（v2 · 数据驱动）

> 版本：v2（2026-11-12）　基线代码：`main` @ `12c4b6a`（本地另有未推送提交 `d134553`）
> 数据来源：`retrain/malicious_pe_2026_{01..05}.csv` + `retrain/benign.csv`（**良性沿用上一版，4 万条不变**）
> 证据：`CoDefenderC3/docs/test-records/retrain_manifest_stats.json`、`retrain_split_plan_2026-11-12.json`
> 基线测评：`test2_eval/eval_output/最终模型详细评估报告.md`（6160 有效样本，SMDA 后端）

> **本文件是计划，不是已完成的训练/验收报告。** 所有"预期收益"均为基于同类模型与实测基线的推断，必须以本轮重训后的实测结果为准。历史实验数字、已被合并取代的分支路线和不存在的评测 CLI，均不作为当前操作指南。

---

## 0. 决策摘要（一页读完）

**核心结论：本轮重训的最大风险不是模型能力，而是数据可分性（shortcut）。** 实测表明，
**仅用 `filetype` + 文件大小两个元数据字段，逻辑回归就能在 2026 新数据上达到 ROC-AUC 0.9656**
（而当前线上集成在 6160 样本上的 AUC 是 0.9571）。同时**文件大小本身就是模型输入**
（`extract_feature.py:349` → `sec_meta[1] = float(len(raw))`，位于 V4_import 视角的 `A08_A15`）。
这意味着：

1. **不控制样本构成，重训只会把"元数据捷径"学得更牢**，AUC 数字会更好看，但线上低 FPR 段不会改善。
2. 本计划的核心动作是 **把元数据捷径消掉**：按 `filetype × 文件大小分桶` 做**格内 1:1 配平**，
   实测可使所选子集的 **metadata-only AUC 从 0.9656 降到 0.5037**（≈随机），即模型只能靠代码语义区分良恶。
3. **数据规模被两个硬约束卡死**（见 §2 P-B）：恶意侧 DLL 仅 6,530 条、良性侧 EXE 仅 6,428 条（可用 6,355）。
   因此"全量 267 万恶意样本"在**平衡 + 捷径中性**的口径下最多只能产出 **12,430 对（24,860 样本）**。
   **不要按全量规模排期。**
4. 良性侧**没有真实时间轴**（仅 2 个入库日），所以"时间外推"只对恶意侧成立；良性侧只能按
   `ssdeep` 近重复组 + sha256 哈希做确定性随机切分。这一点必须写进论文/报告的局限性。

**建议节奏（三轮，勿一次动太多）**

| 轮次 | 内容 | 周期 | 门禁 |
|---|---|---|---|
| **R0 数据侧** | 落地 §3 采样方案（真实月份切分 + 格内配平 + ssdeep 分组），产出 selection manifest | 1~2 天 | metadata-only AUC ≤ 0.55；跨 split sha256/ssdeep 交集 = 0 |
| **R1 小规模验证** | T1 档（3,537 对 / 7,074 样本）跑通训练→评测→门禁全链路，验证"口径统一"确实能救回模型 | 2~3 天 | 至少 1 个 opcode 模型 AUC ≥ 0.70 且快通道集成 AUC ≥ 0.93 |
| **R2 正式重训** | T2 档（12,430 对 / 24,860 样本），按 §5 优先级分批重训 | 1~2 周 | §6 全部门禁通过 |

---

## 1. 本轮数据画像（实测，证据 `retrain_manifest_stats.json`）

### 1.1 规模与构成

| 项 | 恶意（2026-01 ~ 05） | 良性（沿用上版） |
|---|---:|---:|
| 行数 | **2,667,563** | **40,000** |
| sha256 唯一 | 2,667,563（**0 重复**） | 40,000（0 重复） |
| 总体积 | **8,313 GB** | 75.6 GB |
| 中位大小 | Jan 659KB / Feb 1.78MB / Mar 2.14MB / Apr 1.82MB / May 1.05MB | **148KiB**（151.5 KB） |
| p90 / p99 | 5.1~12.5MB / 21.6~46.0MB | 2.35MB / 34.5MB |
| 最大 | 952MB | 786MB |
| filetype | exe32 **71.2%**、exe64 19.1%、**pe(未解析) 9.4%**、dll32 0.15%、dll64 0.10% | **dll32 47.8% + dll64 36.1% = 83.9% DLL**、exe32 8.05%、exe64 8.02% |
| source | InTheWild 88.2%、**Sophos-ReversingLabs 9.4%**、VirusSign 1.8%、malwarebazaar 0.6% | nkrepo benign_pe |
| `family` / `category` / `packer` 列 | **99.7% / 99.7% / 99.9% 为空 → 不可用** | packer 全空 |
| `has_vt` | **仅 610 / 267 万** | 0 |
| `ssdeep` | 2,231,904 有值；**108,366 组重复（多出 435,659 行）**；**54,307 组跨月（389,256 行 = 14.59%）** | 36,974 组、**0 重复组** |

### 1.2 逐月分布与两个"尖峰"

| 月份 | 行数 | 日均中位 | 备注 |
|---|---:|---:|---|
| 2026-01 | 313,324 | 10,591 | — |
| 2026-02 | 427,004 | 7,935 | — |
| 2026-03 | **944,033** | 51,236 | 最大月 |
| 2026-04 | 432,208 | 19,340 | — |
| 2026-05 | 550,994 | 4,716 | **含 05-07 单日 262,220 条** |

**尖峰 1 — 2026-05-07（251,231 条）**：全部来自 `Sophos-ReversingLabs` 单次批量导入，
`filetype='pe'`（未解析出 exe/dll）、**中位大小仅 438KB**（其他日期约 2.1MB）。
**这是与 InTheWild 明显不同的总体**，把它和常规样本混在一起训练会污染先验。
→ **决策：整批划为 OOD 留出集，不进 train/val/test**（`plan_retrain_split.py --ood-source`）。

**尖峰 2 — `filetype='pe'`（PE 头未解析出 exe/dll）共 251,271 条（9.42%）**：
其中 **251,240 条在 2026-05**（即上述 Sophos 批量），其余 5 个月合计仅 31 条。
说明**这批文件的 PE 头根本没被解析**。若不处理，模型会学到"未解析 = 恶意"的伪规律。
→ **决策：OOD 隔离 + 落地阶段补做 PE 头解析后再决定去留**。

### 1.3 时间字段可信度（已校验）

- `date` 列与 `name` 列内嵌日期 **100% 一致（0 处分歧，2,667,563 行全量校验）**，可放心作为真实采集时间轴。
  （证据字段 `malicious.date_column_trustworthy = true`）
- 恶意侧 `md5` **2,667,563 全唯一**（0 重复）；`imphash` 仅 1,203 条有值（0.045%）→ **imphash 不能做分组键**。
- 良性侧只有 `created_at`，且**只有 2 个入库日**（2026-05-26: 36,974；2026-06-03: 3,026），
  **不是样本的真实产生时间** → 良性侧无法做时间外推切分。

### 1.4 标签交叉污染

**4 个 sha256 同时出现在恶意与良性清单**（已记录于证据文件 `cross_class_conflicts`）。
→ **决策：训练集构建时按 sha256 剔除这 4 条**（`selection_manifest` 已自动标记为 label=2 并排除）。

---

## 2. 三个阻断项（本轮重训必须先解决）

### P-A（最高优先级）· 元数据可解 → 捷径风险

实测（平衡 1:1、独立测试集，**只用元数据、不碰任何代码特征**）：

| 特征 | ROC-AUC |
|---|---:|
| 仅 `filetype` | **0.9467** |
| 仅 文件大小 | 0.7808 |
| **`filetype` + 大小** | **0.9656** |

逻辑回归系数：`dll32 −6.278`、`dll64 −6.619`、`exe32 +1.489`、`pe +5.848`、`log_size +0.606`。
即：**"是 DLL ⇒ 大概率良性"这条规则本身就值 0.947 AUC**。

这与上一版评测报告 §5.2 的发现完全吻合——线上集成（33 模型等权）AUC 0.9571，
**低于本数据上纯元数据的 0.9656**，说明当前集成的主要信息量就来自 filetype 先验，
而不是代码语义。**这也解释了 dll64 检出率只有 0.404 的根因**：良性侧 84% 是 DLL，
模型学到"DLL ⇒ 分数高"，把恶意 DLL 压到阈值下。

> 文件大小还是**直接进模型的输入特征**（`extract_feature.py:349`，`sec_meta[1] = float(len(raw))`
> 落在 V4_import 的 `A08_A15` 段）。所以这不是"理论风险"，是模型已经能吃到的捷径。

**对策（本计划核心）**：按 `filetype × 文件大小分桶` **格内 1:1 配平**采样。
实测效果（`plan_retrain_split.py --mode matched --tier max`）：

| split | 配平后样本 | **metadata-only AUC** |
|---|---:|---:|
| train | 8,987 对 | **0.5108** |
| val | 1,792 对 | **0.5089** |
| test | 1,651 对 | **0.5215** |
| **整体** | **12,430 对 / 24,860 样本** | **0.5037** |

捷径被消到随机水平（**0.9656 → 0.5037**）。**在这套数据上训出来的 AUC 才代表代码语义能力。**
（对照组：同工具 `--mode natural` 得 0.9613，说明差异确实来自配平而非切分方式。）

> **因此门禁 M1 必须改写口径**：模型的 AUC 门限不是"超过旧基线"，而是
> **必须显著超过该 split 的 metadata-only AUC（≈0.51）**，否则就是没学到语义。

### P-B · 良性样本量与 filetype 构成

- 良性总量 40,000，**83.9% 是 DLL**；恶意侧 **99.7% 是 EXE**。
- 因此**完全按 filetype 配平是不可能的**：良性 EXE 清单里只有 6,428 条（剔除 >128MB 后可用 **6,355**），
  而恶意 DLL 全量只有 6,530 条 → **任一"双侧 filetype 完全配平"方案的规模上限 ≈ 12,885 对**。
- 良性侧**没有真实时间轴**，不能做时间外推 → 只能用 `ssdeep` 组 + sha256 哈希确定性切分。

**对策**：
1. 训练/评测集用**格内 1:1**（每格内两类等量），而不是"全局 1:1 但 filetype 自由"。
   格内配平后各 split 的 filetype 比例仍可能与真实分布不同——这是**刻意的**：
   目的就是消除先验，让模型只能看代码。
2. **上线判定阈值必须按 filetype 分段标定**（§6.4），否则训练分布与线上分布的差异会吃掉收益。
3. **补采良性 EXE ≥ 2 万条**（含加壳的正常软件）→ 列入 §8 未决事项。

### P-C · 近重复与跨月泄漏

- 恶意侧 **ssdeep 重复组 108,366 个（多出 435,659 行）**，其中 **54,307 组跨月（389,256 行 = 14.59%）**。
- 良性侧 ssdeep **0 重复组**，且与恶意侧 **0 组共享** → 良性侧干净。
- 若按月切分而不做组归并，**测试集里会出现训练集里出现过的变体**（同一家族的打包/改写版本）。

**对策**：`plan_retrain_split.py` 第一遍扫描找出跨月 ssdeep 组，**整组折叠到最早出现的月份**，
保证同组不跨 split；再叠加 `--max-per-group`（默认 2）抑制组内膨胀。

---

## 3. 修正后的采样设计（可直接执行）

### 3.1 切分定义

| split | 恶意侧时间窗 | 良性侧 | 用途 |
|---|---|---|---|
| **train** | 2026-01 ~ 2026-03 | sha256 哈希确定性切分（63%） | 训练 |
| **val** | 2026-04 | 同上（16.2%） | 早停/阈值/超参（**只允许用一次**做最终选择） |
| **test** | 2026-05 | 同上（20.7%） | **最终评测，只评一次** |
| **OOD** | 2026-05-07 Sophos 批量 251,129 条 | — | 分布外鲁棒性检查（不入训练） |

> ⚠️ 与旧管线的根本差异：`build_minimal_dataset.py::assign_months_grouped` 是
> **按组轮询分配"合成月份"**（`(i % n_months) + 1`），**完全不使用真实采集时间**。
> 本计划用 `plan_retrain_split.py` 产出的 `selection_manifest.csv` 直接给出真实 split，
> **绕开旧月份分配逻辑**。

### 3.2 采样规则（工具已实现）

1. **剔除**：`>128MB`（= 引擎 `CODEFENDER_MAX_UPLOAD_BYTES` 上限，线上永远评不到的样本不训练）
   → 536 条；OOD source → 251,129 条；跨类 sha256 冲突 → 4 条。
2. **近重复组折叠**：跨月 ssdeep 组折叠到最早月份；组内最多保留 2 条（`--max-per-group`）。
3. **格内 1:1**：以 `filetype × size_bucket`（分桶 0-64KB / 64-256KB / 256-1MB / 1-4MB /
   4-16MB / 16-64MB / >64MB）为格，每格内恶意与良性等量，取两侧的较小值。
4. **随机性可控**：所有随机都走 `--seed`（默认 42），reservoir sampling，**可复现**。

### 3.3 规模档位（已实测产出）

| 档 | 工具参数 | 实测 train / val / test | 合计 | 总体积 | **metadata-only AUC** | 适用场景 |
|---|---|---|---|---:|---:|---|
| **T1** | `--tier t1` | 1,991 / 916 / 630 对 | 3,537 对 / 7,074 样本 | 13.1 GB | **0.5036** | R1 链路验证（2~3 天） |
| **T2** | `--tier max` | **8,987 / 1,792 / 1,651 对** | **12,430 对 / 24,860 样本** | **55.6 GB** | **0.5037** | **R2 正式重训**（推荐） |
| 自然先验 1:1（对照） | `--mode natural` | 18,156 / 6,189 / 8,211 对 | 32,556 对 / 65,112 样本 | 152.4 GB | **0.9613** | **仅作对照，不作训练集** |

> **对照组的意义**：同样的工具、同样的时间切分与 ssdeep 分组，唯一差别是**是否格内配平**。
> natural 档的 metadata-only AUC 是 **0.9613**，matched 档是 **0.5037**——
> 这就把"捷径"和"语义"干净地分离开了：
> **在 natural 档上训出来的任何 AUC 提升都无法证明模型学到了代码语义**，
> 因为它可以用 filetype+大小解释掉绝大部分。
>
> **T2 就是当前数据结构下的上限**：格内配平（filetype × 大小分桶）口径下 12,430 对；
> 即使放宽到只按 filetype 配平，上限也只有 **12,885 对**（见 §2 P-B 的算术）。
> 再往上走必须先补数据（§8 Q1）。

### 3.4 复现命令

```bash
cd CoDefenderC3
# 1) 统计画像（生成 docs/test-records/retrain_manifest_stats.json）
python -B -X utf8 train/analyze_retrain_manifests.py \
    --manifest-dir ../retrain --out-dir docs/test-records

# 2) 生成 selection manifest（T2 = 正式档；--tier t1 为链路验证档）
python -B -X utf8 train/plan_retrain_split.py \
    --manifest-dir ../retrain --out-dir ../retrain_plan --tier max --mode matched
# 产出：selection_manifest.csv / ood_holdout.csv / split_plan.json
# 链路验证档改用 --tier t1（3,537 对 / 7,074 样本 / 13.1 GB）
```

---

## 4. 特征与口径（与推理侧对齐）

| 维度 | 决定 | 理由 |
|---|---|---|
| 反汇编后端 | **统一 SMDA**（训练侧 `data_loader.py:356` 默认已是 smda） | 消除 BN↔SMDA 语义漂移；重训 = 白训 |
| 哈希编码 | **crc32 稳定哈希**（`feature_extraction/hashing.py`） | 跨进程一致；旧权重作废属预期 |
| V6_opcode_stat 掩码 | **训练侧与推理侧同开同关** | 实测掩掉 D02/D03 后 OpcodeStatNet AUC 0.5688→**0.6108**；训练掩而推理不掩 = 新的口径错配 |
| 文件大小 | **保留为输入，但已在采样层中和** | `sec_meta[1]=len(raw)` 是真实可用特征；配平后它不再是标签代理 |
| 中间表示 ProgramIR | **不采用** | 合并验证实测 IR 候选路径与 main D/E **非逐位等价**（D05 75% / D06 60% / E04 70~80% 一致，OpcodeStatNet 分数 Δ≈−0.11），见 `docs/MERGE_VERIFICATION_2026-11-11.md` |
| 图结构 | **暂不启用真图拓扑** | 5 个图模型当前只吃 22 维统计向量；改架构与换数据同时做，结论不可归因 |

---

## 5. 模型清单与训练顺序

沿用上一版评测报告（6160 样本）的模型级结论作为**优先级依据**：

| 优先级 | 模型 | 动作 | 依据（上一版实测） | 目标 |
|---|---|---|---|---|
| **P0** | OpcodeStatNet | 重训（**训练侧带掩码**） | 掩码实验 A：0.5688→0.6108；BN 时代 0.8676 | AUC ≥ 0.80 |
| **P0** | OpcodeLSTM / OpcodeTransformer / AsmEmbedNet | 重训 | 输入 100% 哈希维，**从未有效**（BN 侧 CI 覆盖 0.5） | AUC ≥ 0.70 |
| **P1** | CallGraphGNN / GraphStatNet / CFGGCN / CFGDGCNN / CFGGAT | 重训 | 纯 22 维语义漂移；SMDA 侧 0.556~0.589 | 恢复 BN 水平并越过 |
| **P1** | DrebinImport / ALOHANet / EmberGBDT_Import / DrebinString / RaffFeatureNet | 重训 | 哈希维依赖，旧权重作废 | ≥ 当前水平 |
| **P1** | InceptionV3 / IMCFN / DL4MD / DrebinSVM | 重训或下线 | 实测 0.2915 / 0.6062 / 0.4982 / 0.5469，**部分低于随机** | 移除负贡献 |
| **P2** | MalConv / MalConv2 / PEMinerRF / EmberDNN / SaxeBerlinDNN / HashEmbedNet / MarkovCNN / ColorCNN / ByteTransformer / NatarajKNN / EmberGBDT_Import | 冻结或微调 | 实测 0.80~0.94，是低 FPR 段主力 | 不退化 |
| **P3** | MalGraph | 独立管线，不走通用 train_all | special 占位 + 外部权重 | 保持 |

**分批顺序（每批独立产出 + 独立评测，不要一次全训）**

```
批次 1  P0 opcode 族 4 个        → 验证"口径统一 + 掩码"假设
批次 2  P1 哈希依赖 5 个          → 验证 crc32 修复
批次 3  P1 图族 5 个             → 验证 SMDA 语义对齐
批次 4  P1 退化模型 4 个          → 移除负贡献
批次 5  P2 主力族（可选 finetune） → 确认不退化
```

> NumPy 模型无通用 `warm_start`，`--mode finetune` 只对 PyTorch 模型有效；
> MalGraph 有独立占位/外部权重，**不由 `train_all.py` 重训**。

---

## 6. 验收门禁（任一不过则不发布）

### 6.1 数据侧门禁（发布前必须全绿）

| # | 门禁 | 判据 |
|---|---|---|
| D1 | 元数据捷径已消除 | 所选子集 **metadata-only AUC ≤ 0.55**（实测 0.5037） |
| D2 | 跨 split sha256 交集 | **= 0** |
| D3 | 跨 split ssdeep 组交集 | **= 0** |
| D4 | 跨类 sha256 冲突 | 入选集合内 **= 0** |
| D5 | 类别平衡 | 每个 split 内恶意:良性 = 1:1（格内亦 1:1） |
| D6 | D/E 覆盖率 | **100%**（`_probe_de_coverage.py` 无缺口） |
| D7 | 超限样本 | 无 `>128MB` 样本进入数据集 |

### 6.2 模型侧门禁

| # | 门禁 | 判据 |
|---|---|---|
| M1 | **语义增益** | 模型 AUC 必须**显著超过该 split 的 metadata-only AUC**（实测 ≈0.51，D1 门禁），否则视为没学到语义 |
| M2 | 低 FPR 段 | 快通道集成 **TPR@FPR=1e-3 ≥ 0.17**、**TPR@1e-4 ≥ 0.0189**（上一版"仅快通道 23 模型"口径为基线） |
| M3 | 集成口径 | 必须用 **family_weighted**（上一版实测 AUC 0.9595 / TPR@1e-3 0.1424 / FPR@TPR95 0.2028 三项均优于等权） |
| M4 | 禁用 max_score | 上一版实测 max_score 集成 AUC 0.4995，**绝不可用** |
| M5 | 分 filetype 报告 | exe32 / exe64 / dll32 / dll64 **分别报 TPR@1e-3 / TPR@1e-4 / FPR@TPR95**（DLL 是历史短板） |
| M6 | 分家族报告 | 按 name 内嵌家族标签（amadey / njrat / wannacry / darkgate / vidar …）分别报指标 |
| M7 | 校准 | 集成 **ECE ≤ 0.15**（上一版等权集成 0.2846，单模型最好 0.0208） |
| M8 | 逐位一致性 | 训练侧与推理侧同批样本的 D/E 特征 **逐位一致** |

### 6.3 与线上分布的一致性（容易被忽略）

训练集是**格内配平**的，线上真实流量是**自然先验**的。因此：

- **必须**在自然先验留出集上额外标定 per-filetype 阈值；
- **必须**用 OOD 集（Sophos 2026-05-07 批量，251,129 条）做一次分布外鲁棒性抽检；
- **不得**用配平集上的单一 0.5 阈值直接上线。

### 6.4 阈值与集成标定

1. 集成权重：按家族加权（family_weighted），**不是**等权、**不是** max_score。
2. 阈值：**按 filetype 分段**标定（EXE / DLL 各一套），从 val 集上取，**test 只评一次**。
3. 概率校准：Platt / 等距校准，压 ECE。
4. 全部标定只在 val 上做，**test 不参与任何选择**。

---

## 7. 与现有管线的差距（需改代码，按优先级）

| # | 差距 | 位置 | 需要做什么 |
|---|---|---|---|
| **G1** | **月份是合成的，不是真实时间** | `build_minimal_dataset.py:427 assign_months_grouped` | 用 `plan_retrain_split.py` 的 `selection_manifest.csv` 直接给出真实 split，**绕开该函数** |
| **G2** | 分组键只有 imphash | `build_minimal_dataset.py:241 group_key` | 恶意侧 manifest 的 `imphash` 仅 **1,203/2,667,563（0.045%）** 有值 → **必须引入 ssdeep 分组**（清单里 2,231,904 条可用） |
| **G3** | 采样无 filetype/尺寸分层 | `build_minimal_dataset.py:565-590` | 接入 `selection_manifest.csv`，按 sha256 白名单取样，**不要**再用 `--per-class/--mal-ratio` 截断 |
| **G4** | 掩码只在推理侧 | `engine/view_masking.py` | 训练侧拼装 D/E 特征时**必须同步掩码**（否则训练/推理口径再次错配） |
| **G5** | 无 metadata-only 捷径门禁 | 训练/评测链路 | 把 §6.1 的 D1 做成脚本化检查，进 CI |
| **G6** | MalGraph 不在通用训练链路 | `train_all.py:665` | 保持 passthrough，单独走 `models/MalGraph_2022` 管线 |
| **G7** | 无 per-filetype 阈值机制 | 引擎判定 | 按 filetype 分段阈值 + family_weighted 集成权重 |

> G1~G3 的落地方式已经确定：`plan_retrain_split.py` 产出 `selection_manifest.csv`
> （含 `sha256,label,split,filetype,size,size_bucket,month,source,family,ssdeep,path`），
> 构建阶段按 sha256 白名单落盘 + 写 `metadata.jsonl` 的 `month` 字段（train=1、val=2、test=3），
> 即可复用现有 `PELoader` / `train_all.py` 的按月训练-留出评估机制，**不需要重写训练框架**。

---

## 8. 未决事项（需要决策 / 补数据）

| # | 事项 | 影响 | 建议 |
|---|---|---|---|
| **Q1** | **是否补采良性 EXE ≥ 2 万条**（含加壳正常软件） | 决定 filetype 完全配平能否突破 12,885 对上限；同时消除"良性 84% DLL"先验 | **强烈建议补**。良性 EXE 总量仅 6,355，是比恶意样本更硬的瓶颈 |
| **Q2** | **Sophos 2026-05-07 批量（251,129 条）是否纳入** | 它是独立总体（filetype 未解析、中位 438KB），纳入会污染先验 | **默认隔离为 OOD**；若要纳入，先补做 PE 头解析再重新评估 |
| **Q3** | `filetype='pe'`（9.4%）是否补解析 | 未解析状态本身可能是伪特征 | 落地阶段用 `pefile` 补解析后重跑画像 |
| **Q4** | 良性侧无时间轴 | 无法做良性的时间外推评估，只能靠恶意侧 | 若能拿到良性真实入库时间，R2 应重做切分 |
| **Q5** | 加壳正常软件（packer 捷径） | 上一版：packed 检出 0.977 vs unpacked 0.797 | 补良性加壳样本，否则 packed 亚组指标持续乐观 |
| **Q6** | 是否启用真图拓扑 | 图族跨时间表现的决定性因素 | 建议 R3 单独做，与数据轮次解耦 |

---

## 9. 里程碑与算力估算

### 9.1 里程碑

| 阶段 | 内容 | 周期 | 产出 |
|---|---|---|---|
| R0 | §3 采样落地 + 数据门禁 | 1~2 天 | `selection_manifest.csv`、D1~D7 全绿报告 |
| R1 | T1 档（3,537 对）全链路验证 | 2~3 天 | 1 个 opcode 模型 AUC ≥ 0.70 的实证 |
| R2 | T2 档分批重训（§5 五批） | 1~2 周 | 新 `ensemble.pkl` 候选 |
| R3 | 门禁 + 校准 + 阈值 | 3~5 天 | `summary.csv/json`、`report.md`、图表 |
| R4 | 发布（备份 → 独立镜像 → 热加载 → 回滚预案） | 1~2 天 | 线上版本 + 回滚包 |

### 9.2 算力

- **特征提取（T2 = 24,860 样本 / 55.6 GB）**：SMDA 实测反汇编 p50 **6.28s**、p99 **600.6s**，
  端到端墙钟 p50 **10.82s**（BN 时代 46.73s）。
  按 80 核并行，**提取阶段约 1~2 天**（长尾样本是主要成本，需配 `CODEFENDER_SMDA_TIMEOUT` 兜底）。
- **训练**：T2 规模下 33 个模型分批训练，**CPU 约 2~4 天**；有 GPU 时 PyTorch 族可显著加速。
- **对比**：全量 267 万恶意样本（8.3 TB）在同口径下约需 **9 天以上**纯提取，**不现实**——
  这也是 §0 结论 3 的算术依据。

---

## 10. 风险与回滚

| 风险 | 缓解 |
|---|---|
| 配平后样本量偏小（12,430 对）导致过拟合 | 门禁 M1（语义增益）+ 早停 + 逐批对照；必要时叠加 Q1 补数据 |
| 训练集分布 ≠ 线上分布 | §6.3 per-filetype 阈值 + OOD 抽检 + 自然先验对照集 |
| D/E 特征覆盖率 < 100% | D6 门禁；只读核对覆盖率与失败原因，修复根因并备份、核对失败记录后重跑构建 |
| 新权重上线后线上退化 | **保留基线 ensemble.pkl 不动**，候选产物写 `runs/<run-id>/`；上线走 `reload-model` 热切换，**保留一键回滚** |
| 不可逆误操作 | 训练脚本默认**不覆盖** `ensemble.pkl`；`--in-place` 需显式指定并先备份 |

---

## 11. 附录 · 证据与工具

| 工具 / 证据 | 作用 |
|---|---|
| `train/analyze_retrain_manifests.py` | 清单画像：规模/构成/逐月/质量/泄漏/交叉标签/元数据捷径基线 |
| `train/plan_retrain_split.py` | 采样方案生成器：真实时间切分 + ssdeep 分组 + 格内 1:1 配平 + OOD 隔离 + 捷径复测 |
| `docs/test-records/retrain_manifest_stats.json` | §1~§2 全部数字的原始证据（由 `analyze_retrain_manifests.py` 直接产出） |
| `docs/test-records/retrain_data_stats_2026-11-12.json` | 逐月 packer/category/platform/family 构成补充 |
| `docs/test-records/retrain_data_profile_2026-11-12.json` | name 字段结构、size 分档、日分布补充 |
| `docs/test-records/retrain_leak_stats_2026-11-12.json` | ssdeep 跨月泄漏与跨类共享的独立复核 |
| `docs/test-records/retrain_shortcut_auc_2026-11-12.json` | 元数据捷径基线的独立复核 |
| `docs/test-records/retrain_split_plan_2026-11-12.json` | §3 采样方案与逐格供给/绑定侧记录（matched 档） |
| `docs/test-records/retrain_split_plan_natural_2026-11-12.json` | 自然先验对照组（metadata-only AUC 0.9613） |
| `docs/test-records/retrain_selection_manifest_2026-11-12.csv` | T2 档逐样本 split 决策（可直接喂给构建阶段） |
| `test2_eval/eval_output/最终模型详细评估报告.md` | §5 模型优先级与 §6 门禁阈值的来源 |
| `docs/MERGE_VERIFICATION_2026-11-11.md` | ProgramIR 路线为何不采用 |
| `docs/SMDA_BACKEND.md` | SMDA 后端契约 |
| `docs/TESTING.md` | 真实接口验收 |

---

*编制：2026-11-12　数据基线：`retrain/`（2026-01 ~ 2026-05 恶意 + 沿用上版 4 万良性）*
