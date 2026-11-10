# test_lm 分支分析与 main 对比报告

> 生成日期：2026-11-10
> 对象：`origin/test_lm` @ `a3610d7`（"BN切换到SMDA"，34 个提交）
> 基线：`origin/main` @ `e6db412`（SMDA 后端 + hash 确定性 + GPU 双镜像 + 训练侧 SMDA 默认）
> 检出方式：`git worktree add test_lm test_lm`（本地目录 `test_lm/`，已 gitignore）
> 验证方式：读码 + **实跑两边代码对比同一份 `ensemble.pkl`** + 跑 test_lm 自带测试套件

---

## 一、结论摘要

1. **test_lm 不是 main 的超集，而是一次"从更早基点分叉、删掉 web 层"的独立演进**。
   它在 **架构层（ProgramIR 中间表示）** 比 main 走得更远，在 **运行时层（引擎 app.py）落后于 main**。
2. **不要整体 merge**。实测：test_lm 的 `engine/app.py` 会把 `V1_byte` 截成 **128**、`V8_color` 截成 **25088**
   —— 正是 main 已修掉的 MalConv / IMCFN / InceptionV3 不出分的根因（历史上 3741 次报错会回来）。
   同时它**没有** GPU 设备迁移、**没有**掩码开关接入、**没有**空特征守卫。
3. **test_lm 值得吸收的三样东西**：① ProgramIR 契约（7 条硬不变量 + BN API 完备性证明）；
   ② IR 缓存（**105 KB/样本 vs bndb 6.0 MB，小 58 倍**，后端中立）；
   ③ **黄金基线快照 + 两级门禁**（`bn_baseline` fixture + 28 项可离线跑的断言）。
4. **哈希两家实现数值完全等价**（实测 8 个字符串 × 3 个取模维度全部一致）⇒ 合并时二选一即可，无语义风险。
5. **建议路线：以 test_lm 为"架构来源"、以 main 为"运行时来源"，做定向移植**（§六），不要整体合并。

---

## 二、test_lm 做了什么

### 2.1 规模

| 项 | 数值 |
|---|---|
| 提交数 | 34（基点 `b8e39f3`，tip `a3610d7`） |
| `CoDefenderC3/` 改动 | 104 文件，**+65,896 / −16,990** |
| 顶层 | **删除了整个 `web/`**（Vue 前端 + FastAPI 后端），新增 `test_results/20261106_predict_directory/` 一次评测快照 |
| 清理 | 删除 24 个 BN 探针/死代码；补回 `engine/virus_namer.py` |

### 2.2 四个阶段

| 阶段 | 内容 | 关键产物 |
|---|---|---|
| **Phase 1** | ① **W0 稳定哈希**：13 处内置 `hash()` → `zlib.crc32`；② **ProgramIR 契约**：反汇编与特征层之间插入后端中立中间表示 | `feature_extraction/{ir,backend,backend_bn,backend_smda,features_from_ir,ir_cache}.py`、`docs/IR_CONTRACT.md`、`docs/FEATURE_HASH_STABILITY.md` |
| **Phase 2** | SMDA 后端适配器 + 跨后端对比工具（**挖出一个生产缺陷**） | `tests/compare_ir_backends.py`、`tests/compare_malgraph_backends.py` |
| **Phase 3** | MalGraph 切干净：移除 BN 依赖，改走 ProgramIR | `models/MalGraph_2022/{graph_from_ir,artifact_guard,rebuild_smda}.py` |
| **Phase 4** | **MalGraph 作废 + SMDA 重建重训**；切除其余 BN 专用路径 | `models/MalGraph_2022/saved/feature_manifest.json` |

### 2.3 ProgramIR 契约（最值得学的一块）

```
PE ──[后端: BN / SMDA]──> ProgramIR ──[特征层]──> D01-D07 / E03-E04
```

数据类：`BasicBlock(start, length, instructions, successors)`、
`Function(start, size, blocks, callees, callees_known)`、
`ProgramIR(functions, imports, arch, bitness, backend, backend_version, schema_version)`。

**7 条硬不变量**（破坏即改变特征）：

| # | 不变量 | 为什么 |
|---|---|---|
| I1 | **顺序即语义**（functions/blocks/instructions/callees 全有序） | D01/D02/D03 直接依赖顺序；去重会改特征 |
| I2 | **callees 保留重复** | 现有 `cg_edges += 1` 按重数计调用边 |
| I3 | 助记符非空且小写 | 等价于现有 `if m:` 过滤 + 规范化 |
| I4 | 地址用 int，一切身份比较用起始地址 | 与现有代码一致 |
| I5 | 不可变（frozen + tuple） | 可哈希、可安全缓存、可等值比对 |
| I6 | successors 原样透传（不排序不去重） | E03 回边判定依赖地址序 |
| I7 | **callees 未知 ≠ callees 为空** | 现有代码在 `func.callees` 抛异常时 n_callees=0 但 is_leaf/is_recursive 保持 False，E04 叶子计数却按"空"算 —— 两处语义不同，用 `callees_known` 区分 |

还附 **BN API 完备性证明**：把现有代码用到的每一个 BN API 映射到 IR 字段（§3 表格），
以此论证"IR 够不够用"。这种写法在重训项目里很少见，值得推广。

### 2.4 两档分析深度（main 没有的区分）

| profile | 用途 | BN 分析模式 |
|---|---|---|
| `features` | D01-D07 / E03-E04 | basic（线性扫描，快） |
| `graph` | MalGraph 的 CFG / FCG | full（要算 MLIL 才能还原调用边） |

⚠ 两档 IR **不能混用**：basic 档下 BN 不会为大多数函数算 MLIL（实测 521/612 个函数 mlil 为 None），
拿它做 FCG 会得到**空调用图**。

### 2.5 训练侧：中间缓存从 .bndb 换成 IR

| | bndb（旧） | IR（新） |
|---|---|---|
| 单样本体积 | 6.0 MB（最大 36.9 MB） | **105 KB（最大 1.4 MB）→ 小 58 倍** |
| 可读性 | 只有 BN 能读 | **后端中立** |
| 抽特征是否需要 BN 许可 | 需要 | **不需要** |

`train/data_loader.py` 里 `.bndb` 路径被**删除**，统一走
`ir_cache.generate_irs_batch()`（PE→IR）与 `ir_cache.extract_de_from_ir_batch()`（IR→特征）。
`CODEFENDER_DE_CACHE=bndb` 只保留为"识别旧环境变量"，会打告警并按 ir 处理。

### 2.6 门禁与工具链

| 工具 | 作用 | 本地可跑? |
|---|---|---|
| `tests/test_ir_contract.py` | IR 结构不变量 / 序列化 / 校验（**17 项**） | ✅ **全部通过** |
| `tests/test_stable_hash.py` | 跨进程哈希稳定性（**11 项**，含"特征提取里已无内置 hash"） | ✅ **全部通过** |
| `tests/verify_ir_equivalence.py` | bndb→IR→特征 vs bndb→特征 **逐位相同** | ❌ 需 BN |
| `tests/verify_de_pipeline_equivalence.py` | 两条 D/E 抽取路径逐位对照 | ❌ 需 BN + 样本 |
| `tests/compare_ir_backends.py` | 跨后端 IR / 特征差异量化 | ❌ 需双后端 + 样本 |
| `tests/compare_malgraph_backends.py` | MalGraph 双后端对比 | ❌ 同上 |
| `tests/fixtures/bn_baseline/` | **BN 黄金基线快照**（manifest 533 KB + samples 41 KB + bndb_manifest 602 KB） | 数据在 |

### 2.7 一个关键实测结论（W1）

> **「PE → BN 实时分析」这一步本身不确定**：同批样本两次采集，**25/88 的 D/E 指纹不同**；
> 而「固定 .bndb → 抽特征」确定（288/288 一致）。

这条比"哈希随机"更深一层：**即使把哈希修好，BN 时代的训练特征本身也不可复现**。
IR 把这个不确定性显式隔离成"生成一次 IR，IR→特征是纯函数"。main 目前没有这一层隔离。

### 2.8 附带产物

- `engine/naming.py`：生产档命名与恶意度分档（并提醒"切 AUC 加权聚合后必须用留出月重新标定档位"）
- `engine/projection.py`：对外响应字段裁剪（对外契约只保留业务必需字段）
- `engine/dev/app.py`：单样本推理的开发快照服务

---

## 三、与 main 的逐项对比

### 3.1 同一目标的两种实现

| 维度 | main（本轮） | test_lm | 结论 |
|---|---|---|---|
| 确定性哈希 | `feature_extraction/hashing.py::stable_bucket`（10 处替换） | `feature_extraction/_stable_hash.py::{stable_hash, stable_bucket, stable_seed}`（13 处） | **数值等价**（实测），二选一 |
| 后端抽象 | 引擎内 `_disasm_backend()` 分发 bn/smda | **ProgramIR 中间层** + `backend.py` 两档 profile | test_lm 更彻底 |
| 训练 D/E 抽取 | 直接 PE→D/E（**无中间缓存**） | PE→**IR 缓存**→D/E（105 KB/样本） | test_lm 更优（换特征算法不必重跑反汇编） |
| 训练后端默认 | **SMDA**（`CODEFENDER_DISASM_BACKEND` 未设即 smda） | IR 缓存 + 后端分发 | 目标一致 |
| 视图维度推断 | **视图优先**：V1_byte=32768、V8_color=196608 | **模型优先多数票**：V1_byte=128、V8_color=25088 | **test_lm 回归** |
| GPU 设备迁移 | `CODEFENDER_MODEL_DEVICE`（auto/cuda/cuda:N/cpu）+ 加载后迁移 | **无**（app.py 无 `_move_ensemble_to_device`） | **main 独有** |
| 推理期掩码开关 | `CODEFENDER_MASK_VIEWS` + `apply_view_mask` 接入 | 文件在、**app.py 不调用**（死代码） | **main 独有** |
| 空特征守卫 | `de_features_are_empty()` + worker 双保险 | 无 | **main 独有** |
| 维度推断修复 | 视图优先（实测 32768/196608） | 回归到模型内部 `nn.Linear.in_features` | **main 独有** |
| 接口字段裁剪 / 命名分档 | 无 | `engine/projection.py` / `engine/naming.py` | **test_lm 独有** |
| web 层（检测统计面板等 8 提交） | 有 | **删除** | **main 独有** |
| 重训计划 / train README §0.5 | 有 | 无 | **main 独有** |

### 3.2 哈希数值等价性（实测）

```
字符串                                              main  test_lm  一致?
CreateFileA                                          120     120    一致
LoadLibraryA                                         141     141    一致
mov                                                    0       0    一致
call                                                  62      62    一致
xor rax, rax                                          96      96    一致
api-ms-win-core-eventing-l1-1-0.dll!EventWrite...     233     233    一致
三种取模维度(256/511/128)下完全一致: True
```
⇒ 两套实现可以互换，合并时不会出现"特征语义漂移"。

### 3.3 视图维度推断：同一份 ensemble.pkl 的实跑对比

| 视图 | test_lm | main | 后果（test_lm） |
|---|---:|---:|---|
| **V1_byte** | **128** | **32768** | MalConv(kernel 500 > 128) 报错；MalConv2/ByteTransformer 拿到错维度 |
| **V8_color** | **25088** | **196608** | IMCFN reshape 91×91×3 失败；ColorCNN 错维度 |
| V8_gray | 65536 | 65536 | 一致 ✓ |
| V6_opcode_seq / V6_opcode_stat / V7_graph / V4_import / V5_string | 4096 / 549 / 22 / 339 / 553 | 同 | 一致 ✓ |

**根因**：test_lm 用"视角组内**模型期望维度多数票**优先"（V1_byte 三个模型都说 128 → 截 128）；
main 用"**视图优先**"（V1_byte 的视图构造器固定 `np.zeros(RAW_LEN)`，与模型内部结构无关）。

### 3.4 冲突面（同名文件两边都改）

| 文件 | 差异量 | 合并风险 |
|---|---:|---|
| `feature_extraction/extract_feature.py` | 1462 行 | **高**（两边都大改：main 换哈希 + insn_categories 回退；test_lm 去掉 BN 硬依赖 + 换 stable_hash） |
| `engine/app.py` | 466 行 | **高**（会回退维度修复 / 丢 GPU 迁移 / 丢掩码接入） |
| `train/data_loader.py` | 135 行 | **高**（main 直抽 vs test_lm IR 缓存） |
| `engine/analysis_worker.py` | 115 行 | 中 |
| `config.py` | +40 | 低 |
| `Dockerfile.smda` / `.gpu` | 各 4 行 | 低 |
| `train/build_minimal_dataset.py` | 30 行 | 低 |

main 独有（test_lm 没有）：`feature_extraction/{hashing,smda_extract}.py`、`engine/view_masking.py`、
`train/RETRAIN_2026_PLAN.md`、24 个 BN 探针/死代码、整个 `web/`。
test_lm 独有：`feature_extraction/{ir,backend,backend_bn,backend_smda,features_from_ir,ir_cache,_ir_worker,_ir_de_worker}.py`、
`engine/{naming,projection,virus_namer}.py`、`engine/dev/`、`models/MalGraph_2022/{graph_from_ir,artifact_guard,rebuild_smda}.py`、
`tests/` 全套、`docs/{IR_CONTRACT,FEATURE_HASH_STABILITY,BASELINE_FIXTURE}.md`。

---

## 四、test_lm 的优势（应当吸收）

1. **ProgramIR 契约**：7 条硬不变量 + BN API 完备性证明 → 口径**可审计**、可**逐位回归**。
2. **IR 缓存**：105 KB/样本（小 58 倍）、后端中立 → 换特征算法/重训不必重跑昂贵的反汇编；
   也让"IR→特征是纯函数"这一性质显式化。
3. **黄金基线快照 + 两级门禁**：任何后续改动都能用 `bn_baseline` 做逐位比对，这是重训项目的**基础设施级**资产。
4. **两档 profile（features/graph）**：main 的推理链路没有区分，MalGraph 需要 full 分析
   （BN basic 档 521/612 函数无 MLIL → FCG 会空）。这是 main 的一个潜在隐患。
5. **跨后端对比工具**：`compare_ir_backends.py` / `compare_malgraph_backends.py` 可量化两个后端的差异，
   正是"SMDA 替换 BN 到底丢了什么"这个问题的标准答案。
6. **W1 实测**（BN 实时分析不确定）→ 解释了为什么中间产物必须"生成一次"。
7. **接口裁剪与命名分档**：`projection.py` / `naming.py`，并明确提醒"切加权聚合后必须重标定档位"。
8. **清理 24 个死代码** + 补回 `virus_namer.py`。

## 五、main 的优势（合并时必须保留）

1. **视图维度推断修复**（实测 32768 / 196608）—— 直接决定 MalConv/IMCFN/InceptionV3 能否出分。
2. **GPU 设备迁移**（`CODEFENDER_MODEL_DEVICE`）—— 没有它，GPU 镜像里只有 MalGraph 用 GPU。
3. **推理期掩码开关接入**（`apply_view_mask`）。
4. **空特征守卫**（`de_features_are_empty`）—— 防止"全零特征"污染数据集。
5. **web 层**（检测统计面板 / 判定契约统一 / 运行时升级契约 / 旧容器后端自适应）。
6. **重训计划报告 + train/README §0.5**。

---

## 六、建议的整合路线（定向移植，不整体 merge）

| 步骤 | 内容 | 收益 | 风险 |
|---|---|---|---|
| **S1** | 移植 ProgramIR：`ir.py` + `backend*.py` + `features_from_ir.py` + `ir_cache.py` + `docs/IR_CONTRACT.md` | 口径可审计、可逐位回归、缓存小 58 倍 | 中（要重构 `data_loader` 的 D/E 阶段） |
| **S2** | 移植门禁：`tests/fixtures/bn_baseline/` + `test_ir_contract.py` + `test_stable_hash.py` + `verify_*` | 后续所有改动都有逐位门禁 | 低 |
| **S3** | 移植两档 profile 到 main 的推理链路（features vs graph） | 修正 MalGraph 的分析深度隐患 | 中 |
| **S4** | 哈希二选一（建议保留 main 的 `hashing.py`，把 test_lm 的 `stable_seed()` 补进去覆盖图像 RNG 种子） | 数值等价，无语义风险 | 低 |
| **S5** | 训练侧：把 main 的 SMDA 直抽与 test_lm 的 IR 缓存**叠加**（先抽 IR 缓存，再从 IR 出特征） | 兼顾"训练/推理同源"与"可重算特征" | 中 |
| **S6** | 保留 main 的维度修复 / GPU 迁移 / 掩码 / 空特征守卫 / web 层 | 防止回退 | — |
| **S7** | MalGraph 决策：test_lm 选择"作废 + SMDA 重建重训"；main 的实测是"跨后端稳定（ρ=0.80，AUC 差异不显著 P=21.7%）" | — | 需拍板：**先按 test_lm 的 Phase 4 走（它有 `graph_from_ir.py` 打通）**，但用 ρ=0.80 的证据复核"是否真的必须作废" |

**明确不要做**：不要把 test_lm 的 `engine/app.py`、`feature_extraction/extract_feature.py`、
`train/data_loader.py` 整文件覆盖到 main（会回退 §五 的 5 项）。

---

## 七、复核方法（本文结论都可复现）

```bash
# 检出分支到本地目录
git worktree add test_lm test_lm

# 哈希等价性
python -c "import sys;sys.path[:0]=[r'CoDefenderC3',r'CoDefenderC3/feature_extraction'];\
import importlib,importlib.util;\
m=importlib.import_module('feature_extraction.hashing');\
s=importlib.util.spec_from_file_location('t',r'test_lm/CoDefenderC3/feature_extraction/_stable_hash.py');\
t=importlib.util.module_from_spec(s);s.loader.exec_module(t);\
print([m.stable_bucket(x,256)==t.stable_bucket(x,256) for x in ['mov','call','CreateFileA']])"

# 维度推断对比（同一份 ensemble.pkl）
cd test_lm/CoDefenderC3 && python <script> <path>/ensemble.pkl
cd CoDefenderC3      && python <script> <path>/ensemble.pkl

# test_lm 自带测试
cd test_lm/CoDefenderC3/tests && python test_stable_hash.py && python test_ir_contract.py
```

## 八、遗留问题

1. test_lm 的 `verify_ir_equivalence.py` / `verify_de_pipeline_equivalence.py` / `compare_*_backends.py`
   需要 **BN 许可 + 真实样本**，本地跑不了；**建议在测评服务器（有 BN 镜像与样本）上跑一遍**，
   这是判定"IR 是否逐位等价于现有 D/E 口径"的唯一硬证据。
2. `tests/fixtures/bn_baseline/` 里的 `samples.json` 指向作者机器的样本路径 —— 需要改成
   测评服务器的路径，否则 fixture 不可复现。
3. test_lm 的 `bndb_manifest.json.invalidated`（602 KB）说明 **BN 基线已失效**（许可过期），
   这与 `docs/FEATURE_HASH_STABILITY.md` 里的"许可过期误判更正"一致 —— 说明他们的 BN 基线
   快照是在许可失效前取的，**新环境需重新生成**。
