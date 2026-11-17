# 数据集构建与训练

核对日期：2026-11-11。命令从 `CoDefenderC3/` 执行。当前部署为 33 模型 / 15 视图，实际训练集合以基线模型、数据集视图和筛选参数为准，不等于注册表所有候选项。

## 1. 运行边界与依赖

- 训练默认只写 `runs/<run-id>/`，不覆盖 `ensemble.pkl`。不要直接在生产目录中构建数据集/清缓存。
- 模型运行依赖见 [启动指南](../docs/README.md#21-安装依赖)；训练/评估额外按脚本需要安装 `scikit-learn`、`matplotlib`、`Pillow` 等。公共数据下载脚本还有各自依赖，推理 requirements 不等于完整训练环境。
- D/E 默认 SMDA；显式 `CODEFENDER_DISASM_BACKEND=bn` 才使用已安装并授权的 BN。
- 当前训练可以微调普通 PyTorch 模型；NumPy 模型在 `fit` 中重新训练，不支持通用 warm_start。MalGraph 保留特殊占位/外部权重，不由通用 `train_all.py` 重训。
- 所有 PE 仅静态分析，不执行样本。

## 2. 当前脚本

| 脚本 | 用途 |
|---|---|
| `build_minimal_dataset.py` | 分类 PE 源 → 样本/元数据/特征缓存/构建 manifest |
| `train_all.py` | 已有数据集训练，或使用 `--source/--out` 先构建再训练 |
| `train_minimal.py` | 已有数据集训练入口，保留基础训练兼容性 |
| `verify_trained_ensemble.py` | 基线与候选 schema、槽位、加载及伪特征前向检查 |
| `build_flat_dataset_meta.py` | 已有平铺样本生成元数据/合成月份；不自动重建全部特征 |
| `build_dataset.py`、`build_rawpe.py`、`run_all.py` | 数据源准备与离线实验链路；运行前阅读各自参数/配置 |
| `data_loader.py`、`dataset_utils.py`、`ember_vectorizer.py` | 数据发现、特征缓存和视图拼装 |
| `ir_candidate.py` | 显式候选 IR 接线，非默认路径 |
| `_probe_de_coverage.py` | D/E 覆盖诊断 |

旧设计稿中的 `train_incremental.py`、`ingest_new_samples.py`、`train_malgraph.py` 等并非当前可用的通用 CLI；不要从历史文档复制这些命令。

## 3. 标准工作流

### 3.1 准备源目录

```text
/data/pe-source/
  benign/
    sample-a.exe
  malicious/
    sample-b.exe
```

`build_minimal_dataset.py` 在有限目录深度内扫描支持的扩展名并检查 MZ，标签从路径目录名推断；它与在线按内容验证 PE 的筛选规则不同。使用上面的标准名称，避免未识别名称被忽略。

识别的良性名称为 `benign/clean/negative/ben/goodware/0`，恶意为 `malicious/malware/positive/mal/1`；代码会规范大小写，但不接受 `malicous` 等拼写错误。样本按 SHA256 去重，标签冲突、类数量和最终配比需检查 manifest。

### 3.2 先预演，再构建

```bash
python train/build_minimal_dataset.py --source /data/pe-source --out /data/pe-dataset \
  --baseline ensemble.pkl --per-class 250 --months 4 --train-months 2 --views full --dry-run
python train/build_minimal_dataset.py --source /data/pe-source --out /data/pe-dataset \
  --baseline ensemble.pkl --per-class 250 --months 4 --train-months 2 --views full
```

| 参数 | 默认/行为 |
|---|---|
| `--views full` | 根据基线提取 fast + D/E；当前部署为 11 + 4 个视图 |
| `--views fast` | 不提取 D/E；缺视图模型从基线冻结继承，不代表全部模型重训 |
| `--per-class` | 默认 0；按类别/配比规则取样，不是总样本数 |
| `--mal-ratio` | 默认 1.0；构建目标恶意:良性配比 |
| `--months/--train-months` | 构建默认 4/2；仅合成月份桶，不证明真实时间外推 |
| `--link` | 同盘优先硬链接，失败回退复制；与源共享内容，不能就地修改数据集样本 |
| `--allow-partial-de` | 放宽 D/E 覆盖门禁，可能丢样本，不是用零特征填补 |
| `--force` | 允许使用非空输出目录；不是无副作用的默认选项 |
| `--drop-per-sample` | 构建后删除逐样本 NPZ，执行前确认后续用途 |
| `--exclude-sha256` | 以文件清单排除样本；不是在线模型排除参数 |

`--source` 一条龙训练入口的构建默认月份为 10/7，和独立构建脚本的 4/2 不同；为了复现，应显式填写。构建后检查 `metadata.json/jsonl`、`manifest.json`、每月样本数、视图维度、实际覆盖及告警；失败或不完整不算可训练数据集。

### 3.3 旧 month-only 训练

```bash
python train/train_all.py --dataset /data/pe-dataset --baseline ensemble.pkl \
  --mode scratch --epochs 20 --device cpu --run-id pe-run-new
# 中断后使用相同数据/参数和 run-id，复用已经完成的模型 checkpoint
python train/train_all.py --dataset /data/pe-dataset --baseline ensemble.pkl \
  --mode scratch --epochs 20 --device cpu --run-id pe-run-new --resume
```

- `--models` / `--exclude` 按名称筛选，`--mode finetune` 尝试加载已有 PyTorch state_dict；不支持/不兼容时可退回从零训练，要检查 `warm_started`。
- `--resume` 复用逐模型完成后的 `partial/<model>.pkl` / `progress.json`，不是精确恢复模型内部 epoch、优化器和随机状态。
- 已存在目标模型 checkpoint 且未加 `--resume` 时拒绝复用；换新 run-id 可开始新实验。
- 缺少整个视图的模型冻结继承；特殊模型（MalGraph）透传。查看 manifest 的 `trainable/frozen/passthrough`，不要把“输出仍有 33 个槽位”当成 33 个模型均新训练。
- `--weighting equal/auc` 生成的已保存合法 `_weights` 现由共享 DecisionPolicy 用于源码中的离线/Web 聚合；没有权重才等权。旧 month-only 产物的 `--threshold-grid` 仍仅用于离线报告，不自动变成线上阈值；没有显式 `decision_policy` 的旧集成继续 identity + 严格 > 0.5 + 明确缺失模型重归一化。新源码不等于已部署，见第 9 节。

### 3.4 旧 month-only 产物与复验

```text
runs/pe-run-new/
  partial/<model>.pkl
  progress.json
  ensemble.pkl
  manifest.json
```

```bash
python train/verify_trained_ensemble.py --baseline ensemble.pkl \
  --candidate runs/pe-run-new/ensemble.pkl --fake-n 4
```

该工具只做结构/加载/伪特征检查，不证明真实 PE 的特征兼容、MalGraph 外部权重、检测质量或生产可用。还须按 [真实接口测试](../docs/TESTING.md#3-真实接口检查)验证，并在独立留出集评估 FPR/召回等指标。

默认保存额外 schema 键和特殊模型占位，不默默删除未知状态；`--no-preserve-extra-keys` 会改变这项行为，非日常选项。`--in-place` 会先备份再复制覆盖基线，不是事务化自动发布；正常流程优先独立候选、验证后由运维发布。

## 4. 特征缓存与失败处理

训练 SMDA 直接 PE → D/E，不生成 BN 中间 bndb；成功记 `de_done`，硬失败记 `de_fail`，软超时保留重试机会。`CODEFENDER_SMDA_WORKERS` 默认 loader 并发；`CODEFENDER_SMDA_TIMEOUT` / 批提取回退 `CODEFENDER_DE_PER_FILE_TIMEOUT` 不是在线 HTTP 超时。

```bash
python train/_probe_de_coverage.py /data/pe-dataset
python train/build_flat_dataset_meta.py --data-dir /data/existing-dataset --dry-run
```

BN 专用探针与补救脚本已移除；通用 D/E 覆盖率诊断保留。先诊断失败日志、样本路径、实际 NPZ 和月度缓存。不要为“重新跑一遍”批量删除源样本/整个缓存；调整标签、月份或特征口径后旧月度缓存可能失效。平铺元数据工具的 `--purge-per-month` 会归档旧目录，只有确认目标后使用。

## 5. 发布与长期计划

- 发布须验证基线/候选可追溯性、未知键保留、实际模型覆盖和真实质量；备份当前模型与外部 MalGraph 产物。
- `POST /reload-model?model_path=...` 只接受服务端可访问文件。宿主路径不能直接作为容器路径；换镜像内产物应重建镜像/容器。
- `reload-model` 影响共享监听器；标准生产配置不依赖 dev 的运行时覆盖文件。
- GPU `train` Docker target 是纯模型推理/离线基础镜像，当前不 COPY 训练目录，不能当作已经准备好的训练环境。

专题：[增量与 Checkpoint 边界](../docs/增量训练与Checkpoint技术方案.md)、[重训计划](RETRAIN_2026_PLAN.md)、[IR 契约](../docs/IR_CONTRACT.md)。

## 6. retrain R0 清单工具（2026-11-13）

新增 dependency-light 审计、严格四角色采样、SHA/path/PE头校验与白名单物化入口：

- analyze_retrain_manifests.py / plan_retrain_split.py
- verify_retrain_manifest.py / build_retrain_dataset.py

操作说明与局限见 [R0 实施记录](../../retrain/RETRAIN_R0_IMPLEMENTATION_2026-11-13.md)。
四角色数据保留实际 YYYY-MM，不使用 month=1/2/3 编码角色；当前旧 PELoader 会拒绝显式 split 数据，避免合并留出集。R0 本身不含训练器；后续 opt-in 接线见第 8 节，不能将这些产物视为开训批准。
所有新目录禁止覆盖；不改变旧数据集的 month-only 加载行为，也不修改生产 ensemble.pkl。

## 7. retrain 显式切分与版本化缓存（P0，2026-11-13）

新增 RetrainSplitLoader / FeatureContract / SubprocessFeatureBuilder。create_loader 仅在 split_aware=True 时返回 PE_RAW_SPLIT；默认旧月份入口继续拒绝四角色数据。get_split 不提取特征且默认要求全覆盖，sample_ids/labels 与 mmap 行一起保存；内容、后端/代码/依赖与显式 view 配置绑定不同层缓存。

独立进程 adapter 当前只开放 B01–B07 与 SMDA D01–D07/E03/E04；其余未审计阶段和图拓扑不以补零替代。实际 SMDA native 验证因本地 LIEF DLL 限制未成功，不能把合成回归当作真实 PE 或生产验证。

详细契约与 API 见 [P0 实施记录](../../retrain/RETRAIN_SPLIT_CACHE_P0_2026-11-13.md)。train_all 的 opt-in 四角色训练/校准接线见第 8 节；没有启动正式训练或改生产权重。

## 8. retrain 四角色训练入口（P0，2026-11-13）

`train_all.py` 新增 `--split-aware --feature-contract <冻结 JSON> --models <显式名称>`。必须使用 R0 已验证物化的数据和已提取的全覆盖缓存；入口不提取特征，默认旧月份分支仍拒绝四角色数据。

- 只用 train 拟合；PyTorch 以外部 model_val 早停并恢复最佳状态，NumPy 仅将 model_val 用于拟合后选择。NumPy finetune 明确拒绝，PyTorch 不兼容 warm state 不退回 scratch。
- model_val 选择 equal/auc 权重并落盘锁定后，才获取 calibration batch 选择预声明网格中的阈值。test 特征/预测不读取；公共四角色元数据仍由 loader 审计。
- 所有显式模型均要求成功、全覆盖、ID 对齐及有限概率；不继承失败模型，不调用含常量填充的 predict_all。旧构建/序列化/--in-place 参数在 split 分支拒绝。
- resume 严格绑定数据、schema、模型配置/源码、后端、训练参数及源码版本；只复用完成 checkpoint，不是 epoch/优化器恢复。损坏 checkpoint、未知状态或丢失进度拒绝。
- 仅生成 `trained_models.pkl` 研究 schema、decision_candidate/manifest 与完整性指针，不生成可 reload 的 `ensemble.pkl`，`deployable=false`。用 `train.retrain_run.verified_manifest` 验证发布文件，不能仅看 complete.json 是否存在。
- calibration 当前为 identity 概率变换 + 阈值选择，不是概率校准或低 FPR 认证。CPU 选择路径保持新训练/恢复一致；--device auto 在新分支明确为 CPU。
- `--dry-run` 仅预检 train/model_val，不建 run 目录、不训练；可能生成派生 mmap 缓存。Windows 深目录建议显式使用短 `--split-cache-dir`；本机长路径缓存写入失败已保留证据。

本训练阶段验收时 96 项回归通过（R0 21 + split/cache 37 + 本项 38），其中 torch 控制流程使用注入 stub；真实 torch/sklearn/生产模型未验证，实际样本定位和 SMDA LIEF DLL 问题仍未解决。后续共享 DecisionPolicy 接线见第 9 节，模型输入/序列化契约及独立验收仍待实现，**仍未获准正式开训或上线**。

说明：[训练入口实施记录](../../retrain/RETRAIN_SPLIT_TRAINING_P0_2026-11-13.md)。

## 9. 共享离线/Web DecisionPolicy（P0，2026-11-13）

- engine/decision_policy.py 统一显式模型名称、非负归一化权重、校准器、严格 > 阈值及覆盖策略；列重排按名称对齐，每行必须有真实 ok/error/missing 等状态。require_all 缺任一 allowlist 模型即无法判定；renormalize 只重归一化成功模型的正权重，没有正权重返回 -1/NaN，不返回良性。
- 旧集成使用已保存权重（无权重才等权）、identity、阈值 0.5 和显式 renormalize。非法/全零权重拒绝。缺失/失败 0.5 原始占位仍为兼容 raw predict_all 保留，**不能不带状态聚合**：使用 predict_all(return_status=True) → ensemble_predict(..., statuses=states) 或 decide。
- 固定策略通过 set_decision_policy 安装并随 ensemble.save/load 保存；有固定策略时拒绝临时 DSIR 权重替换。研究候选默认 require_all，不能把 fast/full/降级重归一化后的分数当成已经独立校准。identity 与预拟合单调 platt_logit 参数可执行，但没有拟合新的概率校准器。
- 主 Web 单样本、production/development 共用批量管线和旧批量兼容包装器均委托同一格式器。阈值、calibrator、allowlist 与权重实际决定 Score/IsMalicious；低/中/高命名只用于旧展示档位，服从策略判定但尚未重新校准。缺模型的 SDD 不接收占位列，诊断标记 unavailable；不得视为没有漂移的证据。
- train/retrain_selection 与 runtime 共用聚合/比较；新 decision_candidate v2 绑定完整策略和指纹，verified_manifest 校验与 model_val 权重及 calibration 阈值语义一致。旧研究 v1 仍可完整性复验，不能发布。trained_models.pkl 仍是 deployable=false 的非运行时 schema。
- train/run_all 的三个集成调用已要求真实状态；旧月份缓存没有状态时重新推断。四个数组由 checksum-bound 最终指针验证并串行发布，缓存仅限当前 ensemble 实例/调用作用域，不宣称解决旧月份数据身份、SDD 校准或模型输入契约。

本阶段新增 43 项合成策略/适配器/候选/缓存/张量接口回归，总计 139 项重训回归通过，旧响应投影 7 项通过。真实 HTTP/ASGI 测试因缺少 torch（以及 fastapi/httpx 等依赖）未运行成功；没有安装依赖、正式训练、替换生产权重、部署、提交或建分支。

下一项 P0：环境无关的完整模型输入/预处理/序列化契约、候选运行时产物发布，以及冻结后只读 test 的独立统计验收。样本路径与 SMDA native 依赖问题仍待解决。详情：[决策层实施记录](../../retrain/RETRAIN_DECISION_POLICY_P0_2026-11-13.md)。
