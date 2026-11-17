# P0：四角色训练入口、隔离校准与严格恢复

日期：2026-11-13（Asia/Shanghai）。承接 R0 和 split/cache P0，完成 train_all 的 opt-in 接线与合成回归，**不是正式训练或上线批准**。

## 1. 交付范围

源码根目录：`D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/`。

| 文件 | 作用 |
|---|---|
| retrain_training.py | 全量 train 拟合、外部 model_val 检查/早停、严格 warm state |
| retrain_selection.py | ID 对齐后的有限概率、精确 AUC、model_val 权重与 calibration 阈值选择 |
| retrain_run.py | 角色/覆盖门禁、运行身份、checkpoint、发布完整性和严格模型适配 |
| train_all.py | 新增 --split-aware / --feature-contract / --split-cache-dir，保留旧月份入口 |

回归源码：`D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/tests/test_retrain_training.py`。

## 2. 数据角色与模型门禁

1. 新分支仅接受显式模型 allowlist 和冻结 FeatureContract；特殊/未知模型、重复名称、不兼容 view dtype 拒绝。模型实际构造 kwargs 与源码哈希保存到 run identity 和产物。
2. get_split 只读已提取的原始缓存，默认要求全覆盖；runner 再核对请求/纳入 IDs、原始分母、标签、view shape/dtype 及 feature/view/matrix 指纹。train/model_val 不完整时，在任何拟合前停止。
3. PyTorch 所有 train 行逐 batch 参与每轮拟合，包括尾 batch；不划内部随机验证集。仅外部 model_val 用于早停，恢复其最佳 state，有限损失门禁生效。输入转 tensor 以 batch 为单位，不一次复制巨大 mmap。
4. NumPy 模型仅向 fit 传递所有 train 行；model_val 只做拟合后评分/选择，不能声称有基于 model_val 的 NumPy 早停。现有 DrebinLinear 自带的训练集 Platt 拟合不等于隔离 calibration 上的概率校准。
5. NumPy finetune 明确拒绝。PyTorch finetune 使用严格 state_dict 加载，不兼容即失败，不静默改为 scratch。
6. 每个显式模型都必须拟合成功，报告 train/model_val 行数与外部验证来源，并给出准确 ID 顺序的有限 [0,1] 概率。即使其最终权重为 0，也不跳过失败检查。二类 NumPy 概率要求两列、有限且和为 1；torch 输出宽度受 BCE/CE 契约约束。
7. 不使用 legacy predict_all 的常量填充、不继承冻结失败模型，也不混入 allowlist 以外的模型。新训练和恢复的选择评分统一 CPU；GPU 仅在显式 --device cuda 的训练循环使用，--device auto 在新分支为 CPU。

loader 会审计公共四角色清单/元数据，包括 test 的身份与角色约束；runner **不获取 test 特征或模型预测，不将 test 用于拟合、权重、阈值或质量选择**。本项没有独立 test 评估器。

## 3. 权重与校准隔离

- 权重只能在 model_val 上选择。equal 为等权；auc 为 max(AUC-0.5,0) 的平方并归一化。全部为 0 时显式记录等权回退，不是模型训练失败回退。
- 每个模型完成且 model_val 概率通过验证后，写入 locked_weights.json，再首次获取 calibration 的模型输入/评分 batch。
- calibration 不再调模型或权重，只从运行开始前声明的 threshold_grid 选择阈值。固定 tie break：F1 更高、FP 更少、阈值更高；比较器为严格 scores > threshold。
- 当前 calibrator=identity，probability_fit_performed=false；这是**阈值调优，不是概率校准或低 FPR 认证**。阈值调优后的 calibration 指标不作为独立泛化/上线验收。
- calibration 覆盖失败没有完成发布；恢复时其矩阵身份变化拒绝，不能重用原 run-id 将 calibration 悄悄换掉。

## 4. checkpoint 与恢复边界

运行身份绑定：冻结特征/view 契约、清单/计划/路径审计哈希、train/model_val 行与矩阵快照、模型 allowlist/spec/源码、基线哈希、后端运行时、全部训练/选择参数，以及 training/loader/cache/contract 关键源码字节组合哈希。不是只看 Git HEAD 或 run-id。

- 每 run-id 跨进程锁；checkpoint 与进度原子写入。
- 完成模型的 checkpoint 含 schema、run_fingerprint、model_name、info、payload。只有拟合和 model_val 评分均通过，才记 status=ok。
- resume 要求身份完全一致、完整有效 progress、已完成 checkpoint 的 checksum/status/info 一致；不重写有效 checkpoint 字节，只重训明确 failed 或尚未开始的模型。
- checkpoint_invalid 或未知状态拒绝继续；缺失 progress 不推断为 scratch。修复损坏/改变契约或参数须新 run-id。
- 恢复成功会清除过时失败字段。恢复时的训练/选择/校准失败更新 progress，使旧完整性指针不再通过验证。
- 恢复单位是**完成模型**，不是模型内部 epoch、优化器或 RNG 状态；本项不提供精确中途续训。
- 禁止输出进入数据目录或覆盖基线；拒绝路径回迁、Windows 保留名、run-owned 文件/partial/lock 的 symlink 或 junction 别名。路径检查不是对可并发恶意写入者的完整 TOCTOU 防护。

## 5. 研究产物与完整性

输出树（绝对根示例：`D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/runs/<new-run-id>/`）：

```text
run_identity.json
partial/<model>.pkl
progress.json
locked_weights.json
calibration_identity.json
trained_models.pkl
decision_candidate.json
manifest.json
complete.json
```

trained_models.pkl 使用 `retrain-training-artifact-v1`，并非 legacy ensemble.pkl schema。包含 trained_models/model_specs/decision_candidate，**deployable=false**；实际 legacy MultiModelEnsemble.load 的拒绝行为已合成测试。没有生成或替换生产 ensemble.pkl。

complete.json 最后发布，绑定 manifest、模型包、progress、decision_candidate、locked_weights、run_identity 和 calibration_identity 的哈希。仅存在模型包或 complete.json 不能证明成功；应调用 `train.retrain_run.verified_manifest(run_dir)`。该函数不 unpickle 模型包，检查完整性、身份和决策/角色一致性。最终指针写入失败后，残留文件保持未完成，不能作为完成候选。

pickle 仅用于受信任的本地 checkpoint/研究产物；禁止把不可信外部 pickle 作为恢复输入。SHA 是一致性校验，**不是签名或认证信任根**，保护源码/清单/契约/缓存/run 目录的写权限仍是前提。

## 6. 使用与预检

以下只展示入口，不表示当前环境/真实数据已准备好。不要删除 --dry-run 来直接正式开训。

```powershell
python "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py" `
  --dataset "D:/retrain-materialized" `
  --split-aware --feature-contract "D:/retrain-materialized/feature_contract.json" `
  --split-cache-dir "D:/retrain-cache" `
  --baseline "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/ensemble.pkl" `
  --models MalConv --mode scratch --device cpu `
  --run-dir "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/runs" `
  --run-id split-preflight-new --epochs 20 --patience 3 --seed 42 `
  --weighting auc --threshold-grid 0.3,0.5,0.7 --dry-run
```

路径和模型均为示例，应匹配实际已核验物化目录、批准的 view/模型组合及冻结契约。deep Windows 路径在本机原子缓存 tempfile 写入时触发传统路径长度限制；合成证据改用显式短 cache_dir 后通过。没有启用系统 long-path 设置或实现通用长路径支持。

- dry-run 只预检 train/model_val，不触发拟合、calibration/test batch、run 目录写入；可能生成派生 mmap 矩阵缓存，并加载受信任基线以核对模型映射。因此当前缺 torch/sklearn 的环境不能据此声称真实后端可运行。
- split 分支拒绝旧 --source/--out/--per-class/--mal-ratio/--months/--train-months/--views/--allow-partial-de/--link/--force，以及旧 preserve-extra-keys 和 --in-place 参数；它们不能改变显式角色或研究 schema。
- 默认 month-only 路径保留原行为；没有 --split-aware 时仍拒绝四角色数据。旧 finetune/frozen/ensemble.pkl 规则不适用于新分支。

## 7. 验证结果与证据

重训回归 **96 项通过，无跳过**：R0 21、split/cache 37、本项 38。覆盖角色隔离、全量行训练、外部验证、best-state 恢复、有限损失、严格 warm state、权重先锁定、缺失/错位概率、覆盖、失败恢复、损坏 checkpoint、参数/契约/后端变化、原子发布失败、发布文件哈希、路径别名及旧入口回归。

- PyTorch 控制流程使用注入 torch/nn stub，不运行真实 torch、梯度、native kernel 或 GPU；目录 junction 逃逸为注入 resolve 测试，不是原生 junction 兼容认证。
- 实际 dependency-light DrebinLinear 在 4 行 train / 2 行 model_val 的合成矩阵上进行了 2 epoch 微型测试；不含正式 PE 模型训练或质量评估。
- 持久化合成 smoke 使用 10 条最小 PE 头 fixture + 假特征 builder + FakeBackend，主动移除 test 样本文件后仍可训练编排/恢复验证。FakeBackend 使用合成标签造分数，仅验证路由，不证明检测性能。不得部署其模型包。
- CLI --help、Python 语法与 git diff --check 通过；Git 的 CRLF 提示不是 whitespace 错误。
- 合成 smoke 初始导入路径错误和长缓存路径错误日志均保留，最终成功结果另存；失败尝试不计成功。

证据目录：`D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/p0-split-training/`。
测试记录：`D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_split_training_p0_2026-11-13.json`。

## 8. 尚未解决的正式训练/部署条件

1. R0 所选 24,904 个真实样本仍未通过已有 manifest 路径定位；需要实际样本根或 path map。这不证明整台机器上不存在样本。未物化真实数据集，未重新跑大规模采样。
2. bundled Python 缺 torch/sklearn；SMDA 的 LIEF native DLL 导入仍失败。没有安装/升级依赖，也没有成功的真实 PE D/E 或生产后端验证。
3. 未审计 A/C/F/G/H 与 E01/E02 图拓扑，当前 adapter 不是全 33 模型特征入口。模型构造/序列化的完整输入语义和环境脱钩预处理契约仍待下一项 P0。
4. 离线与 HTTP 共享 DecisionPolicy 尚未接线，当前在线系统不会自动使用本研究包的 weights/threshold/calibrator；本项未改变 HTTP 路由/决策、生产模型或部署配置。
5. 独立 test / 大规模良性低 FPR 验收尚未实施；当前 calibration 仅阈值选择，不宣称低误报改善。

下一 P0：共享离线/HTTP DecisionPolicy，然后完善模型输入/序列化契约与独立验收。未启动正式训练、未改生产权重、未 commit/建分支。
