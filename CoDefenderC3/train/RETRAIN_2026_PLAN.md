# 重训计划与当前前置条件

核对日期：2026-11-11。本文是**计划**，不是已完成训练/质量验收报告；历史实验数字、外部机器路径和仓库中不存在的评估 CLI 不作为当前操作指南。

## 1. 当前实现

- 当前部署 33 模型 / 15 视图；配置/注册表还保留 V11 候选，是否加载以实际 ensemble 为准。
- 训练和共享启动默认 SMDA，BN 显式可选；候选 ProgramIR 默认关闭、MalGraph 独立特殊管线。
- 支持 full/fast 数据集、逐模型 scratch/finetune、模型筛选与完成级 checkpoint 恢复。
- NumPy 模型没有通用 warm_start；MalGraph 不由通用 train_all 重训。输出保留旧槽位不代表全部模型新训练。
- 离线 AUC 加权/阈值扫描与当前在线有效模型等权均值、严格 > 0.5 的判定是两条路径，不能直接把离线策略宣称已上线。

## 2. 重训前门禁

| 门禁 | 必须核对 |
|---|---|
| 数据 | 来源、合法用途、可信标签、真实采集时间、类配比、SHA256 去重/标签冲突 |
| 切分 | 时间或家族/来源隔离；合成月份不等于真实时间外推 |
| 特征 | 同后端/版本/哈希及命名口径；覆盖、失败、维度和缓存 schema |
| 基线 | 保存 ensemble、MalGraph 权重/词表、代码版本与内容指纹 |
| 训练 | trainable/frozen/passthrough、实际 warm_started、参数、种子、设备 |
| 评估 | 独立留出集 FPR/召回/AUC、覆盖率和退化；不能只看训练 loss |
| 发布 | 真实接口协议/模型覆盖、超时资源、备份和可回滚路径 |

## 3. 建议执行顺序

1. 小规模可信 PE 演练数据构建和完整特征，先看 manifest 和覆盖诊断。
2. 按模型族分批训练，验证特征变化对旧权重及实际质量的影响。
3. 对缺视图冻结模型与 special 模型单独标记，不把它们混入“本轮训练成功率”。
4. 扩展至独立真实时间留出集，检查跨集合污染和良性构成变化。
5. 先以当前线上聚合口径复验；权重/阈值迁移需要单独实现、版本化和重新标定。
6. 独立模型服务做真实 HTTP、全 D/E、资源和超时验收，再显式发布，保留基线。

## 4. 可执行入口

从 `CoDefenderC3/` 执行，下面只预演；完整运行见 [训练指南](README.md)：

```bash
python train/build_minimal_dataset.py --source /data/pe-source --out /data/pe-dataset \
  --baseline ensemble.pkl --views full --months 4 --train-months 2 --dry-run
python train/train_all.py --dataset /data/pe-dataset --baseline ensemble.pkl \
  --models OpcodeStatNet,OpcodeLSTM,OpcodeTransformer,AsmEmbedNet \
  --mode scratch --run-id retrain-opcode-new --dry-run
```

后续实际训练使用新 run-id；断点恢复需 `--resume` 且不变更数据/参数。结构验收用 `verify_trained_ensemble.py`，真实 PE/协议验收见 [TESTING](../docs/TESTING.md)。

## 5. 未完成的设计项

- 通用 NumPy 增量接口、自动 replay/遗忘门禁与版本账本。
- MalGraph 通用训练接线及其外部产物协同发布。
- 在线权重/阈值/模型排除策略的统一版本契约；不要使用不存在的 `CODEFENDER_EXCLUDE_MODELS` 开关假装该功能已实现。
- 图模型真实拓扑与现行统计特征适配的独立质量评估；GNN 类名不证明所有入口均消费真实 CFG。
- GPU、BN/SMDA 后端互换和长期时间漂移评测需另做真实环境验收。

相关：[增量/Checkpoint 边界](../docs/增量训练与Checkpoint技术方案.md)、[模型材料](../docs/PAPERS.md)、[IR 契约](../docs/IR_CONTRACT.md)。
