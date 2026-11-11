# 增量训练与 Checkpoint：当前能力及设计边界

核对日期：2026-11-11。本文取代旧的长篇伪代码/机器路径说明：明确哪些已有实现、哪些仍是设计，不把计划中的 CLI 当作现成功能。实际操作以 [训练指南](../train/README.md) 为准。

## 1. 已实现与未实现

| 能力 | 当前状态/代码依据 |
|---|---|
| 分类 PE 数据集构建 | `train/build_minimal_dataset.py`；有配比、合成月份、D/E 门禁和 manifest |
| 已有数据集/一条龙训练 | `train/train_all.py`，筛选模型、scratch/finetune |
| 逐模型 checkpoint | `partial/<model>.pkl`，临时文件写完后原子替换；`progress.json` |
| 恢复已完成模型 | 相同 run-id 加 `--resume`；不是 epoch 内优化器恢复 |
| PyTorch 微调 | 尝试 state_dict 热启动；兼容性失败可回退 scratch，检查记录 |
| NumPy 通用 warm_start | **未实现**；现行 fit 重训，即使 mode 为 finetune 也不复用旧训练状态 |
| 缺视图模型 | 基线冻结继承，不置零删除；需看 frozen 清单 |
| MalGraph 通用重训 | **未接入**；保留 special 占位、外部权重和词表 |
| 未知 schema 键透传 | 默认保留，验证候选时检查；可显式关闭但不建议 |
| 在线重载 | 内部 `/reload-model`；重载影响所有共享入口 |
| 自动增量摄入/回放池/质量门禁/账本发布 | **未提供完整自动链路**，需另行设计实现 |

`train_incremental.py`、`ingest_new_samples.py`、`train_malgraph.py`、自动 ledger/publish 接口均不是当前说明可直接执行的命令。现有 `experiments/` 和 SDD/LLM 模块也不代表在线会自动重训或自动发布。

## 2. 两类状态不能混淆

### 训练进度

`partial/` 保存已经完成的单模型序列化结果，`progress.json` 保存 done 状态。中途终止某一模型可能需从该模型重新训练，不承诺恢复 mini-batch、优化器、随机数和早停状态。

恢复时保持数据集、基线、特征口径、参数和 run-id 一致。脚本没有替代运维做完整的数据指纹一致性门禁；不能换数据后仅凭 `--resume` 宣称同一实验可复现。

### 候选版本

`runs/<run-id>/ensemble.pkl` + `manifest.json` 是候选产物，不是线上 active 指针。当前在线权重更新须显式执行发布/重载，不能把“训练完成”理解为自动上线。

## 3. 最小安全操作

命令从 `CoDefenderC3/` 执行：

```bash
python train/build_minimal_dataset.py --source /data/pe-source --out /data/pe-dataset \
  --baseline ensemble.pkl --views full --months 4 --train-months 2 --dry-run
python train/train_all.py --dataset /data/pe-dataset --baseline ensemble.pkl \
  --mode finetune --device cpu --run-id incremental-new --dry-run
# 数据集已构建并通过覆盖检查后，去掉训练 dry-run
python train/train_all.py --dataset /data/pe-dataset --baseline ensemble.pkl \
  --mode finetune --device cpu --run-id incremental-new
python train/verify_trained_ensemble.py --baseline ensemble.pkl \
  --candidate runs/incremental-new/ensemble.pkl
```

第一条只是构建预演，不会生成可训练数据集。完整构建/恢复命令见 [训练指南](../train/README.md#3-标准工作流)。复验工具的结构通过不等于模型质量或线上特征兼容通过。

## 4. 特征与聚合约束

- SMDA/BN 或哈希编码改变后需重建相关特征并验证旧权重；维度匹配不保证数值映射相同。
- 当前生产/开发 HTTP 聚合仅使用成功模型的等权均值、严格 `> 0.5`；`--weighting auc` 的训练评估结果不自动接入该在线路径。
- 缺模型、未执行漂移分析、哈希短路、超时必须显式区分，不用 0.5 占位分数宣称模型成功。
- 合成月份桶只适合流程演练；真实时间外推必须有真实来源时间及跨集合 SHA256/家族污染检查。
- MalGraph 产物的 checkpoint、词表与解析口径独立于通用 ensemble 槽位；不能仅替换 ensemble 即认为它已重训。

## 5. 后续设计建议（尚未自动化）

1. 数据摄入保留来源、标签、真实时间与内容指纹，跨训练/验证/测试去重并处理标签冲突。
2. 引入回放/遗忘评估时记录策略和采样，不能依赖在线无标签数据静默自训练。
3. 增量模型支持按类型实现，不伪装 NumPy warm_start；MalGraph 接入需独立数据适配、训练与质量门禁。
4. 版本 manifest 记录数据/代码/特征 schema、权重、词表、设备、基线及真实指标；发布需人工审批或可验证门禁。
5. 阈值/权重部署使用明确版本契约，不用改文档替代未实现的在线接线。

## 6. 回滚与验证

保留当前可用模型和外部产物。候选先在独立服务上做结构、真实 PE、留出集和资源/超时验证，再发布。可用内部重载指向已验证旧模型，但该路径必须在服务端可访问，且会影响全部共享入口；镜像内代码/产物更新或回滚需重建对应容器。

禁止为了恢复训练删除源样本/用户整套缓存、改写历史测试结果或把良性样本注入线上恶意签名库。签名发布与模型发布是独立状态管理，详见 [签名库指南](testing_hash.md)。
