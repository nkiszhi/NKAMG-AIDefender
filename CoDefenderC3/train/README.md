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
| `_fix_de_gap.py`、`_drain_bndb_to_de.py` | BN 专用修复；不适用于 SMDA 缓存 |

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

### 3.3 训练

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
- `--weighting equal/auc`、`--threshold-grid` 用于离线训练/评估，**不会让当前在线生产/开发聚合自动使用这些权重或扫描阈值**。在线路径当前为有效模型等权均值，严格 > 0.5。

### 3.4 产物与复验

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
python train/_fix_de_gap.py /data/pe-dataset --dry-run
python train/build_flat_dataset_meta.py --data-dir /data/existing-dataset --dry-run
```

先诊断失败日志、样本路径、实际 NPZ 和月度缓存。不要为“重新跑一遍”批量删除源样本/整个缓存；调整标签、月份或特征口径后旧月度缓存可能失效。平铺元数据工具的 `--purge-per-month` 会归档旧目录，只有确认目标后使用。

## 5. 发布与长期计划

- 发布须验证基线/候选可追溯性、未知键保留、实际模型覆盖和真实质量；备份当前模型与外部 MalGraph 产物。
- `POST /reload-model?model_path=...` 只接受服务端可访问文件。宿主路径不能直接作为容器路径；换镜像内产物应重建镜像/容器。
- `reload-model` 影响共享监听器；标准生产配置不依赖 dev 的运行时覆盖文件。
- GPU `train` Docker target 是纯模型推理/离线基础镜像，当前不 COPY 训练目录，不能当作已经准备好的训练环境。

专题：[增量与 Checkpoint 边界](../docs/增量训练与Checkpoint技术方案.md)、[重训计划](RETRAIN_2026_PLAN.md)、[IR 契约](../docs/IR_CONTRACT.md)。
