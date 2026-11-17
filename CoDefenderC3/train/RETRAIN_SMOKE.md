# 真实 PE 小规模训练测试

该入口用于确认 **真实 PE → 版本化特征缓存 → fit → 保存 → 恢复 → 独立测试**，不是全量重训或生产发布入口。

## 前提与模型范围

- Python + NumPy；不安装或伪造 torch/SMDA 依赖。
- 使用现有 NatarajKNN（k=5）及 V2_byte_stat 的 B02/B03/B04/B05，共 776 维。
- 使用受审计的 fast 子进程 worker，冻结源码、包版本与数据指纹。
- 旧注册表加载 NumPy 模型也会导入 torch；本入口通过显式冻结的真实模型适配器，复用严格训练／恢复／预测方法。
- 未覆盖神经网络、反汇编、图及专用模型；不读取或替换生产 ensemble.pkl。

## 数据规则

源目录包含 benign/、malicious/；递归、固定 seed 选样。核验 PE 头、大小、内容 SHA256 与哈希文件名。非 PE 不会伪装成 PE；不执行、不解包样本。

良性存在 manifest.csv 时继承可用的 exact ssdeep，同 SHA256 或同 exact ssdeep 只保留一份。**这不是近重复／家族／软件版本谱系隔离**；目录及清单标签没有独立复核。

恶意 YYYY-MM-DD 目录只表示收集日期，**不是确认的首次出现时间**；良性不补造出现日期。本入口仅支持单收集月的分层随机 smoke，不得称为时间外推。

每类按 60% / 15% / 10% / 剩余分配：1000 对应 600/150/100/150，909 对应 545/136/90/138。

| 角色 | 用途 |
|---|---|
| train | fit |
| model_val | 外部验证、锁定模型权重 |
| calibration | 预声明网格上选择 F1 阈值，不是低 FPR 约束 |
| test | 仅模型与阈值冻结后访问；不参与选择 |

## 启动（从 CoDefenderC3 目录）

```powershell
python -X utf8 train/run_retrain_smoke.py --source-root "E:\nkproject\02 训练集" --output "..\outputs\retrain-real-pe-smoke-1000x2" --count-per-class 1000 --seed 20261116
```

数量不足会明确失败，并写 selection_audit.json（已选数量、拒绝原因）；绝不复制样本凑数或静默降采样。若需较小规模，明确修改 --count-per-class，并使用新的输出目录。

完成数据准备后可用相同参数加 --resume 恢复；核对选样、入口源码、特征、包版本、参数和候选指纹。test 保持选择隔离，完成候选不会用 test 重训。准备阶段中断且没有 prepared.json 时应使用新的输出目录。

## 输出

- selection_audit.json、selection_manifest.csv、split_plan.json：可复现选样及限制。
- path_verification/：逐样本 PE / SHA256 / 大小复核。
- dataset/：隔离副本、四角色元数据及特征契约。
- runtime.json：短路径缓存位置、实际 Python/NumPy 环境；缓存默认放在 output 的同级 sc-<id>/，避免 Windows 临时文件名超过 MAX_PATH，可用 --cache-dir 指定。
- features_<role>.json、preflight.json：覆盖率与预检证据。
- runs/nataraj_cpu/：完整性校验的研究候选、冻结策略及模型输入契约。
- evaluation.json、test_predictions.csv：独立测试指标与逐样本预测。

**deployable=false**：研究候选不是旧版或生产可直接 reload 的 ensemble.pkl。
保存恢复只对本机生成并先校验 SHA256 的可信 pickle 执行；不能读取未知来源 pickle。

## 回归测试

```powershell
python -X utf8 -m unittest discover -s tests -p "test_retrain*.py" -v
```

测试内的 PE 是合成夹具，不替代真实数据训练记录。
