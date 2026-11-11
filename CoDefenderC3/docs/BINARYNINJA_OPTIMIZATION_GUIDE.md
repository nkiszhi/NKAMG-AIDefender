# BinaryNinja 接入与调优

核对日期：2026-11-11。本文件仅说明当前代码中的 BN 路径；不保留未经当前样本验证的速度倍数、固定吞吐或“已实施”伪代码。默认共享/训练启动使用 SMDA，见 [SMDA 后端](SMDA_BACKEND.md)。

## 1. 使用前提

- 显式设置 `CODEFENDER_DISASM_BACKEND=bn`，使用有效的 BinaryNinja 安装、Python API 和支持当前调用方式的许可证。
- 共享启动通过 `engine.startup` 选择后端；缺依赖/授权不能认为已自动切换 SMDA。
- 原始 PE 仅静态分析，不能通过执行待检文件来验证分析效果。

本机 Python/授权发现逻辑见 `feature_extraction/bn_runtime.py`，可使用 `CODEFENDER_BN_PYTHON_DIR`、`CODEFENDER_BN_LICENSE` 指定路径。容器脚本另有 `/opt/binaryninja` 和许可证初始化逻辑，二者不要混用成固定的本机路径。

## 2. 模型覆盖

当前部署有 10 个 D/E 相关模型：OpcodeLSTM、OpcodeTransformer、OpcodeStatNet、AsmEmbedNet、MalGraph、CFGGAT、CFGGCN、CFGDGCNN、CallGraphGNN、GraphStatNet。

`include_de=false` 只跳过 D/E 依赖，不是跳过所有图像特征，更不是“只剩 18 个模型”。`include_de=true` 也不保证全模型成功，需检查模型覆盖与排除原因。

```bash
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@sample.exe"
```

## 3. 当前分析配置

线上隔离 worker 的 `load_analysis_view` 使用：

| 选项 | 当前值 | 原因/限制 |
|---|---|---|
| `analysis.mode` | `intermediate` | MalGraph 读取 MLIL，不能盲目降到 basic/仅 LLIL |
| `analysis.linearSweep.autorun` | `true` | 当前函数发现口径的一部分 |
| `analysis.limits.maxFunctionSize` | `262144` | 限制大型函数分析 |
| `BN_WORKER_THREADS` | 特征提取路径默认 8 | BN 内部线程；不等于 HTTP 并发扫描数 |

配置来自 `engine/analysis_worker.py` 与 `feature_extraction/extract_feature.py`。改分析级别、线性扫描或函数限制会改变特征与覆盖，不能仅以速度判断正确性。

## 4. 超时、缓存和并发

- 线上使用隔离分析预算、请求预算和硬超时；硬超时可能结束整个共享模型进程，由 Supervisor 恢复。
- BN 训练默认采用 PE → bndb → D/E 两阶段，保留 bndb 会增加磁盘占用；SMDA 和候选 IR 使用不同缓存路径。
- 不把旧 bndb/NPZ 文件存在当作特征成功，需校验完成记录与真实有效特征。
- `BN_BATCH_WORKERS` / `BN_BATCH_SIZE` 不是本指南核对到的现行配置接口，旧指南的示例不应继续用于部署。
- 调整 `BN_WORKER_THREADS`、训练提取 worker、HTTP 扫描容量时分开记录。线程越多不保证越快，需监控 CPU、内存和实际样本耗时。

## 5. 训练诊断与实验工具

命令从 `CoDefenderC3/` 执行：

```bash
python train/_probe_de_coverage.py /data/dataset
python train/_fix_de_gap.py /data/dataset --dry-run
python train/benchmark_bn_optimization.py
```

`_fix_de_gap.py`、`_drain_bndb_to_de.py` 是 BN 专用修复工具，不用于 SMDA 缓存。前者不加 `--dry-run` 会改文件；只有确认目标路径、备份和原因后才运行写操作。

`apply_bn_optimizations.py` 是旧 BN 实验辅助脚本，不是标准启动前置步骤；运行前阅读代码，不能把它生成的参数视为生产默认或当前性能验收。

## 6. 验证要求

在同一组静态 PE、权重、特征口径和设备下比较；记录成功/跳过/超时模型数，以及 P50/P95/最大耗时。开发返回不含逐模型明细时使用 `PerModelScores`、`ModelStats.ExcludedModels`，必要的内部图诊断查看独立验证工具。不得拿历史单样本数字作当前环境保证。
