# 说明文档索引

核对日期：**2026-11-11**。以当前工作区代码、配置、启动脚本和 CLI 参数为准。本次覆盖仓库已跟踪的 24 份 Markdown 说明，另新增本索引；不修改论文 PDF、第三方依赖文档、日志或 JSON 测试证据。

## 1. 当前操作指南

| 文档 | 用途 |
|---|---|
| [仓库 README](../../README.md) | Web 全栈开发/生产启动、检测队列及后端接口 |
| [CoDefenderC3 README](../README.md) | 模型组件入口与目录导航 |
| [模型服务 README](README.md) | 共享监听、依赖、生产/开发启动、响应协议及管理接口 |
| [TESTING](TESTING.md) | 单元回归、真实 PE 验证、HTTP 检查及验收边界 |
| [Docker 测试脚本](DOCKER_TEST_SCRIPTS_USAGE.md) | 构建前检查、冒烟测试范围及脚本已知限制 |
| [SMDA 后端](SMDA_BACKEND.md) | 默认后端、CPU/GPU 镜像、超时和缓存 |
| [Binary Ninja 指南](BINARYNINJA_OPTIMIZATION_GUIDE.md) | 显式启用 BN、授权与真实可用配置 |
| [开发响应字段](DEV_RESPONSE_FIELDS.md) | 开发投影裁剪项与诊断字段语义 |
| [IR 契约](IR_CONTRACT.md) | 默认关闭的候选 D/E 特征、schema、缓存及验收要求 |
| [模型与参考材料](PAPERS.md) | 当前 33 模型 / 15 视图、候选状态和代码/PDF 入口 |
| [论文目录入口](../papers/PAPERS.md) | 指向唯一维护的模型参考页，避免重复漂移 |
| [训练指南](../train/README.md) | 已实现的数据构建、训练、续跑和产物验证 |
| [签名库验证](testing_hash.md) | Web 数据库与引擎签名库区别、预检/更新及写库风险 |
| [签名库快速检查](testing_hash_simple.md) | 只读排查入口；完整操作以签名库指南为准 |

## 2. 训练现状与规划

| 文档 | 定位 |
|---|---|
| [增量训练与 Checkpoint](增量训练与Checkpoint技术方案.md) | 已实现/未实现能力矩阵；不将设计伪代码当作可执行 CLI |
| [2026 重训计划](../train/RETRAIN_2026_PLAN.md) | 当前工具链、验收门槛和后续工作；不是“已完成全部重训”的报告 |

`train_incremental.py`、`ingest_new_samples.py`、`train_malgraph.py` 等规划中的命令目前不存在。`--resume` 复用已完成模型产物，不代表恢复某个 epoch 的优化器/RNG 状态。训练结果验证、质量评估和在线发布是不同阶段。

## 3. 历史记录（保留证据，不作为当前操作说明）

| 文档 | 原始记录范围 |
|---|---|
| [2026-11-10 清理与回迁](CLEANUP_AND_RELOCATION_2026-11-10.md) | 指定旧目录的回迁状态与步骤 |
| [2026-11-10 合并实施](MERGE_IMPLEMENTATION_2026-11-10.md) | main / test_lm 的基线、取舍与回归证据 |
| [合并版详细 README](README_DETAILED_MERGED_2026-11-10.md) | 当时完整说明的存档 |
| [合并版组件 README](README_MERGED_2026-11-10.md) | 当时组件入口的存档 |
| [合并版训练 README](README_TRAIN_MERGED_2026-11-10.md) | 当时训练说明的存档 |
| [2026-11-10 SMDA 运行验证](SMDA_RUNTIME_VALIDATION_2026-11-10.md) | 当时工作区与样本的运行结果 |
| [test_lm 分支分析](TEST_LM_BRANCH_ANALYSIS.md) | 指定提交的分支对比，不代表当前全部接入 |
| [2026-10-14 Docker 脚本测试](TEST_RECORD_2026-10-14.md) | 指定旧环境/服务/权重的测试记录 |

以上 8 份原始正文保持不变，新增历史提示。`historical-snapshot` 注释之后的旧命令、路径、链接和统计按历史快照保留；应按记录中的版本复核，不能直接套用当前环境。本次不将历史数据改写成新结果，也不覆盖 `docs/test-records/` 中的证据。

## 4. 维护与核对规则

- **启动看入口代码**：[engine/serve.py](../engine/serve.py) + [startup.py](../engine/startup.py)。共享启动默认 SMDA；Web/生产/开发三种协议共享一个模型进程。开发入口需单独启用，环境档位不能代替协议选择。
- **返回看投影和策略**：[生产投影](../engine/projection.py)、[开发投影](../engine/dev/projection.py)、[预测策略](../engine/prediction_policy.py)。现有 Web 必须连接 Web 兼容入口，不能直接换为生产精简接口。
- **接口看路由**：[模型 API](../engine/app.py)、[Web 后端](../../web/FastAPI/main.py)。区分上传、任务轮询与最终报告；HTTP 成功不等于模型/数据库全部成功。
- **模型看部署而非目录数量**：[config.py](../config.py)、[model_registry.py](../model_registry.py)、[装载代码](../models/ensemble.py)及 `/model-info`。配置中的 V11 候选不计入当前默认部署。
- **训练看现有 CLI**：[build_minimal_dataset.py](../train/build_minimal_dataset.py)、[train_all.py](../train/train_all.py)、[verify_trained_ensemble.py](../train/verify_trained_ensemble.py)。结构验证不能代替模型质量或生产验收。
- 本次为代码/文档一致性核对及文档静态检查，不是重新执行全接口、全量训练、Docker 生产部署或真实后端差分的验收报告。运行验证流程见 [TESTING](TESTING.md)。
