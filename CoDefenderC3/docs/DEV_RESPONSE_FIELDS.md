# 开发接口返回字段

核对日期：2026-11-11。当前开发入口为 `engine.dev.app:app`；共享启动用 `CODEFENDER_ENABLE_DEV_API=1` 开启，默认监听 `127.0.0.1:18002`。

**入口决定协议，环境决定配置**：仅把生产入口的 `CODEFENDER_ENV` 改为 dev，不会得到开发响应。启动和完整对照见 [README](README.md#4-接口返回数据差异)。

## 1. 生效范围

只对开发 `POST /predict-single`、`POST /predict-directory` 的 HTTP 返回边界裁剪，复制响应层级而非原地修改共享证据。

| 被移除的完整字段路径 | 当前行为 |
|---|---|
| `ScanResult.PerModelPreds` | 删除，不返回 null；逐模型判定当前为 `score > 0.5` |
| `ScanResult.PerModelDetails` | 删除；不再提供内部图诊断和逐模型结构化明细 |
| `ScanResult.ModelStats.AggregatedModels` | 删除；成功参与名单使用 `PerModelScores` 的键 |

生产投影和 Web 完整/流式协议不受该裁剪影响；管理、模型信息和探针沿用共享契约。开发/生产入口均不提供 `/predict-stream`，Web 入口才提供。

## 2. 保留与解释

- 标识及文件信息：MD5、SHA256、CRC32、FileName、FileSize；目录项另有 FilePath。
- 判定：IsMalicious、Score、Status、StatusLabel；VirusName 与生产命名一致。Score 是聚合分数，不保证已校准为概率。
- 分析：Packed、PerModelScores、DriftEvidence、SampleDriftType、AnomalyScore、IsDriftCandidate，以及按检测路径提供的哈希来源/命中诊断。
- 模型统计：TotalModels、OkModels、SkippedModels、ErrorModels、ExcludedModels、AggregationMethod、DecisionThreshold、投票与分数概览等；字段以路径实际输出为准。
- 目录：Summary / Results，保留计数、目录和耗时。ErrorCount 不含 TimeoutCount，失败总数需合计二者。

这些字段不是所有检测路径必有的统一全集。哈希短路可能不执行模型；缺少模型分数不能推断为“所有模型失败”。单文件不返回上传临时路径。失败目录项不能因 IsMalicious=false 被归入良性。

## 3. 当前语义边界

1. 成功模型按注册顺序聚合，当前生产/开发数值管线使用等权均值、严格 `> 0.5` 判恶意；不是多数票，也不会自动采用训练产物中的 AUC 权重。
2. `ModelStats.EnsembleScore` 为舍入后的重复展示值；临界判断以顶层 `Score` / `IsMalicious` 为准。
3. `AgreementRate` 当前实为 MaliciousVotes / OkModels，不是与最终结论的一致率。保留既有名字，不应换一种含义解释它。
4. 模型不全、SDD 基线缺失或执行失败时漂移信息可为默认零值/none/false，不能据此证明已完成漂移检测且无漂移。`Status=2` 表示 DriftSuspect，不等于恶意。
5. 删除 PerModelDetails 后不能从开发响应验证 MalGraph 内部图计数；真实模型覆盖由成功分数和覆盖统计验证，内部图需专用验证工具。
6. 逐样本 ProcessingTime / TimingMethod 包含共享批前向均摊时，不是该样本独占 wall-clock；不同入口的耗时字段也不保证完全相同。

## 4. 验证与历史记录

测试步骤见 [TESTING](TESTING.md)。回归覆盖正常/部分失败/哈希命中/目录错误项及非原地修改；真实请求应验证三个字段直接不存在，同时确认 Web 仍保留原契约。

2026-11-10 的合成及真实 PE 证据保留在 [契约报告](test-records/dev_response_fields_2026-11-10.json)、[真实 HTTP 报告](test-records/dev_response_fields_real_http_2026-11-10.json)。它们仅代表该次环境和范围，不是本次文档核查重新测试的结果。历史原始响应不做离线改写。

实现：[开发投影](../engine/dev/projection.py)、[HTTP 契约](../engine/contract_app.py)、[聚合策略](../engine/prediction_policy.py)。
