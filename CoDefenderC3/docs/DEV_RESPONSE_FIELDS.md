# 开发接口响应字段审查（2026-11-10）

## 1. 本次生效范围

仅影响独立开发入口 `engine.dev.app:app` 的 `POST /predict-single`、`POST /predict-directory`。
开发入口由 ASGI app 选择，不是把生产入口的 CODEFENDER_ENV 设为 dev 就会切换协议。
生产响应投影、main Web 兼容响应/流式事件、模型推理、分数、阈值、D/E 和 MalGraph 均不变。

在 HTTP 返回边界移除以下字段（不是返回 null 或空集合）：

| 字段路径 | 原因 |
|---|---|
| ScanResult.PerModelPreds | 当前逐模型二值判定可由 PerModelScores 按 score > 0.5 推导，等于 0.5 时为良性。 |
| ScanResult.ModelStats.AggregatedModels | 名单与 PerModelScores 的键重复；后者只包含成功进入集成的模型。 |
| ScanResult.PerModelDetails | 重复逐模型分数、判定及注册信息，且包含体积较大的内部诊断；失败原因由 ExcludedModels 保留。 |

通过复制被裁剪的响应层级实现，不原地修改共享证据或哈希命中对象。
覆盖正常模型结果、部分模型失败、哈希短路与目录失败项；缺省块不补假数据。
这是缩减响应，不是隐藏内部计算，也不是阻止通过保留分数推导二值判定。

## 2. 其他字段是否必要

本次**只删除明确指定的三个字段**。其他字段分为必要诊断与可进一步精简两类，避免一次性扩大不兼容变更。

### 建议保留

| 字段 | 用途/注意事项 |
|---|---|
| MD5、SHA256 | 样本关联、去重、核对源文件和哈希库命中。 |
| FileName、FileSize；目录 FilePath | 定位样本、排查尺寸与性能问题；单文件上传不返回临时文件路径。 |
| IsMalicious、Score、ScanResult.VirusName | 最终判定、集成分数及恶意等级；Score 不是经过校准的置信概率承诺。 |
| Status、StatusLabel、Error | 区分正常良性、恶意、漂移嫌疑、失败和超时，避免把失败项的 IsMalicious=false 当作良性结论。 |
| ScanResult.Packed | 壳/归档诊断信息；哈希短路时默认值不证明做过完整壳分析。 |
| ScanResult.PerModelScores | 定位分数分歧和误报/漏报；保留成功模型名单与分数。 |
| ModelStats.TotalModels、OkModels、SkippedModels、ErrorModels | 判断模型覆盖是否完整；请求 HTTP 200 不等于全部模型成功。 |
| ModelStats.ExcludedModels | 被排除模型及原因；在移除 PerModelDetails 后仍能定位缺模型、缺特征等问题。不再提供逐模型结构化 status/view/type/内部图元数据。 |
| ModelStats.AggregationMethod、DecisionThreshold | 解释等权均值和严格大于阈值的最终判定，避免按多数票替代均值判定。 |
| ModelStats.MaliciousVotes、BenignVotes、ScoreRange | 简洁的分歧概览；虽可计算，但对开发排障便利且体积小。 |
| DriftEvidence、SampleDriftType、AnomalyScore、IsDriftCandidate | 漂移排障信息；见下文“语义风险”。 |
| Source、ScanResult.HashMatch（仅命中时） | 解释哈希短路与命中来源。命中后模型可能完全未执行，不能把缺少模型统计当作 0 个失败。属于内部开发诊断，不建议未经访问控制暴露。 |
| Summary 的计数、Directory | TotalFiles 是候选 PE 数；TotalFilesInDirectory 是目录全部文件数；SkippedNonPE 解释差额。开发的 ErrorCount 不含 TimeoutCount，需要合计判断失败总量。 |
| Summary.Timing、ProcessingTime、TimingMethod | 性能排障。逐样本 ProcessingTime 包含批前向均摊，不是独占 wall-clock；TimingMethod 必须随其保留。 |

### 可在下一版契约继续精简（本次兼容保留）

| 字段 | 评估 |
|---|---|
| CRC32 | 已有 MD5/SHA256，通常没有必要额外输出；若无旧客户端依赖，可移除。 |
| ModelStats.EnsembleScore | 与顶层 Score 重复，但该字段四舍五入至 6 位；客户端应使用顶层 Score，不用它重新判定临界值。 |
| ModelStats.EnsemblePred | 与顶层 IsMalicious 重复（整数与布尔差异），可移除。 |
| StatusLabel | 可由 Status 映射，但开发可读性较好，建议暂保留。 |
| Summary.Timing 的 Avg/Median/Min/MaxSampleTime | 性能定位有价值；若需要更小的常规输出，可仅保留 TotalTime/Throughput，详细统计改为另一个明确版本的契约。 |

### 已发现的语义风险（未改计算口径）

1. ModelStats.AgreementRate 实际计算为 MaliciousVotes / OkModels，**是恶意票占比，不是与最终判定的一致率**。例如所有模型都判良性时该字段为 0，而非一致率 1。当前保留名称和值以兼容；后续应考虑版本化重命名，而不是悄悄改算法。
2. SDD 仅在成功模型列覆盖完整注册顺序时尝试执行。缺基线/调用失败或模型不全时会保留默认零值/none/false。因此漂移字段全零**不能证明已完成漂移检测且无漂移**；后续宜增加明确的执行状态/跳过原因，不应靠隐藏字段掩盖这一限制。
3. 去掉 PerModelDetails 后，逐模型精确状态和 MalGraph 图内部计数不可从开发响应验证。可通过成功分数与覆盖计数证明模型前向成功；需要内部图诊断时应查看专用验证记录。main Web 契约按冻结要求仍保留原明细，不能为了全局隐藏而修改它。

## 3. 验证与历史数据

- 契约回归覆盖两个开发接口、部分模型失败、哈希短路、空缺块、错误/超时项及非原地修改。
- 同时验证生产投影与 main Web 响应不变，不能把开发裁剪应用到 Web。
- 真实 HTTP 验证工具改从 PerModelScores + ModelStats 校验开发模型覆盖，不能继续强制要求已隐藏的 PerModelDetails。
- 目录测试汇总同时兼容旧明细与新紧凑格式；新格式只能把非成功模型记为 excluded 并附原因，不猜测具体的 error/timeout/skipped 状态。
- 之前保存的原始接口响应和历史测试记录保持原样，不把历史响应改写成新契约。任何离线裁剪预览须单独命名并明确不是新的 HTTP 扫描结果。

相关实现：engine/dev/projection.py、engine/contract_app.py。

### 本次实测结果

- 完整回归 **175 项通过**（含 78 项未修改 main Web 测试）；三监听器合成模型真实 HTTP 冒烟和冻结检查均通过。记录：docs/test-records/dev_response_fields_2026-11-10.json。
- 使用既有样本集中的一个真实 PE，在 CPU + 默认 SMDA + include_de=true 下，Web/生产/开发的单文件与目录共 **6 次请求均 HTTP 200**。开发两个响应均无上述三个字段，33/33 模型（含 MalGraph）成功；生产结果仍等于开发结果的生产投影。记录：docs/test-records/dev_response_fields_real_http_2026-11-10.json。
- 新开发响应示例另存 scan-results/dev_response_fields_2026-11-10/；不是全 20 样本重扫，旧两份原始响应 SHA256 未变。临时验证服务已停止；既有服务未重启，需重启对应开发入口才能加载新代码。
