# 共享 DecisionPolicy P0 实施记录（2026-11-13）

## 结论与边界

**本项源码实现和本地合成回归已完成；真实 HTTP/ASGI、真实 PE 与生产模型验收仍未完成。** 没有启动正式训练、替换生产权重、部署候选、安装依赖、提交或创建分支。此前 R0、split/cache、split-aware training 记录保持不变，研究候选继续 deployable=false。

解决的是离线、主 Web 单样本、production/development 批量扫描采用不同聚合规则的源码问题，不是完整候选发布或检测质量问题。

## 1. 共享数学与失败门禁

新增 CoDefenderC3/engine/decision_policy.py，不加载模型、不提取特征、不拟合校准器。严格 decision-policy-v1 文档包含：

- 唯一显式 model_names（allowlist）；按名称对齐分数列，不依赖调用方列顺序。
- 同序非负有限、总和为 1 的 weights；非法或全零权重拒绝。
- 有限 [0,1] threshold 和 comparator=strict_gt；阈值等值判良性。
- 明确 calibrator：identity，或外部预拟合的单调递增 platt_logit（正 slope、有限 intercept、epsilon）。本项没有拟合概率校准器。
- missing_model_policy=require_all|renormalize。

每次调用必须携带与分数完全同形的逐行模型状态；ok 概率必须有限且在 [0,1]。error/missing/skipped/unavailable/timeout 等不能投票，即使原始兼容矩阵中的值是 0.5。

| 覆盖策略 | 有模型不可用 | 没有成功的正权重模型 |
|---|---|---|
| require_all | 任意 allowlist 模型缺失即无法判定（包含零权重成员的明确完整性门禁） | 无法判定 |
| renormalize | 只在可用模型正权重上重归一化，返回 degraded 和有效权重 | 无法判定 |

无法判定内部表示为 prediction=-1、score=NaN；require_decidable() 抛出 DecisionUnavailable。Web 格式器不会生成成功良性响应；批量管线返回 Status=-1 + Error。旧错误协议中的 IsMalicious=false 不表示成功判良性；错误项没有成功 Score，不进入 BenignCount。

文档深复制、公共字段冻结、内部权重使用不可写字节 backing；canonical JSON SHA256 指纹可复验。指纹是完整性标识，不是签名或独立发布授权。

## 2. 旧集成与固定策略

没有固定策略的旧集成明确使用已保存合法 _weights（仅缺失时等权）、identity、严格 >0.5、renormalize。**已保存权重现在确实影响源码中的 Web 决策**，不是继续用成功模型等权平均。

MultiModelEnsemble.predict_all(return_status=True) 返回 (preds, scores, statuses)。默认二元 raw tuple 保留旧 .5 占位以免破坏原始矩阵消费者；ensemble_predict 已要求显式 statuses，不能猜测 .5 是真实结果还是失败值。状态矩阵属于当前调用，不使用并发不安全的全局 last-mask。

固定策略通过 set_decision_policy 安装，并在 ensemble.save/load 时保存/校验；allowlist 必须属于注册集。固定策略拒绝临时 DSIR/weights 覆盖，避免冻结决策悄悄变更。

**策略可加载不表示当前模型输入、环境、构造参数、外部 MalGraph 权重或整包发布已兼容。**

## 3. 单样本、批量及格式器接线

- prediction_policy.py：真实行推理、非法概率门禁、按行重试；共享策略结果直接用于 Score/IsMalicious。
- app.py::_predict_per_model 委托共享 batch adapter，保留 staged fast/slow 筛选、callback 与 MalGraph sentinel。
- app.py::_scan_single_pe 委托共享格式器；旧 _batch_scan_samples 委托 contract_pipeline.scan_paths。AST 对比确认主程序顶层函数/类及集成类已有方法没有删掉。
- production/development 路由继续使用现有 contract_pipeline；没有改变签名库、hash 命中优先级或生产投影公开字段集合。
- production/development 命名服从最终二分类预测，不用独立 .5 门限重新命名。历史 Low/Medium/High 仅是展示档位，**未重新校准，不是新模型风险保证**。

ModelStats 增加策略指纹、选中模型、有效权重、覆盖/降级、校准器、原始聚合分、实际阈值/比较器及 calibration profile 状态。完整覆盖标记 full_coverage_not_certified；降级标记 unverified_renormalized_profile。不能因为执行预拟合校准器就声称 fast/full/降级组合均经过验证。

SDD 只接受完整注册列的真实成功矩阵；部分矩阵不压缩后冒充原注册索引，不送入失败占位。中性漂移字段伴随 unavailable 诊断，**不是“未发生漂移”的证据**。历史 month-only 原始 per-model/SDD 指标尚未重设计，本项不把这些结果包装为正式重训验收。

## 4. 重训选择与研究候选

retrain_selection.py 使用相同 DecisionPolicy 聚合及 apply_threshold 比较；model_val 权重锁定和 calibration-only 阈值选择顺序不变，test 特征/预测仍不读取。

新 retrain-decision-candidate-v2 保存完整 decision_policy 与 policy_fingerprint；training_revision 包括决策、推理适配器及集成源码。verified_manifest 除 checksum 外，校验策略与锁定 model_val 权重、calibration 阈值语义一致；即使重算文件指针，不一致策略或 v2 缺失策略仍拒绝。

旧研究 v1 仍可完整性复验，不能自动部署。trained_models.pkl 仍为研究专用非运行时 schema，legacy ensemble loader 拒绝它；没有发布可 reload 的训练候选。

## 5. 旧月份评估缓存

run_all.py 三个 ensemble_predict 调用均传入真实 statuses。新增 train/prediction_cache.py：

- preds/scores/y/statuses 四个数组按行/列验证、allow_pickle=False；成功状态的概率与预测语义一致。
- 锁内串行写入数组、最终原子 JSON marker 绑定四文件 SHA256；读取在同一锁内验证整组后再用于决策。
- 状态缺失、损坏、名称顺序或实例作用域不符则重新推断，不推断“旧 .5 = ok”。
- 仅限当前 ensemble 实例作用域，跨进程不自动复用；fit 完成使作用域失效。

这是有限兼容修复，**不是旧 month 数据身份、特征版本或完整模型状态的可复用训练缓存设计**；同一实例作用域内数据/模型若变更，应开始新实例/运行。新 split-aware 入口继续使用既有内容/版本绑定缓存，不拿本缓存替代它。

## 6. 测试结果与保留失败证据

| 验证 | 结果 | 证明范围 |
|---|---|---|
| test_retrain*py | 139 passed / 0 failed / 0 skipped | R0 21 + split/cache 37 + training 38 + decision 43 |
| test_merge_dev_projection.py | 7 passed | 旧响应裁剪、计数、诊断工具，不是 HTTP 服务测试 |
| 新增决策 43 项 | 18 policy + 7 ensemble + 8 adapter + 4 cache + 3 publication + 3 tensor-injection | 合成矩阵、真实 NumPy 适配函数、源码抽取的主程序/批量函数、注入张量接口 |
| 独立进程 synthetic_decision_smoke | passed | 四个策略下离线/格式器完全一致；没有 PE 提取、拟合或 HTTP server |
| Python compile / AST 方法清点 | passed | 12 个本项 Python 文件语法；主程序和已有集成方法无删除 |
| git diff --check / 新增文件 whitespace | passed | 新改动差异卫生；历史未改行空白列明并保留 |
| test_merge_contracts.py | 无法导入，未执行真实测试 | ModuleNotFoundError: torch；不是跳过后宣称通过 |

初次扩展测试的两项失败日志保留：一项测试错误地期待 float32 模型输入保留 float64 特征差异，已改为验证模型输出精度；另一项 CRLF 字符串替换未实际更新命名门限，检查落盘源码后修复。133/136 项中间通过日志与最终 139 项日志均保留。

独立进程演示的相同 .9/.1 模型分：权重 .8/.2 得 .74（阈值 .6 判恶意）；反转权重得 .26（判良性）；阈值改 .8 判良性；预拟合 logit 变换后约 .278 判良性。strict require_all 缺一个模型返回 -1/NaN。这些是合成决策证明，不是检测质量指标。

环境为 Python 3.12.14、NumPy 2.3.5；torch、sklearn、fastapi、httpx、starlette、multipart 缺失。SMDA 入口仍因 LIEF native DLL 加载失败。没有安装依赖绕过限制。

此前 24,904 条入选样本未通过现有 manifest 路径定位的问题仍未解决；不据此证明文件在其他目录不存在，也不把合成矩阵当作真实已物化数据。

## 7. 复现与下一项

证据目录：

    D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/p0-decision-policy/

使用本机 bundled Python 执行目录中的 run_regression.py、run_projection_regression.py、synthetic_decision_smoke.py 或 check_integrity.py。run_http_regression.py 保留真实依赖缺失证据，不自动安装依赖。

机器记录：

    D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_decision_policy_p0_2026-11-13.json

下一项 P0：冻结环境无关的模型输入/预处理/序列化契约，拒绝错 schema 与静默补零；独立候选运行时产物完整性/发布接线；冻结策略后只读 test 的独立统计验收。真实样本定位和 SMDA/HTTP 依赖问题仍需解决。**本项不构成正式开训或上线批准。**
