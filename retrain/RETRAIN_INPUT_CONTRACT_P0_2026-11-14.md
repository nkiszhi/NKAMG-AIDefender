# P0 模型输入 / 预处理 / 序列化契约实施记录

日期：2026-11-14（Asia/Shanghai）

## 结论与边界

本轮完成依赖轻量的模型输入契约、显式构造参数绑定、严格模型工件往返，以及重训研究候选的契约身份绑定。**这是实现与合成回归记录，不是生产发布、真实模型质量或真实 PE / HTTP 验收。**

- 重训相关回归：**196 通过，0 失败，0 错误，0 跳过**。
- 其中新增输入契约回归：**57 通过**，已包含在上述 196 项内，不重复累计。
- 另有现有响应投影回归：**7 通过，0 跳过**；不是运行 HTTP 服务的测试。
- 本轮 13 个 Python 文件语法编译通过；检查的原有顶层函数/类方法未删除；Git diff --check 通过（仅既有 CRLF 转换提示）。
- 合成接口工件保存/加载后的分数与决策一致，错误维度 / float64 输入被拒绝。该 smoke 不拟合，不提取 PE，不使用原生 torch，不保留其临时 pickle 工件。
- 保留已完成的 2026-11-13 记录。本轮抽取的 91 个旧文档、元数据、脚本、小型清单与日志指纹保持不变；未审计未列入的大型数据文件。

## 1. 共享特征契约

运行时实现位于：

- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/feature_contract.py
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_contract.py（兼容重导出，保留直接 worker 所需路径引导）

新增 validate_view：严格检查单行或非空批量形状、冻结 dtype、有限值及显式屏蔽列必须为零。不能从错误输入推断维度、右侧补零、隐式窄化类型或重新应用环境 mask。完整原始特征字典仍必须满足既有形状与 dtype 定义；显式视图截断与 mask 只在共享 transform 中执行。

D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_feature_builder.py 的源码身份新增运行时契约文件。本次源码改动会使旧固定源码修订的缓存/契约失配；不会自动重写旧缓存、旧契约或历史证据来“通过”检查。

FeatureContract 保留历史兼容对象形式；本轮没有将所有历史特征对象都改造成不可变对象。新的 ModelInputContract 保存规范化字节，公共 document/spec 返回副本，并禁止修改 fingerprint。

## 2. 模型输入契约

D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/models/input_contract.py 定义 model-input-contract-v1，包含：

1. 完整特征契约与有序模型 allowlist；每个模型的视图、引擎及固定输入维度/dtype。
2. 经 inspect.signature 物化默认值后的完整 JSON 构造参数；不在加载时借用注册表默认值，也不在加载时强行改写 pretrained 参数。预训练必须在冻结声明中明确禁用（False/None）；数字 0 不伪装成 False。
3. 定义模型类的项目源码路径/内容 SHA256、模块/顶层类身份，以及输入/序列化/共享推理/运行时准备实现修订。
4. 所有已声明包的精确版本；默认构建声明 Python、NumPy，以及所需的 torch。
5. 明确张量转换与输出契约：NumPy float32 + 两列二分类概率；torch float32 或安全整数到 int64 的转换，以及单列概率或两列 logits。tuple 输出只采用声明的首项规则。

严格输入分支不从第一层 Linear、RAW_LEN、注册表或原始行长度猜测维度，不允许把 (1,D) 单行自动摊平成 (D,)。NumPy 的 n_features_in_ 若存在，必须是匹配的整数维度。

**尚非完整依赖闭包证明**：模型定义文件和列入的关键实现有内容指纹，但没有自动遍历所有 helper/import 的传递依赖；包声明也不是 sklearn、torchvision 等所有依赖的自动完备锁定。通用签名绑定亦不能证明任意模型类内部完全忽略环境变量或其它隐式状态。这些是生产验收前的独立审计项。

## 3. 严格保存 / 加载与旧格式隔离

实现：

- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/models/contract_serialization.py
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/models/ensemble.py

新工件 schema 为 ensemble-input-contract-v1，且仅供显式选择严格接口的受信本地调用：

- 保存前验证全部模型、视图映射、引擎、实际构造参数及固定 DecisionPolicy/权重；不得丢弃失败或缺失模型。
- 每个模型 payload 独立保存为 bytes + SHA256。先检查所有 payload 的哈希，再反序列化任何模型 payload。
- torch 保存 CPU 状态，使用冻结类/构造参数及 strict=True 恢复；不经注册表重建，不降级到 scratch。
- 原子替换输出；失败时清理临时文件，保留原有输出。
- 新工件必须由调用方提供 expected_input_contract；指纹、完整文档、运行时源码/包版本通过后才导入/恢复模型。未知、空或研究 schema 都不落入旧格式加载。
- 旧工件默认仍走既有兼容分支；allow_legacy=False 或提供 expected_input_contract 会明确拒绝无契约旧工件。旧分支的既有重建行为没有冒充新契约行为。

**安全声明：pickle 仅能加载受信本地文件。外层 envelope 本身仍是 pickle；模型 payload 哈希检查不发生在外层反序列化之前。SHA256 不是签名，也不防止伪造者重新计算哈希，更不使不受信 pickle 安全。**

程序化用法（不是生产发布指导）：

    ensemble.set_input_contract(frozen_contract)
    ensemble.set_decision_policy(fixed_policy)
    ensemble.save(candidate_path)
    loaded = MultiModelEnsemble.load(
        candidate_path, expected_input_contract=frozen_contract, allow_legacy=False)

安装契约时必须已有完整模型、映射和实际构造参数。绑定失败回滚，不留下半安装契约。绑定后旧 fit 的内部随机划分路径被禁止，应使用显式 split-aware 后端。

## 4. 共享推理与运行时提取限制

D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/prediction_policy.py 与离线 predict_all 共享冻结输入分支：不窄化错误 dtype、不调用旧行补齐；torch 输出宽度由契约声明，不兼容性猜测 1/2 列。失败记录没有成功分数；无法决策仍是 prediction=-1、score=NaN。

旧 predict_all 的原始兼容返回仍可能含 0.5 占位；这不是良性预测。决策必须消费对应的逐行状态，不能把占位参与聚合。

D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/app.py 的冻结特征分支仅接受完整 features + 匹配 feature_fingerprint 的显式 bundle，并使用共享 transform。该标记仅是契约身份声明，**不是经过独立认证的提取来源**。

现有原始 PE 提取器并不提供经过审计的冻结 bundle。因此：

- 严格单样本准备没有合格 bundle 就拒绝，不执行旧提取/EMBER/补零回退。
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/contract_pipeline.py 的冻结批量路径在旧/原生提取前明确失败。
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/staged_scan.py 的冻结阶段扫描明确报告未安装审计提取适配器。
- 旧无输入契约的运行时行为保持兼容。本轮没有启用生产 HTTP 自动加载新契约工件，也没有宣称新工件已经可以直接扫描真实 PE。

## 5. 重训研究候选绑定

D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_run.py 的 EnsembleTrainingBackend 在真实后端进入 fit 前必须构建并验证 ModelInputContract。构造默认值一次物化，train/restore/predict 使用固定参数及共享视图检查，不在加载/恢复时引入临时注册表默认值。

对具有模型输入契约的研究运行：

- run_identity、manifest、decision_candidate 及研究 artifact 保存完整输入契约与指纹。
- 研究决策候选升级为 retrain-decision-candidate-v3；研究模型包为 retrain-training-artifact-v2。
- 完成校验检查输入契约、特征契约、模型规格与各发布文档的语义一致性。历史 v1/v2 候选记录仍可按原身份校验，不被自动迁移。
- 注入的无模型身份 FakeBackend 仍只能产生旧研究 v2 候选；不能伪造完整可加载身份。
- 全部候选仍 deployable=false，test_used=false；不是生产 ensemble.pkl，不被默认运行时加载。研究完成不等于可部署。

该真实后端代码路径本轮仅用合成 NumPy 测试类和极小矩阵执行微型拟合/恢复，不是生产模型训练或模型质量评估。独立 test 数据未读取。

## 6. 可复现证据

测试文件：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/tests/test_retrain_input_contract.py

证据目录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-14/p0-input-contract/

机器记录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_input_contract_p0_2026-11-14.json

PowerShell 复跑示例：

    & "C:/Users/lenovo/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe" -X utf8 "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-14/p0-input-contract/run_regression.py" all
    & "C:/Users/lenovo/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe" -X utf8 "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-14/p0-input-contract/run_regression.py" input
    & "C:/Users/lenovo/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe" -X utf8 "D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-14/p0-input-contract/run_regression.py" projection

目录包含三个 summary / 日志、syntax/API integrity、实际环境探测、合成 roundtrip、Git diff check、旧证据保留校验以及 13 个本轮源码文件 SHA256。

## 7. 尚未完成，不应误报

- 当前 Python 3.12.14，NumPy 2.3.5；torch、sklearn、FastAPI、httpx、starlette、multipart 不可用。没有安装依赖。
- SMDA 原生导入探测失败：ImportError: DLL load failed while importing _lief: 找不到指定的模块。。正向原生反汇编/torch 内核验证未完成。
- 本轮没有运行真实 HTTP 服务验收；7 个响应投影测试不能替代它。此前真实 HTTP 契约测试的 torch 导入失败也不能计作通过或跳过成功。
- 尚需实现并独立审核真实 PE 冻结提取适配器，完成模型 helper/package 依赖闭包审计，再做受控候选发布和独立 test 验收。
- 之前记录的 24,904 条已选样本尚未通过现有清单定位；需要实际根目录/路径映射。本轮没有新的样本定位扫描，未定位不证明文件在其它位置不存在。
- 没有物化真实数据集，没有正式训练、替换生产权重、部署、提交或新建分支，也未改动无关 Docker/签名工作。
