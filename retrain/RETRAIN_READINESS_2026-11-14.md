# 重训前就绪检查（2026-11-14）

## 结论

**尚不具备正式重训条件。** 四角色训练、版本化缓存、共享决策策略、严格输入/序列化契约已实现；当前缺口是实际数据、受支持模型与特征、可复现训练环境、真实模型验证以及独立验收流程。不能把回归测试通过等同于模型可训练或可部署。

本次仅检查代码与小型证据、复跑依赖轻量测试，并新增本报告/审计记录。没有正式训练、原生 PE 反汇编、真实 HTTP 验收、依赖安装、权重替换、部署、提交或新建分支。没有修改业务代码或无关 Docker/签名工作。

## 1. 已完成，不再作为待办

- R0 清单审计、选择/排除记录、显式 train/model_val/calibration/test 划分。
- 四角色 loader 与版本化特征/视图缓存；严格来源、dtype、shape、coverage 检查。
- train 拟合；model_val 外部早停/权重选择；calibration 只选阈值；训练不读取 test。
- 共享 DecisionPolicy、固定模型名对齐、逐行失败状态；不可决策不作为良性。
- ModelInputContract、构造默认值冻结、严格新序列化契约和加载检查。
- 研究候选的输入契约绑定：retrain-decision-candidate-v3 / retrain-training-artifact-v2。

**本次复核：196 个重训回归 + 7 个响应投影测试全部通过，失败/错误/跳过均为 0。** 57 个输入契约测试已包含在 196 内，不重复计数。仅为合成/注入/依赖轻量验证，未验证真实生产模型或训练质量。Git diff --check 通过（原有 CRLF 警告）；上阶段所列 19 个小型证据文件和 13 个源码指纹均未变。

## 2. 启动真实小规模训练前的硬阻塞

### P0-1：提供样本根目录或 SHA256 → 绝对路径映射，并落地验证数据

2026-11-13 的路径审核记录：选择总数 **24,904**；roots=[]、path_map=null，全部为 No candidate file found，build_allowed=false。**这是未提供可用定位输入时的结果，不证明样本在其他磁盘/服务器不存在。** 本次未重扫样本目录。

当前选择数量：

| 角色 | 总数 | 良性 | 恶意 |
|---|---:|---:|---:|
| train | 18,926 | 9,463 | 9,463 |
| model_val | 2,046 | 1,023 | 1,023 |
| calibration | 2,006 | 1,003 | 1,003 |
| test | 1,926 | 963 | 963 |

下一步：定位 → 核验 SHA256/大小/PE 头 → 审核失败/冲突 → 物化四角色数据快照。必须得到可验证的 metadata.json、metadata.jsonl、verified_selection_manifest.csv、split_plan.json、path_audit.json 来源链。禁止直接改 ready 标志绕过检查，也不能把 CSV 名单当作已经存在的 PE 数据集。

历史路径证据：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/path-audit/path_audit.json

### P0-2：冻结本轮模型清单，明确不是所有模型已被新特征适配器覆盖

当前配置有 35 个模型位。受审计的训练 worker 仅支持：

- fast：B01–B07。
- smda：B01–B07、D01–D07、E03/E04。

按当前配置的特征 ID 层面，可以覆盖 V1_byte、V2_byte_stat、三个 V6 视图，共 10 个通用模型候选；**这只是静态支持范围，不是 10 个真实模型已训练/验证成功。** 实际基线的模型/视图映射还需在目标环境检查。

| 视图/模型组 | 当前受审计训练抽取状态 |
|---|---|
| 字节序列、字节统计 | ID 范围支持；需冻结长度、dtype 与真实模型输入语义 |
| opcode 序列、统计、函数表示 | SMDA ID 范围支持；需原生运行成功及真实模型验证 |
| PE 结构/导入 | A 特征适配未纳入该 worker |
| 字符串 | C 特征适配未纳入 |
| 图视图 | E01/E02 未纳入；不可伪造图拓扑，MalGraph 需专用管线 |
| 灰度/彩色/Markov/熵图 | F 特征适配未纳入 |
| Hash/元数据 | G/H 特征适配未纳入 |
| Full EMBER | 无受审计的完整映射；旧缓存不能直接当作新契约缓存 |

可以先选择一个小而完整的受支持模型组开展开发试跑；若目标是全模型重训，需补齐所需适配器和专用训练管线。不要因某特征暂不支持就静默降级、补零或将旧权重伪称本轮重训。

来源：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_feature_builder.py；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_feature_worker.py；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/config.py。

### P0-3：确定并验证实际训练环境，不使用当前分析 Python 冒充训练环境

本次分析环境是 Windows Python 3.12.14 / NumPy 2.3.5：torch、sklearn、FastAPI/httpx 等未安装；SMDA 可定位，但 Disassembler 原生导入因 _lief DLL 失败。**该结论仅适用于这套分析 Python，不等同于服务器环境失败。**

目标环境必须提供：精确 Python/torch/torchvision/NumPy/SMDA/LIEF/Capstone 及所选模型依赖版本、平台信息、镜像 digest 或环境锁、原生导入与实际 GPU 运算证据。当前 constraints-smda-validated.txt 自身明确不是完整平台/torch 锁；GPU Dockerfile 也未使用该约束文件，部分依赖仍浮动。

**Dockerfile.smda.gpu 的 train target 目前只是关闭哈希预检的服务/测评变体：未 COPY train/，继承 supervisor 服务启动命令。** 若使用它重训，需显式打包/挂载冻结的训练代码和数据，并覆盖为真正的 split-aware 训练命令；镜像 target 名称不等于已经具备训练任务。

新 split-aware CLI 的 --device auto 实际选择 CPU。需要 GPU 就显式 --device cuda，并验证真实设备、显存与操作成功，不能用服务端自动 CPU 回退作为 GPU 训练验收。

来源：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/Dockerfile.smda.gpu:76–105、train stage；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/codefender.smda.gpu-train.ini；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/constraints-smda-validated.txt；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py:462–491。

### P0-4：完成每个入选真实模型的输入/初始化审查

已发现的具体风险：

1. B01 原始数组为 2MiB uint8；当前 V1_byte 共用一个冻结视图长度。注册表的名义序列长度分别为 MalConv 200,000、MalConv2 16,000,000、ByteTransformer 32,768。不能假设这三个名义长度已由新训练器分别实现。必须预声明截断范围/共同长度或经审计拆分视图，并对新语义重做基线比较。B01 不会自动恢复超过 2MiB 的内容。
2. **InceptionV3 注册表写 pretrained=True，而严格 freeze_constructor 明确拒绝该设置。** 全模型任务包含它时需要显式、可复现的本地初始化方案/构造配置（无隐式下载），或明确排除。此处为静态代码发现，尚未实例化真实模型。
3. NumPy 后端只支持 scratch；finetune 会明确拒绝。torch finetune 需要有效基线 state_dict 严格匹配，不能自动退回 scratch。
4. 模型自身的词表边界、位置编码长度、图像/函数 reshape、输出与损失契约需做真实前向/训练检查；目前合成测试不覆盖全部生产类。
5. 当前指纹固定类定义源码及部分包，但尚未证明全部 helper/传递导入/原生依赖/预处理闭包都已冻结。完成该闭包审计后再生成长期使用的契约与缓存。

来源：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/models/input_contract.py:41–64；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/model_registry.py；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/feature_extraction/extract_feature.py:128、1255–1267；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_run.py:115–181；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_training.py。

### P0-5：实际提取并审计版本化缓存，然后做真实小样本 smoke

训练入口不隐式提取特征。需要冻结 feature_contract.json，按实际 backend/config/packages/source revision 提取样本，并得到 train/model_val/calibration 的覆盖率、超时/失败原因及缓存指纹报告。当前训练路径要求相关批次完整覆盖；若需要部分可用策略，应另行设计、审核，而非删样本不留痕或补零。

所需检查：跨进程重复提取稳定性、关键 D 特征稳定性、异常/resource-only PE 的状态、类别/来源/大小分层覆盖及耗时、缓存失效行为、磁盘/内存/显存预算。旧 .feature_cache 单个 EMBER_FULL.npy 不等于新四角色受验证缓存。

使用 D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py 的 **--split-aware** 分支，显式指定数据集、feature contract、cache dir、baseline、models、mode、device、run id、种子、超参数、权重法和阈值网格。禁止使用合成月份/minimal/旧 run_all 工作流处理当前清单。旧入口仍有历史兼容行为，不是本轮重训规范。

--dry-run 只预检 train/model_val，不验证 calibration、不训练、不生成完整研究候选。预检后还须在独立开发试验清单上进行真实小规模 fit → 序列化 → 恢复 → 同输入 predict 验证，每个入选模型至少覆盖一次；记录设备、finite loss、实际样本数、恢复一致性、耗时和峰值资源。**正式 test 继续封存，不用于修模型/选超参数。**

## 3. 全量正式重训前要完成的实验与验收设计

### P1-1：数据语义与泄漏审核

- 确认恶意 manifest_date 的语义及标签来源；不能直接当首次出现时间。
- 良性 CSV 无可核验时间/来源轴，当前良性划分是 group-hash partition，不是严格时间外推。
- 确认良性软件/版本谱系、跨类冲突处置和近重复隔离。exact ssdeep 字符串分组已实现，但不是完整相似样本聚类。需要决定并记录更强的审核/分组方法，或明确实验局限。
- 匹配类型/粗大小桶不代表所有捷径已消除；做元数据-only 对照和分层报告。
- 当前测试为 2026-05，相对检查日 2026-11-14 已是历史窗口；若目标是近期部署，应预先准备独立较新样本/影子验收，而非把 5 月结果称作当前效果。

历史 split_plan 中 four_split_training_contract_not_yet_implemented 已被后续实现解除；不要将历史 blockers 原样当作当前缺陷。数据定位/标签/谱系等未解除项仍须处理。

### P1-2：冻结优化目标、基线和独立评估程序

- 基线与候选使用同一锁定样本 ID；各自使用经过审查、与其权重相匹配的特征流程，明确特征口径差异。
- 测量纯模型结果时关闭哈希短路，并分别记录模型失败/不可用/覆盖情况，不能将签名命中或填充值计作模型效果。
- 预先声明总体/分层指标、失败处理、资源预算和接受阈值；默认等权或 AUC 权重都只是已实现的选择法，不代表自动最优。
- **当前 calibration 选择是 F1 → 更少 FP → 更高阈值，默认网格 0.3–0.8。** 不是 FPR 约束下最大召回，也没有拟合概率 calibrator。若目标为低 FPR，需在 test 解封前设计对应阈值/校准与失败规则；不能只修改网格就宣称目标已满足。
- 补充消费 v3 研究候选/v2 研究模型包的独立 split-aware 评估工具，核验工件/契约、冻结策略、严格恢复、同样本 baseline 对照、置信区间及错误样本 ledger。
- 当前 verify_trained_ensemble.py 是旧 ensemble 的结构/伪数据可替换性 smoke，不能替代上述真实独立验收。
- 若本轮目标包含部署，昂贵全量训练前还应冻结运行时提取/发布的接口和源码方案，最好在同一版本完成适配。ModelInputContract 的 implementation_revision 包含 engine/app.py、contract_pipeline.py、staged_scan.py 等源码；训练后修改这些固定文件会使原契约运行时校验失败。不能重算/替换指纹冒充原训练版本；需保留原版本环境或走显式审核的迁移与重验流程，必要时重训。

来源：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_selection.py:102–115；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/retrain_run.py:311–366、495–506；D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/verify_trained_ensemble.py:1–22。

### P1-3：低误报率需要独立良性验收集

当前 test 仅 963 个良性，calibration 仅 1,003 个良性。test 一个 FP 对应约 0.10384% FPR；在独立同分布二项假设下，即使 0 FP，单侧 95% 上界仍约 0.31060%（1 - 0.05^(1/963)）。实际软件谱系相关性未审核，所以不能用该计算掩盖样本相关问题。

需要按目标 FPR 与置信度设计独立、足量、真实新良性 acceptance 集及抽样方案，不挪用已用于阈值选择的 calibration 充当独立验收。source_ood 清单约 205,293 条，只有恶意：只报告召回/覆盖/失败/延迟，不能据此给出 FPR/AUC/概率校准结论。本次未核验该 OOD 集的实际文件。

## 4. 训练后才执行的工作（不是小规模训练启动硬前提）

1. 模型与策略锁定后解封 test，一次性执行独立验收；不根据结果反复调参并继续称其独立 test。
2. 执行独立良性/source OOD/较新影子数据验收，报告覆盖、分层效果、失败与资源指标。
3. 受控发布工具把研究候选转换为严格运行时工件，拒绝混入无契约旧模型，记录完整来源链与回滚基线。
4. 安装并审核真正的原始 PE → 冻结 feature bundle 运行时适配器，实现离线/Web/批量/阶段扫描一致性。当前新-bound raw PE 路径故意 fail closed；这是安全边界，不能删掉拒绝分支当作适配完成。
5. 验证生产加载方提供 expected_input_contract（严格新工件必须外部契约）、真实 PE/HTTP、坏工件、超时、并发、CPU/GPU、回滚。
6. 未过以上关口不得替换生产 ensemble.pkl。研究候选仍 deployable=false、test_used=false，不是生产包。pickle 仅可信本地使用，SHA256 不提供外层 pickle 安全性或发布认证。

## 5. 建议执行顺序

**样本定位/语义审核 → 冻结模型范围 → 锁定训练环境与依赖闭包 → 冻结特征/初始化契约 → 提取并审核开发缓存 → dry-run → 真实开发小样本端到端试跑 → 冻结评估目标/独立评估工具与 acceptance 数据 → 全量训练 → 锁定后独立验收 → 受控发布与 runtime 验收。**

可以先完成不依赖样本的模型支持矩阵、训练镜像/锁定配置、初始化审查和独立评估器设计；但没有实际样本路径和目标环境，就不能证明真实重训已就绪。

原训练 README 和早期计划仍有“输入契约尚待实现”等过期描述，启动前应补充最新版入口与状态说明；保留历史证据，不重写原始审核结果。

## 6. 本次证据

- 目录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-readiness-2026-11-14/
- 机器记录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_readiness_2026-11-14.json
- all-summary.json / projection-summary.json：本次测试结果。
- environment.json：本次分析 Python 原生导入情况。
- model-feature-support.json：配置层模型/特征支持矩阵与静态构造签名。
- previous-stage-integrity.json / previous-source-integrity.json：已列出上阶段证据与源码未变。
- git-status.log / git-diff-check.log：工作区快照和 diff 检查；未检查全部历史大工件或重新扫描百万行 CSV。
