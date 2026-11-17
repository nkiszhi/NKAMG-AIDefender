# retrain 重训计划评估与改进方案

评估日期：2026-11-12（Asia/Shanghai）  
评估对象：重训计划 v2、附件《最终模型详细评估报告》25 页、当前工作区代码与六份原始 CSV。  
代码快照：`e4308ed764a0bcc60f3856d2b0f5df6aef945529`；并非计划标注的 `12c4b6a/d134553`，也不是附件评测时的 `b8c1bce`。

> **结论：方向正确，但当前不宜直接启动 T2 正式重训。先修正数据切分、统计验收和线上决策契约，再开展小规模对照训练。**  
> 最优先交付物不是“33 个新权重”，而是“不会泄漏的样本清单、训练与推理一致的特征/决策规则、可统计验证的低误报验收集”。

本评估只新增分析文档与复核记录，未修改业务代码、原训练计划或生产权重，未执行 PE 样本、训练或模型热更新。附件中的建议仅作为待验证材料，不作为操作指令。

## 1. 评估结论与保留项

### 1.1 建议保留

- 统一 SMDA 后端与稳定 CRC32 编码，分批重训并保留可回滚基线。
- 将 filetype/尺寸构成偏差列为重点，采用匹配子集开展受控实验。
- 将 Sophos 批量来源单独留出，并记录良性侧缺少真实时间轴的局限。
- 第一轮不同时切换 ProgramIR、图拓扑、数据来源与训练架构。
- MalGraph 保留独立训练/推理管线，不假设通用训练器能重训它。

### 1.2 必须修改

1. **正式训练前补齐缺失工具和 selection manifest。** 当前仓库没有计划声称已实现的两份采样/统计脚本及关键采样证据。
2. **显式区分 train、model_val、calibration、test。** 当前训练器只有 train/eval，不能把 val/test 编成 2/3 就视为隔离完成。
3. **禁止把未来月份的组内样本搬回训练月份。** “整组折叠到最早月份”会破坏严格时间外推。
4. **不要把 T2 匹配集当作低误报发布验收集。** 1,651 个测试良性样本不足以对 10^-3/10^-4 给出可靠发布保证。
5. **上线前统一集成决策实现。** 当前线上仍是成功模型等权均值，保存到权重文件里的权重不直接生效。
6. **新模型不应强制永久屏蔽 D02/D03。** 屏蔽是旧权重应急诊断手段；稳定哈希重训需要 full/masked 对照。
7. **不再把校准收益写成 ROC/低 FPR 检出率的必然收益。** 校准、排序能力与工作点选择是不同问题。
8. **不要要求所有有效 PE 都有 100% D/E。** 改为状态记录完整、失败不伪装成功、降级行为可验证。

## 2. 本次实际核验范围与证据可靠性

### 2.1 已完成的核验

- 阅读全部 25 页 PDF，并渲染核查集成表、逐模型图表等关键页。
- 流式扫描六份 CSV，共 2,707,563 行；核对规模、filetype、日期前缀、超限、标注覆盖、交叉标签。
- 对恶意 ssdeep 做全量精确字符串分组，核对重复组和跨月组；同时核对 TLSH 字段语法覆盖。
- 检查数据构建、PELoader、训练循环、缓存、特征编码、掩码、线上聚合和热加载代码。
- 从当前源码 AST 提取实际函数，用合成数据复现切分与线上权重问题，不依赖真实模型运行。
- 运行已有稳定哈希独立测试脚本：输出为 8/11 passed；3 项因当前分析运行时缺少 torch、继而触发 hashing 导入回退失败。**不能据此宣称完整特征一致性测试通过，也不能据此断言生产环境存在相同故障。**

### 2.2 当前不能独立复现的结果

下列路径在本次工作区中不存在：

- `D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/analyze_retrain_manifests.py`
- `D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/plan_retrain_split.py`
- `D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_manifest_stats.json`
- `D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_split_plan_2026-11-12.json`
- `D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_selection_manifest_2026-11-12.csv`
- 工作区中的 `test2_eval` 原始评测目录。

因此，**T1/T2 精确入选数量、匹配后 AUC=0.5037、元数据 AUC=0.9656，以及附件模型 AUC/TPR，属于原材料报告值，不是本轮复跑模型所得值。** 本轮复核确认了原始规模和若干重复统计，但不能替代 selection manifest、逐样本预测和评测代码。

进一步只读检查 `retrain.zip`：压缩包仅含原计划与六份 CSV，没有上述脚本、selection manifest 或原始评测证据；包内计划与工作区原计划的 SHA256 一致。

不要把“当前工作区和所附压缩包没有”扩大为“从未实现”；应补交对应版本、生成参数与输入指纹后重新核验。

## 3. 原始数据复核：哪些正确，哪些需要更正

| 项目 | 本次原始清单复核 | 对计划的影响 |
|---|---:|---|
| 恶意总行数 | 2,667,563 | 与计划一致；本轮此项统计的是行数，不独立声明 SHA 全唯一 |
| 良性总行数 | 40,000 | 与计划一致 |
| 良性 DLL / EXE | 33,572 / 6,428 | DLL 占 83.93%，构成偏差真实存在 |
| 恶意 DLL | 6,530 | 配平方案确实受到稀缺类供给限制 |
| 恶意 ssdeep 非空且格式通过行数 | **2,667,563** | 计划把 2,231,904 写成“有值数”，应更正 |
| 恶意 ssdeep 不同字符串数 | **2,231,904** | 这是去重后组数，不是字段覆盖率 |
| ssdeep 重复组 / 多余行 | 108,366 / 435,659 | 与计划一致 |
| 跨月 ssdeep 组 / 涉及行 | 54,307 / 389,256 | 与计划一致；是精确字符串组，不等于完整变体家族 |
| 良性 ssdeep 非空 / 不同组 | 36,974 / 36,974 | 无相同字符串重复不等于无软件版本近重复 |
| 原始良恶共享 ssdeep 组 | **4** | 其中 3 组是相同 SHA，另 1 组 SHA 不同；剔除已知同 SHA 标签冲突后仍不为 0 |
| 良恶交叉 SHA256 | 4 个哈希 | 与计划一致；应排除两侧记录并保留审计，不随意改成训练类别 2 |
| 恶意 TLSH 格式通过行数 | 2,667,563 | 可以评估基于 TLSH 的候选近邻去重；语法通过不等于算法质量或家族标签可信 |
| 恶意名称有日期前缀 | **2,339,340** | 此适用子集内日期前缀与 date 无分歧 |
| 恶意名称无日期前缀 | **328,223** | 不能写“2,667,563 行全部通过名称日期交叉验证” |
| 良性 packer 非空 | **292** | 包含 UPX、VMProtect、.NET 混淆器等标注；计划“全空”不准确 |
| 恶意 >128 MiB | 536 | 计划 536 的恶意侧口径正确 |
| 良性 >128 MiB | 102 | 两侧合计为 638，排除流水账必须注明分母 |
| Sophos 批次 | 251,231 | 其中 >128 MiB 为 102；尺寸过滤后 251,129，解释了计划中的两种数量 |

其他修正：

- **新增待复核的跨类近重复候选：** 良性清单的 7-Zip（SHA256 `2fb898bacb587f2484c9c4aa6da2729079d93d1f923a017bb84beef87bf74fef`，581,632 字节，清单标为 exe64）与三月恶意清单样本（SHA256 `daaccfe9fa3d7674bc6d109cf3b55d02f964a9e058efc17a8efce9222db75ba9`，619,520 字节，清单标为 exe32）具有完全相同的 ssdeep 字符串，但 SHA/尺寸/类型标注不同。应单列为标签及清单质量复核项；核查原始文件、真实 PE 类型、软件来源与标注依据。**不能据此直接判定它们是同一个文件、同一家族，或哪一个标签错误。** 初始正式训练可将这一跨标签候选组隔离，避免未经审核把它分到不同 split。详细记录见 [跨类候选复核信息](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/cross_class_review_pair.json)。
- 恶意总字节数为 8,926,155,580,040，约 **8.926 TB（十进制）/8,313.13 GiB**。良性为 81,155,870,727 字节，约 **81.16 GB/75.58 GiB**。计划把 GiB 写成 GB，算力/存储预算应统一单位。
- `filetype=pe` 只能证明清单没有细分为 exe/dll，**不能直接证明 PE 头损坏或根本没解析过**；应重新解析样本内容。
- date 与文件名一致最多证明内部一致性，不能证明它是 first-seen、真正采集时间或样本产生时间。
- 恶意名称常同时包含多个家族名，可能是多引擎/多标签拼接。不要把它直接当成单一可信家族标签。
- 恶意 CSV 没有可直接供当前本地训练器使用的 path；良性 source_path 指向 Linux 样本库。必须实现样本定位、落盘、SHA256 与长度校验，不能把“清单存在”当成“样本已在训练机”。

## 4. 阻断级工程问题

### 4.1 P0：现有 month 映射会合并验证集和测试集

源码：

- [PELoader.load，第 268–281 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/data_loader.py#L268)
- [train_torch_model，第 257–265 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py#L257)
- [留出集评分与权重，第 822–873 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py#L822)

计划建议 train=1、val=2、test=3 后复用现有框架。实际行为是：

1. PELoader 取 `max(train_months)`，把更大的所有月份都放进 eval_months。
2. 设置 train_months=[1] 后，eval_months=[2,3]，验证集与测试集合并。
3. 没有正确设置顶层 metadata 时默认 max_train=3，可能使 1/2/3 **全部进入训练集**。
4. PyTorch 早停不是使用计划中的四月验证集，而是对训练矩阵随机抽约 10%；该抽样不保留近重复组完整性。
5. 训练器在合并后的 eval 数据上计算 AUC 权重并寻找最佳 F1 阈值；选择依据与计划要求的低 FPR 也不一致。

最小复现已确认：有 train_months=[1] 时 train=[1]、eval=[2,3]；无配置时 train=[1,2,3]、eval=[]。

**改进：** 引入独立 split 字段与 get_split 接口，训练器显式接收 model_val，校准器只读 calibration，最终评测器只读 test；取消 month 作为角色编码。若短期不能改框架，至少将 test 物理隔离在训练入口不可发现的目录中，并改写独立验证/校准入口。这是必须改代码的工作，不是改 metadata 就能完成。

### 4.2 P0：线上聚合不使用训练保存的权重

源码：[线上聚合，第 175–186、220–227 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/prediction_policy.py#L175)。当前逻辑：

- 只取 status=ok 的模型。
- 直接 scores_arr.mean(axis=1)。
- 固定阈值 0.5，AggregationMethod 固定 equal_weight_mean。

最小复现：模型分数 [0.9,0.1]、保存权重 [0.9,0.1]，线上函数返回 **0.5**，而非预期加权结果 **0.82**。

另外，[训练器的 --models/--exclude](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py#L657) 仅过滤本轮要训练的模型，不是生产禁用开关。训练失败后也可能保留基线模型继续保存候选。**“只训练五个模型”“某模型训练失败”都不等于它不再参加线上投票。** 通用离线 predict_all 还存在 special 槽位常量填充，不能直接等同于真实 MalGraph 推理覆盖。

**改进：** 训练与线上共用 DecisionPolicy，版本化保存 model_allowlist、weights、feature_contract、calibrator、threshold、fallback_profile；候选发布时验证每一项实际生效。严格拒绝非有限/负权重；失败模型不填 0.5；剩余权重归一化；无有效模型返回无法判定而非良性。fast/full/降级组合分别验证概率与阈值，不假设重归一化后仍自动保持校准。

### 4.3 P0：缓存不带特征版本，可能复用旧 BN/旧哈希数据

源码：[普通样本缓存键与命中判断，第 297–319 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/data_loader.py#L297)。非 IR 路径用 md5(path) 做键，命中主要判断文件是否存在。没有在普通缓存身份中绑定内容 SHA、后端、特征版本、掩码与分析预算。

**改进：** 不必启用 ProgramIR 就能给现有路径加 schema/fingerprint。样本缓存绑定内容 SHA+后端版本+提取代码版本+分析预算；视图缓存另绑定维度顺序、dtype、变换与掩码；模型清单声明输入契约。T1/T2 建独立新缓存命名空间，旧缓存隔离保留，不破坏性覆盖。

同时去掉“跨月份维度不一致自动右补零”的默认容错：见 [build_matrix，第 204–213 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py#L204)。正式训练应因契约不一致而失败，不应把错位特征补成看似可用的数据。

### 4.4 P1：同一 SMDA 名称不等于同一特征契约

- [训练批量提取，第 776–785 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/feature_extraction/extract_feature.py#L776) 默认分析预算为 180 秒。
- [线上分析 worker，第 103–113 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/analysis_worker.py#L103) 使用外层 analysis_timeout，附件场景达到约 600 秒。
- [训练侧视图拼装，第 1120–1127 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/data_loader.py#L1120) 没有调用推理侧 apply_view_mask。
- [推理掩码](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/view_masking.py#L24) 是环境变量驱动的实验开关，默认关闭。

**改进：** 固定相同样本字节、库版本、反汇编配置、指令排序、预算、部分分析策略、截断长度、维度顺序与 dtype。整数/token 要精确一致，浮点是否要求位一致或容差一致应显式定义；跨平台不盲目承诺所有浮点逐位相同。还应扩展检查 A/C/F/G 等 fast 特征，不能只检查 D/E。

## 5. 数据切分与采样方案应怎样改

### 5.1 严格时间切分：不移动未来样本

原方案“跨月 ssdeep 组折叠到最早月份”可能把五月变体搬到一月训练集；虽然 split 间没有共享组，却泄漏了未来内容。

建议提供两套明确命名的评测：

- **严格新组时间外推：** 一至三月训练，只取实际观测时间在窗口内的行；四月验证排除训练已见组；五月测试排除训练/验证已见组。跨窗口后续记录排除或进入复现/重复样本监测集，不回迁到早期训练。
- **业务时间回放：** 同样不把未来记录用于训练，但保留未来再次出现的组；同时报告 seen-group/new-group 指标，不能把它称为组完全隔离测试。

日期字段先补 timestamp_kind 与来源说明。良性按软件/发布者/版本谱系和近重复组切分；明确这不是良性时间外推。若能补充之后月份的新良性数据，另建真正时间外推集。

### 5.2 精确 ssdeep 分组是起点，不是完整近重复去重

ssdeep 有独立的相似性比较机制，两个近似文件并不要求产生完全相同的签名字符串（方法依据见附录）。当前“ssdeep 相等分组”只能覆盖部分重复。

建议：先 SHA 去重与标签冲突隔离；再通过 filetype、尺寸、块大小等候选分桶，评估 ssdeep 相似度/TLSH 距离聚类。阈值应在开发样本中核验，不对 267 万样本做全量两两比较。采用连通分量时检查链式误合并与巨型组。不能把 imphash 或 TLSH 单独等同于真实恶意家族。

**原计划关于 imphash 的工程论证也需更正：** [group_key，第 241–259 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/build_minimal_dataset.py#L241) 会从原始 PE 计算 imphash，失败再用前 64 KiB 内容散列，并非只读取 CSV 中的稀疏 imphash 列。manifest 稀疏不能直接证明此函数的分组键同样不可用；但其合成月份和按 label 分组逻辑仍不满足本轮要求。

### 5.3 将匹配训练、代表性评测、低误报验收分开

建议数据资产分为：

| 资产 | 用途 | 关键约束 |
|---|---|---|
| matched_train / matched_model_val | 对比数据构成与特征修复的受控实验 | 时间合法、组隔离、标注可追溯 |
| calibration | 选择集成权重/概率映射/工作点 | 不与最终 test 重叠，内部可采用分组交叉拟合 |
| temporal_test | 一次性最终泛化比较 | 锁定后不反复择优，基线与候选在完全相同样本上比较 |
| benign_acceptance | 验证低误报上界 | 足够多的独立、可信良性，包含 EXE、DLL、加壳正常软件及实际来源 |
| source_ood | Sophos 等跨来源鲁棒性 | 该批目前只有恶意；只报告召回、覆盖、失败与时延，不能单独估计 FPR/AUC/ECE |
| recent_shadow | 发布前的近期分布检查 | 若有条件，补 2026-06 至 2026-11 的独立数据，勿用一至五月代表十一月流量 |

T1/T2 可继续作为**候选实验预算**，但严格时间去重、真实 PE 解析、数据可获取性和留出验收集都会改变可用数。12,430 对是原规则下的报告产量，不是一般意义的数据价值或训练规模上限。

训练中可以对更多恶意样本做分层权重/组内限额、轮换采样或 hard-negative 对照，不必永久抛弃所有未匹配恶意记录；这需要独立实验，不能未经验证替代 matched 对照。

### 5.4 修改“语义能力已经被证明”的表述

以下推论不成立：

- 新 CSV 上 metadata AUC=0.9656 大于另一批 6,160 样本上模型 AUC=0.9571，不能证明后者主要依赖元数据。数据集、切分与样本构成都不同。
- 仅用 filetype+大小的逻辑回归 AUC 接近 0.5，不能证明所有捷径已消除，更不能证明模型只学习代码语义。
- 匹配粗尺寸桶不等于桶内连续尺寸完全独立；来源、软件谱系、编译器、签名、加壳、采集与解析成功状态等仍可能泄漏标签。

建议将 D1 重命名为“已知元数据捷径诊断”。在相同 split 上比较逻辑回归与可拟合非线性交互的轻量基线；检查 AUC 是否接近 0.5，避免单独用 AUC<=0.55 把反向可分的 0.1 当成合格。补充分层消融和同批候选/基线配对差异；最终表述为“超过所测元数据基线”，不要扩大为“语义已证明”。

“自然先验 1:1”也应改名为“保留原 filetype 构成的 1:1 对照集”，它并不等于生产恶意率或真实流量先验。

## 6. 附件报告：哪些结论能用，哪些需要降级

### 6.1 可以指导候选优先级，但不是上线承诺

附件第 5 页提供的历史报告值：

| 历史集成 | AUC | TPR@10^-3 | TPR@10^-4 |
|---|---:|---:|---:|
| 33 模型等权 | 0.9571 | 0.1036 | 0.0055 |
| 仅 fast 23 模型 | 0.9577 | 0.1720 | 0.0189 |
| family_weighted | 0.9595 | 0.1424 | 0.0326 |
| 按低 FPR 选择的 Top5 | 0.9541 | 0.3115 | 0.1176 |

因此优先对比 fast、低 FPR Top5、family-weighted 是合理的；但**不应把 family_weighted 写成唯一必须通过的配置**。它在历史第一指标上并非最优；且该集已参与模型筛选，属于开发证据，不能再当完全未触碰的最终测试集。

当前报告的单模型覆盖集不同：D/E 覆盖 6,042，MalGraph 5,579，fast 6,160。比较模型能力要同时给相同交集上的配对结果与全请求集合上的端到端结果，不能忽略失败覆盖差异。

### 6.2 校准不能凭空改变单一分数的排序

附件第 9–11、22–24 页将部分模型的低 FPR 改善归因于温度、秩变换或 Platt 重标定，并给出数倍提升预期，需要撤回此保证。

严格递增的单变量变换保持排序和可实现的 ROC 工作点集合，所以不会单独改善该分数的 AUC 或可达到的 TPR@固定 FPR；isotonic 可能引入并列分数，也不保证改善。它能改善概率含义、固定数值阈值对应的工作点和校准误差。**逐模型校准后重新融合、分组路由或重训**可能改变最终排序，但那是不同实验，应单独归因。

统一使用术语“保序回归/isotonic calibration”，不要把它与“等距”混用。

### 6.3 旧权重掩码收益不能决定新权重的永久输入

附件实验 A 的同批结果是 0.5688→0.6108，不能与全量表 0.5478 混写成同一次提升。当前 D02/D03 已使用稳定 CRC32；对新权重应至少比较：

- A：旧模型+原线上特征；
- B：旧模型+推理掩码；
- C：SMDA+稳定哈希全特征重训；
- D：SMDA+稳定哈希、D02/D03 同步屏蔽重训。

C/D 都必须与各自部署预处理完全一致。选择依据是独立验证结果，而不是历史旧权重的噪声抑制结果。

### 6.4 图模型 BN 对齐只是低成本候选，不是已证实修复

附件把它称为零重训可行，但报告没有给出实验 B 的独立效果。当前 [GraphStatNet，第 49–57 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/models/GraphStatNet_2022/graph_stat.py#L49) 是 Linear→BatchNorm，不是直接对 22 维输入做 BatchNorm。隐藏层统计反推输入矩只在特定假设下可用；缺少协方差与误差验证时，“残差小”不能证明反演分布唯一或能消除反汇编语义差异。

允许在开发数据上做 running stats 重估对照，但属于模型状态适配，应版本化、禁止使用最终测试数据拟合，并与从零训练的 22 维简单基线比较。

### 6.5 其他报告口径修正

- 分数方向应统一为 P(malicious)：当前代码分数越高越恶意。附件与计划的“DLL→分数高，导致压到 0.5 以下”表述自相矛盾，应改为“恶意分数偏低的假设”，并通过匹配对照验证因果。
- DLL 召回低且良性 DLL 多是风险证据，不足以单独证明根因就是先验；还可能有样本来源、组重复、特征与阈值问题。
- 报告不同段落用到 3,091 与 2,865 个良性，后者是有特定 platform 标签的子集；任何比例都要标清分母。
- HashEmbedNet 在 [快速提取器第 413–457 行](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/feature_extraction/extract_feature.py#L413) 使用导入表摘要、块摘要、字节统计代理与 Rich header，不是“直接对整个文件 SHA256 做泛化分类”。G02/G03 的 ssdeep-like/TLSH-like 也不是真正的清单 ssdeep/TLSH。
- 低 AUC、低 std、低 ECE 分别反映不同问题。不要仅凭 std<0.03 或某模型 AUC 高低确定上线价值，也不要未经标签方向核查就把输出取反。
- max_score 在这份报告的配置下很差，可以禁用该候选；无需把结论扩大为所有模型/任务下都绝不可用。

## 7. 重写低误报验收门禁

### 7.1 现有测试量不足

在阈值预先固定、试验近似独立同分布的二项假设下，n 个良性样本零误报的 95% 单侧精确上界为：

`p_upper = 1 - 0.05^(1/n)`

| 数据量 | 良性 n | FPR 最小非零步进 | 零误报的 95% 单侧上界 |
|---|---:|---:|---:|
| T1 test（计划） | 630 | 0.0015873 | 0.0047438 |
| T2 val（计划） | 1,792 | 0.0005580 | 0.0016703 |
| T2 test（计划） | 1,651 | 0.0006057 | 0.0018129 |
| 附件全量 | 3,091 | 0.0003235 | 0.0009687 |

所以，附件的 10^-4 可以作为经验 ROC 尾部描述，但无法用 3,091 个良性可靠认证该误报率；是否用了线性插值、零 FPR 点或最大允许 FPR 点，也需要评测源码确认。

若零误报，要把该上界压到 10^-4，至少需要 **29,956 个独立良性样本**；这是特定假设下的最低数量，不是充分的业务代表性保证。软件家族相关性、阈值在同集选择、逐组多重比较都会使简单数量结论过于乐观。

### 7.2 建议门禁

| 门禁 | 替代判据 |
|---|---|
| 数据隔离 | 训练/模型选择/校准/最终测试角色明确；SHA 与已定义近重复组无违规交叉；无未来样本回迁 |
| 历史污染 | 对候选和保留基线的历史训练 SHA/组清单做交叉核验；无法取得时明确标记旧良性复用风险 |
| 契约一致 | 特征 schema、维度、编码、预算、mask、标准化在训练与服务间验证一致 |
| 单模型晋级 | 与同 split 的旧模型/简单基线配对对照，报告不确定性；AUC 目标作为研发目标而非跨数据集硬搬 |
| 集成晋级 | 在固定业务工作点，以配对的召回增益、误报非劣、DLL 等重点子集及覆盖/时延综合判定 |
| 低 FPR 发布 | calibration 固定阈值后，在独立 benign_acceptance 报 FP/n 和单侧精确置信上界；不足则不承诺 10^-4 |
| 概率校准 | 在代表性留出数据报告 reliability、ECE（注明分箱）、Brier/LogLoss，不只凭 ECE<=0.15 |
| 缺失处理 | 100% 样本有可追溯状态；失败/超时不填成有效特征或当良性；fast/full/fallback 均可验证 |
| 回归 | 同一运行契约下单样本/批处理共享模型分数一致；fast 与 full 的共同模型一致，不强求集成总分相同 |
| 发布完整性 | 权重、输入 schema、允许模型、校准、阈值、签名/路由策略打包版本化并一起回滚 |

filetype 分组阈值不是无条件必须：T2 分组后样本更少，应先验证全局工作点；只有数据足够且验证集显示稳定收益时，采用 EXE/DLL 分组校准，稀疏组向全局收缩，不足时返回全局策略。恶意家族单组通常只有正样本，应报告固定工作点召回和区间，而不是在纯正例中计算 AUC/FPR。

## 8. 推荐的分批实施顺序

### R0：先修契约与数据工具（阻断项优先）

交付：显式 split、清单生成/校验器、样本定位器、缓存 schema、共享 DecisionPolicy、独立评测器。复核每条入选样本存在、SHA/长度正确、PE 有效、标签来源可追溯；冲突与排除原因有流水账。

先建立固定小型契约回归集，包含 EXE/DLL、x86/x64、加壳、短文件、稀疏导入与预期超时等场景。超时样本用于验证降级，不要求每次强行成功。

### R1：冻结旧权重，先比较决策层候选

在新的开发/校准数据上对比：旧策略、fast-only、历史低 FPR Top5、family-weighted，以及少量受约束的非负融合权重。历史 Top5 为 MalConv、MalConv2、PEMinerRF、HashEmbedNet、EmberDNN，但这里只把它当候选，不预先认定赢家。

这一步能把“换集成规则”与“模型重训”收益分离，也比直接同时重训所有模型更便于定位回归。**不直接在生产改默认配置。**

### R2：T1 小规模特征修复实验

优先安排：

1. OpcodeStatNet 的稳定哈希 full/masked A/B。
2. 选择一个序列模型先验证固定编码、输入与标签对齐，再决定是否训练所有 opcode 深模型。
3. DrebinImport、ALOHANet、EmberGBDT_Import、DrebinString、RaffFeatureNet 的稳定哈希重训，补训练期拟合且可部署的尺度变换。
4. 22 维图统计先比较一个简单树/MLP 与一个现有代表模型，再决定另外几个图模型是否有互补价值。

T1 阶段不要求快通道 AUC 必须达到另一数据集的 0.93，不要求统计不可辨的 10^-4 门禁。目标是确认链路、输入契约、无泄漏与有方向明确的受控收益。

### R3：T2 或修订规模的候选正式训练

- 保留经过独立测试的主力模型，先只替换验证成功的模型。
- 不将全部退化模型无条件列为必须恢复；InceptionV3/IMCFN/DL4MD/DrebinSVM 先诊断标签、输入尺度、输出方向与训练状态，再决定重训或停用。
- 不因单模型 AUC>0.8 就自动加入集成；考察低 FPR 的互补召回与额外误报。
- MalGraph 维护外部权重/词表/输入契约，必须在独立真实推理路径中测覆盖与增益。
- 真图拓扑、ProgramIR 和架构升级延后独立立项，不夹进本轮收益归因。

原计划清单还需补全：EntropyMapCNN、GrayscaleCNN、MetadataNet、ResourceNet 的保留/禁用/重训决策；EmberGBDT_Import 在 P1 与 P2 重复出现，应只保留一种明确动作。

### R4：独立验收与影子部署

模型选择完成后冻结权重和决策策略，再读取最终测试集。保留历史已见数据只做回归，不把其表现包装为新泛化能力。

同时验收两个层次：

- **模型能力：** 在隔离评测环境记录或控制签名库短路，按相同输入与标签评估模型分数。
- **产品能力：** 保留生产路由，分别统计数据库命中、签名命中、进入模型、unsupported、超时、错误以及最终 verdict。

项目有效 PE 可能在 Web 样本库或模型签名预检层命中，不能把这类直接返回算成重训模型的检出收益。

发布优先使用独立候选镜像/实例与流量影子验证，再切换。当前 [reload-model](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/app.py#L1968) 主要加载集成对象并更新模型路径，不自动承诺特征代码、环境掩码、校准器和阈值同步升级；跨 schema 改动不能只靠更换 pkl。

## 9. 资源预算：改成实测吞吐，不用 p50 乘核数

计划的“80 核、特征 1–2 天、训练 2–4 天”目前没有目标机器和该采样集上的吞吐证据，应标成待压测估计。

建议先取独立的 500–1,000 个开发样本做分层 pilot，覆盖 filetype、尺寸、来源和长尾；记录每阶段 mean/p50/p95/p99、失败重试、RSS、磁盘吞吐、缓存体积与有效并发。按 CPU 与内存约束逐步提高 worker 数，不直接开 80 workers。

资源模型：

`总墙钟 ≈ 样本数 × 实测平均服务时间 / 有效并发 + I/O + 重试 + 训练/评测`

需要关注：

- PELoader 的 V1 为 32,768 个 int32，T2 报告训练量 17,974 条仅该矩阵约 2.19 GiB；转 torch.long 又约 4.39 GiB，另有原矩阵、验证切片和其余视图。不能只按原文件 55.6 GB 估计内存。
- 训练器会汇总多视图矩阵；宜按当前训练模型需要的视图懒加载/mmap，避免训练一个模型也驻留全部视图。
- 图分析、解压缓存和 NumPy/BLAS/PyTorch 内部线程会造成过度并行；需要限制每 worker 内线程。
- 离线重试可以比在线更长，但用于部署训练的特征必须匹配在线预算/部分分析策略，否则会产生新的训练–服务偏差。
- 现有 SMDA 进程池主要依赖内部时间预算；建议增加可回收子进程、外部硬超时和可恢复状态，避免极端样本长期占住任务。

## 10. 最小代码改造清单（建议，不是已实现）

| 优先级 | 修改位置 | 最小交付 | 验收 |
|---|---|---|---|
| P0 | 新建采样/定位/校验入口 | 真实时间、组规则、样本 SHA/path 校验、排除账本 | 重跑清单一致，test 不回迁 |
| P0 | [data_loader](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/data_loader.py) | 显式 split、样本 ID 对齐、缓存身份 | val/test 不再落入同一 eval |
| P0 | [train_all](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/train_all.py) | 外部 model_val、独立 calibration、禁止读 test 选权重、失败状态门禁 | 训练日志与产物可追溯 |
| P0 | [prediction_policy](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/prediction_policy.py) | 共享加权/校准/阈值决策 | 离线与 HTTP 决策一致；权重改动真实生效 |
| P0 | 提取/拼接/模型序列化 | schema 与维度指纹、环境脱钩的预处理配置 | 错契约拒绝加载，而非默默补零 |
| P1 | [view_masking](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/view_masking.py) 及训练侧 | 同源变换，full/masked 显式版本 | 同批输入契约一致 |
| P1 | 新建统一评测器 | 逐样本分数/状态、固定阈值、FP 计数与区间、配对差异、分层报告 | 数量分母一致，可重算 |
| P1 | [contract_pipeline](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/engine/contract_pipeline.py) 与 Web 适配 | 路由、覆盖与无法判定状态审计 | 未运行/失败不算良性 |
| P1 | 发布与回滚 | 完整决策包与镜像版本 | 切换/回滚结果可复现 |
| P2 | 图拓扑/IR/更大架构 | 独立实验 | 不与本轮混合归因 |

清单建议至少保存：sample_id/sha256、label 与来源/置信、真实时间及时间类型、split、group_id 与规则版本、filetype 清单值/解析值、size、source、软件/家族弱标签、resolved_path、排除原因。特征与预测另记录 backend/schema、analysis_status、各模型 status、raw_score、policy_version。

“失败模型仍在旧权重中”“--exclude 只影响训练”“checkpoint 与本轮数据/schema 不匹配”必须由显式模型发布清单拦截，不能只看 ensemble.pkl 是否能加载。

## 11. 推荐的启动条件

**允许启动正式 T2 的最低条件：**

- [ ] 缺失脚本/清单已补齐，按当前代码版本复现；所有规模数字重新生成。
- [ ] 样本定位与完整性审计通过，标签冲突已隔离，历史训练重叠已说明。
- [ ] 时间不回迁，train/model_val/calibration/test 角色明确且可测试。
- [ ] 清空的是候选新命名空间，不复用不明旧缓存；输入契约验证通过。
- [ ] 线上决策层能真实应用候选 allowlist/weights/calibration/threshold。
- [ ] T1 的特征修复有同批、受控、可复现结果，而非只达某个历史 AUC 数字。
- [ ] 低误报验收良性集已落实；未落实则明确降低发布承诺，不以插值掩盖不足。
- [ ] 缺失/超时/部分模型失败的降级策略已单独验证。

**最终建议：将当前计划从“数据配平后按 33 模型重训”调整为“先修一致性和验收，再比较少量可解释候选，最后按增量业务价值晋级模型”。** T2 的作用是受控重训实验；独立的大规模良性验收集与近期数据，才决定能否宣称低误报上线改善。

## 附录 A：本次复核产物

- [清单流式统计](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/manifest_audit.json)
- [精确 ssdeep 分组复核](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/group_audit.json)
- [切分与线上权重最小复现](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/contract_audit.json)
- [压缩包及跨类 ssdeep 终核](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/final_evidence_check.json)
- [计划证据可用性](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/evidence_availability.json)
- [源文件指纹与范围](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/review_provenance.json)
- [稳定哈希测试日志](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-review-2026-11-12/stable_hash_test.log)

上述证据不包含新模型训练结果。分析环境缺少 torch，未验证生产依赖、真实 PE 特征、模型训练或 HTTP 端到端效果。

## 附录 B：材料与方法来源

### 本地材料

- [原训练计划](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/RETRAIN_2026_PLAN.md)
- [附件模型评估 PDF](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/最终模型详细评估报告.pdf)
- [良性 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/benign.csv)
- [2026-01 恶意 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/malicious_pe_2026_01.csv)
- [2026-02 恶意 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/malicious_pe_2026_02.csv)
- [2026-03 恶意 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/malicious_pe_2026_03.csv)
- [2026-04 恶意 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/malicious_pe_2026_04.csv)
- [2026-05 恶意 CSV](D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/retrain/malicious_pe_2026_05.csv)

### 方法核验（2026-11-12 查阅，非项目实测来源）

1. scikit-learn 官方 Probability calibration：严格单调校准与排序指标、isotonic 引入 ties 的区别。地址：`https://scikit-learn.org/stable/modules/calibration.html`。
2. NIST，Gilliam 等，Pass-Fail Testing: Statistical Requirements and Interpretations，2009：检测/误报的二项单侧置信检验及样本量要求。地址：`https://nvlpubs.nist.gov/nistpubs/jres/114/3/V114.N03.A05.pdf`。本报告零误报数值由展示公式自行计算，前提为阈值已固定且试验近似独立同分布。
3. ssdeep 官方项目说明：CTPH 的近似匹配机制与生成/比较接口。地址：`https://ssdeep-project.github.io/ssdeep/index.html`。
