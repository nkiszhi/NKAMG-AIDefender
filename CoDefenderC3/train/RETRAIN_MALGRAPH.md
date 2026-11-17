# MalGraph 专用重训入口（SMDA 隔离运行时）

## 状态与范围（2026-11-16）

已接通独立研究入口：真实 PE → SMDA CFG/FCG → 仅训练集词表 → 从零 HGNN 训练 → 外部验证选最佳权重 → 锁定权重/词表 → calibration 阈值选择 → 冻结 test 评估。

**不是 29,824 个样本的全量重训完成报告，也不是 33 模型集成发布入口。**
现有通用 train_all.py/retrain_run.py 的 MalGraph special 槽位没有在本次替换，生产 ensemble.pkl 不变。所有产物 deployable=false。

本次选样八组各 3,728，总数 29,824；dll/exe 来自 COFF DLL 标志，32/64 来自 PE32/PE32+ optional-header magic。**PE32+ 不等价于 x86-64**，architecture 字段单独记录实际 machine；不能用 Intel 后端错解 ARM/IA64。

## 运行时

- Python：D:\conda\envs\ml\python.exe（3.11.17）
- 隔离包目录：D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\outputs\retrain-balanced-3728x8-2026-11-16\runtime_dependencies
- 离线复用工作区 .dev\python-packages 中纯 Python 包：SMDA 5.0.2、demangle 0.6.0、dncil 1.0.2、dnfile 0.18.0、purepdb 0.6.0。
- 原生依赖仍使用 ML 环境 LIEF 1.0.0、Capstone 5.0.9；没有复制旧 Python 3.12 的原生 DLL。
- pefile 2024.8.26、NumPy 2.4.6、Torch 2.11.0+cu130、PyG 2.8.1。
- 本机 RTX 5090 的 CUDA 预检通过；指定 cuda 而不可用时明确失败，不隐式退 CPU。
- 不修改全局 Python 环境、不改生产依赖约束。独立入口使用 5.0.2，不能与旧 SMDA 4.3.10 或 BN 特征/图缓存混用。
- smda_dependency_lock.json 比对了 281 个本地纯 Python 文件与离线来源的 SHA256，并锁定 2 个 ML 原生二进制；这是本地来源核验，不是上游签名验证。

## 数据与图契约

D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\outputs\retrain-balanced-3728x8-2026-11-16\balanced_split_plan.json 是选样的四角色主计划；固定 seed 20261116，分层、exact-ssdeep 分组随机分割：

| 角色 | benign | malicious | 总数 | 用途 |
|---|---:|---:|---:|---|
| train | 8,948 | 8,948 | 17,896 | 训练、词表 |
| model_val | 2,236 | 2,236 | 4,472 | 每轮外部验证选权重 |
| calibration | 1,492 | 1,492 | 2,984 | 权重/词表冻结后的阈值选择 |
| test | 2,236 | 2,236 | 4,472 | 候选冻结后评分，不参与选择 |

这是随机研究划分，不是首次出现时间划分，不保证家族/近重复/软件谱系隔离；CSV 日期不能冒充 first_seen。目录标签没有独立质量复核。

- 仅静态解析，不运行 PE，也不为提取失败样本伪造节点、补零假图。
- Intel 后端限定 COFF machine 0x14c/PE32 与 0x8664/PE32+；其他架构显式拒绝。
- 每个样本独立 SMDA 子进程，有协作式分析超时和更大的硬超时；native status 必须 ok，不能把超时部分图当成功。
- 图为校验 SHA256 的 gzip JSON，绑定样本内容 SHA、提取源码、包版本、超时/后端、图摘要；不是不可信 pickle。
- CFG 特征严格 11 维有限非负，必须有真实指令，检查节点/边边界；FCG 采用实际 local call xrefs 和 direct API call references。
- worker 专用子类补上 SMDA getCodeOutrefs 不含的真实外部 API call 边，不改变生产 extractor。
- Windows 图缓存路径使用 extended-length path；单图 JSON 解压上限 256 MiB，最多 1,000,000 个 CFG block。
- train/model_val 图必须 100% 覆盖才可 fit；失败留在 cache_report.json，不静默跳样本。
- 词表只看 train 中外部函数名（raw dll!api 命名），上限 1,000；验证、校准、测试 OOV 回退，不扩表。
- HGNN：GraphSAGE / global_mean_pool，CFG 64-64，FCG 64-64，dropout 0.2，从零初始化。
- 保存 best/last checkpoint；加载使用 weights_only=True 和 strict state_dict。Python/Torch/CUDA RNG、优化器和历史可恢复；保持预先冻结的总 epochs，不通过 resume 延长实验或绕过早停。
- 显式 --resume 缺 last checkpoint 会失败；已有 checkpoint 不允许无 --resume 覆写。不同计划/源码/参数使用新 work-dir。
- train/retrain_selection.py 用 calibration 选择 F1 阈值（并列时更少 FP、再更高阈值），0.05~0.95 步长 0.05，严格 score > threshold。不是概率校准拟合或低 FPR 认证。
- evaluate-test 校验固定候选、词表、最佳权重和训练相关源码身份，再访问既定 test；不重拟阈值、不自动部署。

## 命令

以下 PowerShell 参数使用当前工作区的绝对路径。preflight 使用自己的目录，不要与正式 train 共用目录。

~~~powershell
$Python = 'D:\conda\envs\ml\python.exe'
$Project = 'D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\CoDefenderC3'
$Output = 'D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\outputs\retrain-balanced-3728x8-2026-11-16'
$Entry = "$Project\train\retrain_malgraph.py"
$BaseArgs = @(
  '--plan', "$Output\balanced_split_plan.json",
  '--package-path', "$Output\runtime_dependencies",
  '--device', 'cuda', '--workers', '4',
  '--analysis-timeout', '60', '--hard-timeout', '100',
  '--batch-size', '4'
)

# 当前已验证的预检目录；再次运行须 --resume，不能覆盖已有预检权重。
& $Python -X utf8 $Entry preflight @BaseArgs --work-dir "$Output\malgraph-ready-v3" --resume

# 正式全量入口顺序（目前有下述适用性阻塞，解决后才能完成）：
$Full = "$Output\malgraph-full"
& $Python -X utf8 $Entry cache @BaseArgs --work-dir $Full
# cache 非 100% 覆盖会报错，不能忽略错误继续训练。
& $Python -X utf8 $Entry train @BaseArgs --work-dir $Full --epochs 20 --lr 0.001 --patience 5
# 中断恢复时使用同一计划/所有参数和 --resume，epochs 仍是原定 20。
# & $Python -X utf8 $Entry train @BaseArgs --work-dir $Full --epochs 20 --lr 0.001 --patience 5 --resume
# 候选完成、全部身份锁定后才执行，不能把 test 用于试参数。
& $Python -X utf8 $Entry evaluate-test @BaseArgs --work-dir $Full
~~~

入口不隐式生成新划分。主计划已从核验完成的 selection.jsonl 生成，并在加载时核验样本完整覆盖、原选样字段及角色/分组隔离。不得手改计划来规避检查。

## 已执行的证据

- 18 项 MalGraph 回归通过；test_retrain*.py 共 225 项通过。
- malgraph-ready：16 个真实主 train/model_val PE 的原始 native 图全部成功。
- malgraph-ready-v3：复用同一版本契约的上述图，最终代码 CUDA 1 epoch forward/backward、best 严格重载和 resume 通过（8 train + 8 model_val）。
- smda_de_smoke.json：8 个主 train 样本，D01–D07、E03/E04 实际提取通过，维度、有限数值及 native 函数/块数量一致。**不是全量 D/E 覆盖证明。**
- malgraph-integration-selftest-v3：16 个上述已见样本，隔离重分 8/4/2/2，CUDA 2 epochs、锁权重、calibration 阈值、冻结 evaluate-test 全链路通过。它的 test 仅为接口自测，不是独立性能验收；结果包含 integration_selftest_only_not_independent_acceptance。
- 原主计划 calibration/test 样本未用于本轮特征提取或质量评估；选样时的 PE/SHA 核验并不冒充训练。
- 老失败/中间版本目录保留审计，不是当前版本候选；不要复用其中旧 trainer 指纹的 checkpoint。
- 生产 ensemble.pkl SHA256 仍为 c7c20bb80ebb24372c5dedc0880fec49fd82020cf7da18056ed3bf0d995849c4。

## 当前全量阻塞（未擅自处理）

主 train + model_val 22,368 个样本的 PE 头审计：396 个 entrypoint=0 且可执行 section raw bytes=0 的无代码候选，86 个非 Intel 架构候选（ARM、IA64、未知 machine）。两类可能重叠，不相加当唯一失败总数；这是头部适用性审计，**不是全量 SMDA native 成功/失败报告**。

先前小文件边界预检实际有 6 个 SMDA 无函数失败，说明现有必须有真实 CFG 的 HGNN 无法自然覆盖所有 PE。不能假图填充、错解 ARM 或静默排除来声称全量成功。

malicious/dll64 的当前去重选样池恰好 3,728，主 train/model_val 已有 2 个非 Intel 样本。若限定可解析 Intel 并保持 3,728 配额，需要补充同类型恶意样本；无代码和其他不可解析样本策略也需明确。尚未审计主 calibration/test 图适用性。

其余 32 个模型的全视图覆盖与正式训练、33 模型共同权重/校准协调及 special 槽位集成仍未完成。不要将本专用入口通过等同于 33 模型全量 ready。


## 2026-11-17：显式审计部分覆盖（方案二）

默认 `--coverage-policy strict` 仍要求 100% 覆盖。用户授权的新启动入口是
`run_audited_malgraph_retrain.py`，显式启用 `audited_partial`，不得覆盖旧 job 或生产模型。

- 保留原 selection 和四角色 plan，train+model_val 合计覆盖率至少 95%；每 split/label/PE类型分层至少 90%。不额外设置单个 train/val 角色 95% 总门禁。
- calibration、test 各自要求总覆盖至少 95%、各分层至少 90%，政策在首次训练之前冻结，不依据 test 分数调门禁。
- 仅允许排除无可解析函数、不支持架构、SMDA native error/timeout、worker 硬超时、固定图资源上限。未知异常、源 SHA/时间戳变化、依赖/契约错误、缓存损坏、OOM/非有限梯度均停止。
- 旧完整报告复用前检查报告身份、源 SHA/时间戳、成功缓存 SHA 和实际图有效性，并复制到新工作目录。旧缓存只读，原样本不执行。
- `coverage_policy.json` 冻结四角色政策；`train_val_eligibility.json`、`calibration_eligibility.json`、`test_eligibility.json` 逐样本记录成功/排除/原因/源标签和类型/缓存 SHA，并保存人口覆盖率和分层统计。清单及 source SHA 纳入 frozen_run / candidate / resume 门禁。
- 词表只从可用 train 构建，每轮完整使用冻结可用 train；最佳权重和词表锁定后才提取 calibration，候选及阈值锁定后才提取 test。
- 指标为“可评分子集条件指标”，同时报告 population、scorable、abstentions、coverage、分层统计；排除项不计为正确、不生成补造分数。
- 新任务 batch_size 默认为 1（个别真实图接近百万基本块），不允许遇 OOM 后偷偷排除训练样本。
- 进度写入 job/status.json 与 job/malgraph/status.json：缓存核验/词表/每100样本训练与评分/epoch指标。词表或导入阶段不代表优化器已开训。
- 仅重训 MalGraph；其他32模型与联合集成仍未启动；deployable=false。

### 启动（示意）

使用 ML Python 执行启动器，传 `--plan`、`--readiness`、`--job-dir`、`--package-path` 和 `--source-cache-report`。
启动器顺序为 import-cache → train（含 calibration）→ evaluate-test；前阶段非零立即阻断。
续训只对同一冻结清单和同一代码/超参使用 trainer 的 `train --resume`，不要重跑 import-cache。
