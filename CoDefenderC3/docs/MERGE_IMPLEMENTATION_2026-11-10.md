# main / test_lm 定向合并实施记录

> **历史快照，不是当前部署指南。** 2026-11-11 文档核对：下方保留当时正文及测试/合并结论；其中端口、绝对路径、命令、模型数量和性能统计仅适用于记录中的版本与环境，不能作为当前运行或上线验收依据。
> 当前操作请使用 [启动与接口指南](README.md)、[训练指南](../train/README.md)、[测试指南](TESTING.md)及[文档索引](INDEX.md)。历史链接或命令可能已失效，请勿直接照抄执行。

<!-- historical-snapshot -->

日期：2026-11-10（Asia/Shanghai）。采用用户确认的 v3 取舍；本记录区分代码回归和真实生产验收。

## 1. 基线、工作区与合并方式

- main 基线：`908c53f472fc0f2c3b798f76c1129f27a3112436`。
- test_lm 来源：`126a4ef88f12e5727aa1211ca4604d67aceb47cb`。
- 初始方案基线 a28355c 之后的 aae3cd2、9b16e90、908c53f 是 main Web 更新，本次一并保留，而非恢复旧 Web。
- 集成分支：`codex/main-test-lm-integration`，基于 main 定向移植；**不是将 test_lm 全部历史合入的双父 merge**。
- 最终交付 worktree：`C:\Users\lenovo\.codex\worktrees\main-test-lm-integration\CoDefenderC3_v9`。
- 原工作区 `D:\VM_Share\CoDefenderC3_v9` 的受跟踪源码及用户原有未跟踪内容不覆盖。该工作区本地 main 原先仍指向 test_lm；不要把其目录误认成集成结果。
- 早期隔离克隆 `D:\VM_Share\CoDefenderC3_v9\_integration\main-test-lm-908c53f` 仅作中间副本；后续修复、验证和交付以当前 worktree 为准。
- 远端没有推送，也没有创建 PR。提交标识以本分支 Git 日志为准。

main 的 `docs/TEST_LM_BRANCH_ANALYSIS.md` 保持原样；其中建议迁移 MalGraph 的历史判断不执行。源码来源及例外见 `merge_main_test_lm_sources.json`。

## 2. 用户硬约束的落实

| 约束 | 实施及门禁 |
|---|---|
| main 顶层 web/ 完整不动 | 路径树、文件模式、工作区及索引零差异；原测试在临时镜像运行，不向冻结树写生成物 |
| main MalGraph 全链保留 | 模型目录、权重、词表、main SMDA 文件保持；loader/预测关键函数 AST 来源检查；生产/开发调用 main 特殊预测路径 |
| main V1_byte / V8_color | 32768 / 196608 视图优先；禁止按模型内部 Linear 维度二次截断；单条、批量、Web 回归覆盖 |
| test_lm 四个接口 | 生产与开发的单条/目录路由、有效模型聚合、分档命名、生产裁剪与开发明细接入 |
| main 运行时安全 | 一个模型注册表、设备迁移、视图掩码、ScanRuntime；超时/断连仍持有真实任务槽位，临时文件随真实工作结束清理 |
| 非 MalGraph IR | 默认关闭、features-only、独立内容/版本缓存，不重接 MalGraph |

冻结对象：

- Web tree：`49ee7604eaad04ebf7a110d426c1c0620d9ef5c8`。
- MalGraph tree：`7f80450e41ba9c08babeb218712d2c9eb9e1c474`。
- main smda_extract.py blob：`0b39872da985479dac21376af6622a608670ec00`。
- 另外核对 15 个 main 核心函数 AST 和 main 公共结果格式器。门禁只检查、报错，不自动 restore/reset/删除文件。

## 3. 三入口、一个推理核心

| 入口 | ASGI 对象 | 默认绑定 | 契约 |
|---|---|---|---|
| Web 兼容 | engine.web_compat:app | 0.0.0.0:8000（容器侧） | main 完整结果、二分类、原 NDJSON /predict-stream |
| 生产 | engine.app:app | 127.0.0.1:18001 | test_lm 生产单条/目录精简字段；无完整 stream 路由 |
| 开发 | engine.dev.app:app | 默认关闭；启用后 127.0.0.1:18002 | 单条/目录完整诊断、模型状态及排除原因 |

完整镜像/源码部署使用 `python -m engine.serve` 在同进程/同事件循环启动上述监听器，模型预热仅一次；先绑定全部端口，冲突即拒绝启动，不留半套入口。不要为三种契约启动三个独立 uvicorn worker 来复制 CUDA 模型。

旧 `docker/Dockerfile.runtime` 是 v8 增量兼容覆盖，只维护既有 Web 协议，不自动提供三入口或 IR 候选；默认分析路径不依赖未随旧镜像分发的 IR 模块。

默认开发 API 关闭，设置 `CODEFENDER_ENABLE_DEV_API=1` 开启。生产绑定可用 `CODEFENDER_PRODUCTION_HOST/PORT` 配置；开发端口可用 `CODEFENDER_DEV_PORT` 配置但主机固定 loopback。健康、就绪、指标和管理接口复用 main 行为；对外暴露生产时必须沿用已有鉴权/网络隔离，不能因为生产预测结果裁剪就认为管理接口已受保护。

### 3.1 保留 Web 的既有地址，而不是盲目按端口号接线

main 的 `web/config.example.ini` 使用宿主机 `http://127.0.0.1:8001`，可选 worker 为 8002。**宿主机端口不等于容器监听端口**。

- Docker：现有宿主 8001 → 容器 8000（另一个 worker 可为宿主 8002 → 容器 8000）的映射保持，容器 8000 始终是 Web 兼容入口。未改任何 Web 部署文件。
- 原生：将引擎侧 `CODEFENDER_WEB_COMPAT_PORT` 设为 Web 原来调用的端口。例如使用 main 示例配置时设为 8001。若既有配置是其他端口，则保留那个端口，不要求修改 Web。
- 生产/开发默认 18001/18002，避免抢占现有 Web worker 的宿主 8001/8002。不要把宿主 8001 改映射到生产精简入口。
- Docker 的 EXPOSE 不等于发布端口。生产默认仅容器 loopback，旧 Web 部署不会自动暴露新生产入口。确需访问时应在**引擎部署层**单独设置 host、端口映射与访问控制；本轮未修改已有部署或启动真实服务。

PowerShell 原生启动示例（从集成 worktree 的 CoDefenderC3 目录执行）：

```powershell
$env:CODEFENDER_WEB_COMPAT_PORT = '8001' # 仅当这是既有 Web 的引擎端口
$env:CODEFENDER_NON_MALGRAPH_IR = '0'
python -m engine.serve
```

需要同时调试开发接口时先设置 `$env:CODEFENDER_ENABLE_DEV_API = '1'`。独立开发脚本 dev_model_only.cmd/.sh 改用 loopback 18002；它会加载独立模型，仅用于独立开发，不与共享启动器重复运行。

## 4. 接口业务与必要适配

- 单条和目录共用准备、真实行分组批推理和格式化策略；批失败后逐行重试，不补 0.5 或伪造全零有效样本。
- 仅注册模型中 status=ok 且分数有限的结果进入等权均值，按注册顺序聚合；无有效模型明确失败。
- 判恶阈值严格为 score > 0.5。score=0.5 为 Benign；默认分档 Low=(0.5,0.62)、Medium=[0.62,0.78)、High≥0.78；哈希库命中名为 Malicious。
- SDD 仅在有效列覆盖完整注册顺序时调用，防止部分矩阵错配基线列。
- Web 保留 main 的公共 engine.result_formatter 和完整结果格式器；test_lm 的格式器放到独立 production_result_formatter，避免污染 main 原导入契约。
- 生产仅在 HTTP 边界投影；开发保留 PerModelScores、ModelStats 和排除原因。2026-11-10 后续按要求隐藏 PerModelPreds、AggregatedModels、PerModelDetails（仅开发响应边界，详见 DEV_RESPONSE_FIELDS.md）。单条超时/全失败不裁成“良性成功”。
- 目录结构识别有效 PE（含无扩展名文件），支持 recursive 和 MAX_BATCH_FILES；失败/超时不计入成功良性数。
- main/开发目录 ErrorCount 和 TimeoutCount 分开；生产因不暴露 TimeoutCount，将其并入 ErrorCount，保证计数闭合。
- 目录时间为特征耗时 + batch forward 均摊 + 格式化，明确标注 TimingMethod，不冒充逐样本独占模型耗时。
- 原 main Web 流式协议和事件名称不改；单条 Web 使用 main 路径，目录 Web 使用共享安全扫描并保留 main 命名/格式。

## 5. IR 与训练候选

当前 IR schema 为 codefender-ir/2，完整保留往返字段，拒绝空函数/指令及不完整、非有限 D/E。缓存身份包含内容 SHA256、后端/版本、分析配置、features profile、adapter/IR/cache schema，特征层另加 feature schema；锁、校验摘要、原子替换和损坏隔离避免不完整命中。

开关 `CODEFENDER_NON_MALGRAPH_IR=0` 默认关闭。候选不读取旧 bndb/path-MD5 缓存，不更换 main MalGraph；main fast C01 不接受 test_lm log1p 改法。训练仅复用校验后的逐样本缓存，候选月矩阵每次重建，超时与进程异常可重试，不自动丢弃缺失视图。

详见 `IR_CONTRACT.md`。真实后端及权重兼容性未验收，不可直接将候选设为生产默认。

## 6. 验证记录与复测

统一入口（在 CoDefenderC3 目录中）：

```powershell
python -B -X utf8 tools/run_merge_regression.py
python -B -X utf8 tools/verify_merge_freeze.py
```

本轮使用 D:\conda\envs\ml\python.exe，具体 Python/依赖版本、时间和原始输出见 `docs/test-records/main_test_lm_merge_2026-11-10.json`。测试固定 CPU、关闭真实签名库，使用合成 PE/轻量模型，Web 测试在一次性镜像执行。

| 回归 | 计数 |
|---|---:|
| IR 契约 | 17 |
| 稳定散列与 main C01 | 11 |
| 合并接口/缓存/训练编排 | 48 |
| main 原样 Web 测试 | 78 |
| 合计 | **154** |

另有三监听器真实 loopback HTTP 冒烟：一次模型预热、生产/开发/Web 的六个单条/目录请求、Web NDJSON 和生产 stream=404；以及冻结树和 15 函数来源门禁。这些不计入上表测试数。

所有 Python 源文件通过 AST 解析，新增 workflow 经 YAML 解析；CI 配置已添加，但**尚未在 GitHub 运行**。本地回归不能替代真实依赖/权重下的生产测试。

### 6.1 上线前仍需验收（本轮未完成）

1. 完整 ensemble.pkl 与生产权重/词表指纹对齐，真实 PE 黄金集、模型覆盖率、单条/目录一致性。
2. 实际 SMDA 与获许可 BN 差分；当前环境 SMDA distribution 不完整，未证明两后端等价。
3. CUDA 前向与显存/设备迁移压力测试；本轮 CPU 合成模型不代表 GPU 验收。
4. Docker 镜像构建及**未修改 Web + 实际端口/挂载 + 真实权重**端到端验证；本轮随机 loopback 监听测试不替代部署验收。
5. 精确率、召回率、AUC、耗时、超时率和内存阈值与批准的生产基线比较。

上述项完成前不宣布生产可上线、不开启默认 IR、不推送或部署。

## 7. 回滚与后续集成

代码按单个定向移植提交交付，可审查后合入真正 main。main 前进后先审查新增提交、重锁冻结基线和指纹，再重跑门禁；不得用旧树覆盖新的 main Web。

发布时记录代码/镜像、权重/词表指纹、三入口拓扑、配置和候选缓存 namespace。发生协议、模型覆盖率、运行时或精度回退时恢复旧引擎镜像与入口映射，关闭候选并保留候选缓存取证；不全局清缓存、不切换到 test_lm MalGraph。Web 源码从未修改，无需补丁回滚。
