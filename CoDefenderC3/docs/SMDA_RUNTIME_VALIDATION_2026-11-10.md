# 引擎默认 SMDA 与真实运行验证（2026-11-10）

## 结论与交付边界

本轮在集成 worktree 中完成代码变更、项目内运行环境补齐和真实 PE 静态验证。
**不是原 D 盘服务的原地升级，也没有重启用户既有服务；没有构建/部署 Docker，没有推送。**

- 引擎默认后端为 SMDA；显式 BN 被保留；拼错后端启动即失败，不静默换后端。
- 真实 ensemble 的 32 个普通模型全部加载；main MalGraph 单独加载成功（合计 33 个），missing/unexpected keys 均为空。
- 16 个真实 PE 中 **15 个 D/E + MalGraph 验证通过、1 个失败**。JSON 总体 `passed` 为 false、工具退出码 1 是有意保留的真实失败，不能描述为 16/16。
- 其中 2 个 PE（s00、s02）跑通全部 33 个模型；其他成功 PE 跑通 9 个 D/E 模型 + MalGraph。
- 另用 x64 s06 做真实共享引擎 HTTP：3 个监听器、单文件和目录共 6 次请求全部成功，无 mock 权重或提取器。
- 本轮沿用 main 的提取器、MalGraph 模型/权重/词表、V1_byte/V8_color 维度逻辑，未引入 test_lm 的 MalGraph 实现。
- 顶层 web/ 完全不动；非 MalGraph IR 仍关闭。

## 1. 启动层变更

### 统一默认值

engine/startup.py 的 configure_disassembly_backend() 是统一入口：

| 输入环境变量 | 生效值 |
|---|---|
| 未设置、空串、纯空白 | smda |
| smda（大小写/首尾空白可规范化） | smda |
| bn（大小写/首尾空白可规范化） | bn |
| 其他值 | ValueError，拒绝启动 |

- engine/serve.py 在加载监听器前配置；engine/app.py 在 import config 前配置。
- 直接 uvicorn 运行生产、开发和 Web 兼容三个 ASGI 对象同样生效。
- 子分析进程继承环境变量。为兼容旧镜像/原 Web 回归，**未改 engine.analysis_worker.selected_backend({}) 的独立调用 legacy BN fallback**；受支持的引擎启动入口会先写入 smda，因此正常推理不会碰到这个空环境 fallback。
- /health 新增 disasm_backend，三个监听器均可查。
- start_codefender.sh 默认不再 import/激活 BinaryNinja；只有明确选 bn 时执行原 BN 环境和许可准备。
- SMDA 启动脚本与本地开发脚本不覆盖显式选择。
- 三份 SMDA Supervisor ini 不再在 environment= 中写死后端，避免覆盖 docker run -e CODEFENDER_DISASM_BACKEND=bn；容器 ENV 和 Python 启动默认仍是 smda。镜像若没有 BN，显式 bn 并不会自动安装商业库/许可证。

额外配置修复：新增解析回归发现原 GPU serve ini 含 UTF-8 BOM、GPU train ini 还残留 PowerShell `@'` 包装行，导致标准 INI 解析失败。本轮去除这些文本包装，保留其他参数；这只确认配置语法可解析，不等于已完成 GPU/Docker 运行验证。

### 本机解释器选择

Windows dev_model_only.cmd 按以下顺序选择解释器：

1. 用户显式 CODEFENDER_PYEXE；
2. 引擎根目录 .venv/Scripts/python.exe；
3. PATH 中的 python。

Linux dev_model_only.sh 对应使用 CODEFENDER_PYTHON → .venv/bin/python → python3。
开发入口仍只监听 127.0.0.1:18002，生产/开发/Web 契约及端口隔离未变。

## 2. 本地实际运行环境

引擎目录：

```text
C:\Users\lenovo\.codex\worktrees\main-test-lm-integration\CoDefenderC3_v9\CoDefenderC3
```

解释器：

```text
C:\Users\lenovo\.codex\worktrees\main-test-lm-integration\CoDefenderC3_v9\CoDefenderC3\.venv\Scripts\python.exe
```

- 基础环境：D:\conda\envs\ml，Python 3.11.17。
- .venv 使用 --system-site-packages，仅在项目环境新增 smda==4.3.10、dncil==1.0.2、dnfile==0.18.0；未改基础 Conda 环境。
- 复用 capstone 5.0.9、lief 1.0.0、torch 2.11.0+cu130、torch-geometric 2.8.1 等已有依赖。此次实际推理设备为 CPU，并非 CUDA 验收。
- pip check 通过。完整实际版本及本地新增包见 [环境记录](test-records/smda_environment_2026-11-10.json)。
- constraints-smda-validated.txt 固定本轮验证的反汇编依赖版本，可与 requirements.txt 配合使用；**不是完整跨平台锁文件**。不应把这个继承本机 Conda 的 .venv 直接搬到另一台机器。
- .venv 与 ensemble.pkl 均被现有 .gitignore 忽略，不应提交到 Git。

仅在同一台机器重建当前补充环境的 CMD 示例（不要在已存在的 .venv 上盲目重复创建）：

```bat
D:\conda\envs\ml\python.exe -m venv --system-site-packages .venv
.venv\Scripts\python.exe -m pip install smda==4.3.10 dncil==1.0.2 dnfile==0.18.0
.venv\Scripts\python.exe -m pip check
```

## 3. 权重与词表溯源

只从原项目补入缺失的 ensemble.pkl。main 自带的 MalGraph checkpoint/词表未替换。

| 制品 | 大小（bytes） | SHA256 |
|---|---:|---|
| ensemble.pkl | 771598004 | c7c20bb80ebb24372c5dedc0880fec49fd82020cf7da18056ed3bf0d995849c4 |
| main MalGraph best_model.pt | 1892386 | ddcf05645044bcdb339b043dd8c78a0cc2ec7950823079cabdd116d27370e585 |
| main MalGraph vocab | 362486 | 6c9e04b91416660bdb6a65d0151a7f400df166a462fcff8192de3bc9dc5e75e7 |

ensemble 源：D:\VM_Share\CoDefenderC3_v9\CoDefenderC3\ensemble.pkl。
目标位于上面的引擎目录。源/目标都实际计算 SHA256，完全一致。
MalGraph 使用 models/MalGraph_2022/best_model.pt 和 saved/train_external_function_name_vocab.jsonl；没有复制 test_lm 的 saved/best_model.pt。

加载验收：32 个普通模型均非 None；另加载 special MalGraph；没有隐式下载预训练权重。
MalGraph checkpoint 的 missing_keys=[]、unexpected_keys=[]。权重/词表绝对路径、哈希与模型列表均写入真实 PE 报告。

## 4. 真实 PE 的验证方法与结果

样本来源：D:\VM_Share\CoDefenderC3_v9\_pe_ascii，16 个本地 PE。
**只读取、解析和静态反汇编，未执行 PE、未上传样本。** 文件名里的 benign/malicious 沿用历史选样标签，没有独立重验标签，因此不据此宣称准确率。

验证工具 tools/verify_smda_runtime.py：

1. 清除测试进程已有后端值，让真实引擎启动代码写入默认 smda；禁用签名库、运行时配置覆盖和非 MalGraph IR，使用 CPU。
2. 通过 engine.staged_scan.isolated_analysis 调用真实隔离 worker，父/子分析预算均为 120 秒。
3. 验证 main 当前输出的 9 个 D/E 向量键、精确形状、finite、D01 非零和 D05 函数数大于零；不能用空字典或全零特征充当通过。
4. 验证 MalGraph ACFG 非空、基本块特征为 N×11、CFG/FCG 边索引合法；把已提取 sample 交给 main 原预测函数，不重复开新后端。
5. 用真实权重跑模型，要求每个被选模型 status=ok、分数 finite；任何缺失或错误都保留失败。
6. 全模型样本还检查 V1_byte=(1,32768)、V8_color=(1,196608)。

D/E 向量长度：D01=4096、D02=256、D03=256、D04=15、D05=12、D06=10、D07=6144、E03=12、E04=10。
main SMDA 的统计图视角使用 E03/E04，V7_graph=22；**没有宣称新增了 E01/E02 原始图输出**。
单独的 MalGraph 直接使用提取的 ACFG/FCG。无调用边的图允许为空边集；本轮检查其索引和可推理性，不保证函数/边语义与 BN 完全一致。

| 样本 | PE 位数 | D/E + MalGraph | 本地函数数 | FCG 边数 | MalGraph 分数 |
|---|---:|---|---:|---:|---:|
| s00_benign_32.bin | 32 | 通过 | 2565 | 0 | 0.590729 |
| s01_benign_32.bin | 32 | 失败 | — | — | — |
| s02_benign_32.bin | 32 | 通过 | 605 | 883 | 0.675667 |
| s03_benign_32.bin | 32 | 通过 | 1890 | 2879 | 0.782238 |
| s04_benign_64.bin | 64 | 通过 | 582 | 1184 | 0.586138 |
| s05_benign_64.bin | 64 | 通过 | 197 | 0 | 0.480231 |
| s06_benign_64.bin | 64 | 通过 | 236 | 308 | 0.580308 |
| s07_benign_64.bin | 64 | 通过 | 291 | 149 | 0.547006 |
| s08_malicious_32.bin | 32 | 通过 | 82 | 106 | 0.593774 |
| s09_malicious_32.bin | 32 | 通过 | 4293 | 11516 | 0.951628 |
| s10_malicious_32.bin | 32 | 通过 | 76 | 125 | 0.561872 |
| s11_malicious_32.bin | 32 | 通过 | 40 | 46 | 0.581609 |
| s12_malicious_64.bin | 64 | 通过 | 25 | 16 | 0.534734 |
| s13_malicious_64.bin | 64 | 通过 | 20 | 13 | 0.532702 |
| s14_malicious_64.bin | 64 | 通过 | 138 | 227 | 0.553882 |
| s15_malicious_64.bin | 64 | 通过 | 1847 | 6783 | 0.776082 |

### 失败样本不得隐去

s01_benign_32.bin，6144 bytes：CLR 元数据仅包含 Module、TypeDef、Assembly、ManifestResource，没有 MethodDef。
SMDA 4.3.10 的 CIL 分析路径对缺失的 MethodDef 进行迭代，触发 TypeError；引擎返回无有效 D/E 与 MalGraph 特征。
它是本轮发现的资源型 .NET PE 支持边界，不是依赖缺失或 checkpoint 加载失败。

- 本轮未为此修改受保护的 main SMDA/MalGraph，也未强制把 CIL 文件当 x86 字节来“凑通过”。
- 诊断见 [资源型 CLR 失败记录](test-records/smda_resource_only_pe_2026-11-10.json)。
- 全量真实 PE 报告保留 failed=1、passed=false；不能把剩余 15 个通过改写成全量验收成功。
- 若要扩大这类 PE 的支持范围，应另行设计资源/无代码文件的分类与降级策略，重新验收特征语义与权重精度。

## 5. 真实 HTTP 验证

tools/verify_smda_http.py 启动单个 engine.serve 进程，仅绑定随机 loopback 端口，测试完成清理自己的进程树，不碰用户已有服务。
测试样本为真实 x64 s06，真实 ensemble 与 main MalGraph 权重，无 mock。

- 三个 /readyz 和 /health 成功；health 均显示 smda，日志三个 listener 都属于 PID 9680。
- Web 兼容、生产、开发各跑一次 /predict-single?include_de=true 与 /predict-directory?include_de=true，共 **6/6 HTTP 200**。
- Web/开发四个完整响应均包含 33 个 status=ok 的模型，MalGraph 函数数大于零。
- 生产按原定契约隐藏模型明细；其单文件和目录结果与本次开发响应的对应精简投影完全一致，不把 HTTP 200 单独当作全部模型通过证据。
- 这是 Windows/CPU 的 model-only 引擎测试，**不是带签名库的生产部署验收**，也没有访问或修改顶层 web/ 的运行配置。
- 证据：[真实 HTTP 报告](test-records/smda_real_http_2026-11-10.json)。

## 6. 复现命令

以下命令均在上面的引擎目录执行。真实 PE 验证因为保留资源型 CLR 失败，预期退出码为 1；回归与 HTTP 工具应为 0。

```bat
.venv\Scripts\python.exe -B -X utf8 tools\verify_smda_runtime.py --sample-dir D:\VM_Share\CoDefenderC3_v9\_pe_ascii --ensemble-source D:\VM_Share\CoDefenderC3_v9\CoDefenderC3\ensemble.pkl --report docs/test-records/smda_real_pe_2026-11-10.json --full-models 2
.venv\Scripts\python.exe -B -X utf8 tools\verify_smda_http.py --sample D:\VM_Share\CoDefenderC3_v9\_pe_ascii\s06_benign_64.bin --report docs/test-records/smda_real_http_2026-11-10.json
.venv\Scripts\python.exe -B -X utf8 tools\run_merge_regression.py --report docs/test-records/smda_startup_regression_2026-11-10.json
.venv\Scripts\python.exe -B -X utf8 tools\verify_merge_freeze.py
```

运行本地纯模型开发服务：

```bat
set "CODEFENDER_DISASM_BACKEND="
dev_model_only.cmd
```

切回 BN（仅在当前解释器能够导入 BinaryNinja 且配置有效许可时）：

```bat
set "CODEFENDER_DISASM_BACKEND=bn"
dev_model_only.cmd
```

默认值变更只对**新启动的进程**生效；已有服务需要按部署流程使用本 worktree 与对应解释器重启。不要误连原目录的旧进程。

## 7. 冻结与剩余验收

- 原 154 项合并报告不覆盖；本轮新增 12 项启动回归，合计 **166/166 通过**（IR 17、稳定哈希 11、合并/启动测试 60、原 Web 测试 78）。共享监听器合成 HTTP、冻结校验另行通过。
- 本轮证据：[启动回归报告](test-records/smda_startup_regression_2026-11-10.json)。
- 冻结校验覆盖顶层 web/、main MalGraph 目录、main smda_extract.py、15 个 main 受保护函数及原 Web formatter。
- 真实测试设置 PYTHONDONTWRITEBYTECODE=1，未往冻结目录写入 pycache/测试数据。
- shell 脚本逐个通过 Git Bash bash -n；Windows .cmd 保持 ASCII。
- 尚未完成：真实 BN 对照/BN 许可验证、BN/SMDA 特征与预测差分、完整精度评估或重训练、CUDA/GPU、Docker 构建与生产签名库上线验收。
- main 的旧计时字段仍可能叫 binaryninja_seconds；此名字不是本轮实际使用 BN 的证据，真实后端以启动值、worker 路径和 health 为准。
