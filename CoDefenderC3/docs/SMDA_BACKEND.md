# SMDA 与反汇编后端

核对日期：2026-11-11。启动步骤见 [README](README.md)，训练步骤见 [训练指南](../train/README.md)。本文件说明实际接线，不承诺 BN/SMDA 特征逐位相同或固定性能提升。

## 1. 后端选择

共享启动 `python -m engine.serve` 在导入应用前执行 `engine.startup.configure_disassembly_backend`：未配置时设为 `smda`，仅接受 `smda` / `bn`；非法值拒绝启动。

- 训练 D/E、开发脚本、CPU/GPU SMDA 镜像均默认 SMDA。
- 标准镜像包含 BinaryNinja 基础环境与许可证，但**不意味着共享启动默认选择 BN**。需要 BN 时显式设置 `CODEFENDER_DISASM_BACKEND=bn`，并验证依赖及授权。
- `engine.analysis_worker` 的低层默认值与共享启动层不同，不建议绕过统一启动自行调用内部 worker。
- `CODEFENDER_ENV=prod` 不是后端开关，也不是响应协议开关。

SMDA 由 `requirements.txt` 安装；兼容版本样本见 `constraints-smda-validated.txt`。该约束文件记录历史验证组合，不是最新版本推荐或自动升级规则。

## 2. 实际数据流

```text
PE → fast 特征（A/B/C/F/G/H）
   → SMDA 或 BN D/E 数值特征 → 普通模型
   → 独立 MalGraph CFG/FCG + 原词表/权重 → MalGraph
   → 成功模型聚合 → Web/生产/开发响应边界
```

- `include_de=false` 不提取 D/E，当前部署的 10 个相关模型通常跳过；图像、哈希和元数据等 fast 视图仍可运行。
- SMDA 不生成训练 BN 路径的中间 `.bndb`。非 MalGraph IR 候选仅在显式开关下启用，见 [IR 契约](IR_CONTRACT.md)。
- MalGraph 保留原特殊管线、词表及权重，不消费候选 ProgramIR。
- SMDA 默认把 `dll!FuncName` 规范为 `FuncName`，复用既有外部函数词表；`CODEFENDER_SMDA_API_NAME_STYLE=raw` 会改变口径，不应无验证切换。
- 反汇编后端、符号名、哈希桶映射和图提取变化都可能影响旧权重。稳定编码不等于与历史训练映射一致，需重建特征并验证或重训。

## 3. 超时与失败

| 参数 | 当前接线 |
|---|---|
| `CODEFENDER_ANALYSIS_TIMEOUT` | 在线隔离分析的单样本预算，由 `engine/staged_scan.py` 读取 |
| `CODEFENDER_REQUEST_TIMEOUT` | 共享扫描运行时请求预算 |
| `CODEFENDER_HARD_TIMEOUT` | 超过硬预算终止模型进程，由 Supervisor 等恢复 |
| `CODEFENDER_SMDA_TIMEOUT` | 特征提取/训练 SMDA 预算；入口默认值不同，不能用一个数字概括全部路径 |
| `CODEFENDER_SMDA_WORKERS` | 训练侧 SMDA 提取进程数，默认 loader 的 `n_workers` |
| `CODEFENDER_DE_PER_FILE_TIMEOUT` | 批量特征提取的旧预算回退变量，不是 HTTP 请求预算 |

SMDA 的协作预算不保证所有底层依赖都不会卡住。线上保留隔离分析、请求和硬超时保护；HTTP 请求超时后真实任务未停止时仍占用容量。不要把超时降级等同于全部模型成功。

当前 `smda_extract.de_features_are_empty` 检查指令/函数是否均为空；IR 候选另有严格完整性校验。无有效分析结果不能以“全零特征成功”写入训练缓存。成功记 `de_done`，硬失败记 `de_fail`，软超时保留重试机会；历史失败日志仍会影响重跑，需要先诊断，不批量清除用户缓存。

## 4. CPU 与 GPU 镜像

| Dockerfile / target | 预检与依赖 | 用途 |
|---|---|---|
| [Dockerfile](../Dockerfile) | `multiscan_basic_v3`、CPU PyTorch、SMDA、完整签名库，无 BN 许可证 | 标准 CPU 全引擎 |
| `Dockerfile.smda` | CPU PyTorch、SMDA，无签名库 | prod 配置的纯模型对照 |
| [Dockerfile.smda.cpu-serve](../Dockerfile.smda.cpu-serve) | CPU PyTorch、SMDA，完整签名库 | 不依赖 BN/CUDA 的 CPU 全引擎 |
| `Dockerfile.smda.gpu --target train` | CUDA PyTorch、SMDA，哈希关闭 | 纯模型推理/离线测评基础镜像 |
| `Dockerfile.smda.gpu --target serve` | CUDA PyTorch、SMDA，完整签名库 | GPU 全引擎 |

CPU 全引擎使用 `bash docker/build_smda_cpu.sh codefender-c3:smda-cpu`，脚本完成三族只读布局门禁、暂存和 COPY 预检；生产设备固定 CPU，默认扫描容量 1。配置、端口和运行命令见 [启动指南](README.md#33-cpu-smda-完整签名库镜像)。布局检查不是实际容器/数据库命中验收。

GPU `train` target 不等于已经内嵌全部训练代码/数据集；当前 COPY 清单不包含 `train/`。真正训练需另外准备训练源码、依赖、数据和输出目录。

```bash
# 在 CoDefenderC3/ 执行；两种 target 按用途选择
# 纯模型，无需签名库
docker build -f Dockerfile.smda.gpu --target train -t codefender-c3:gpu-model .
# 完整引擎，需要签名库暂存
python docker/stage_signatures.py
docker build -f Dockerfile.smda.gpu --target serve -t codefender-c3:gpu-serve .
# 服务器需具备 NVIDIA GPU、匹配驱动和 NVIDIA Container Toolkit
docker run -d --name codefender-c3-gpu --gpus all \
  -p 127.0.0.1:8001:8000 -p 127.0.0.1:18001:18001 \
  -e CODEFENDER_PRODUCTION_HOST=0.0.0.0 -e CODEFENDER_ENABLE_DEV_API=0 \
  codefender-c3:gpu-serve
```

GPU Dockerfile 默认轮子为 `torch 2.5.1+cu121` / `torchvision 0.20.1+cu121`；可用对应构建参数调整，但兼容性需重新验证。CUDA 不可用时当前应用可降级 CPU，所以请求成功不能证明 GPU 实际启用。

三个监听器共享模型进程与状态。`CODEFENDER_MAX_CONCURRENT` 限制扫描容量，不等于启动同数量独立模型进程/权重副本；特征提取子进程、设备内存仍需实际测量。部分变量被 Supervisor 的 `environment=` 固定，`docker run -e` 不一定能覆盖，应同时核对 Dockerfile 和 ini。

## 5. 验证

```bash
curl http://127.0.0.1:18002/health
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@sample.exe"
python -B tools/verify_smda_http.py --sample /data/sample.exe --report docs/test-records/smda-http-new.json
```

检查后端名称、实际设备日志、`PerModelScores` 与覆盖计数，不要求开发入口返回已删除的 `PerModelDetails`。真实 PE 验证与历史报告边界见 [测试指南](TESTING.md)、[历史验证记录](SMDA_RUNTIME_VALIDATION_2026-11-10.md)。
