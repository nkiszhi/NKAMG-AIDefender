# CoDefenderC3

PE 文件检测、特征提取及训练组件。当前部署 `ensemble.pkl` 为 33 模型 / 15 视图；源码还保留 `V11_ensemble` 候选组，配置目录数量不等于当前部署模型数量。以已加载模型的 `/model-info` 为准。

## 使用入口

- [启动与接口说明](docs/README.md)：开发、生产 Docker、Web 接入及三种返回协议。
- [文档索引](docs/INDEX.md)：现行指南、规划与历史记录分类。
- [测试指南](docs/TESTING.md)：契约回归、真实 PE 和管理接口验证。
- [训练指南](train/README.md)：数据集构建、续训、产物验证。
- [模型与论文材料](docs/PAPERS.md)：当前部署清单、候选模型和实现边界。

## 最小启动

先按[依赖安装说明](docs/README.md#21-安装依赖)准备 Python 环境和 `ensemble.pkl`。从本目录执行：

```bash
CODEFENDER_ENV=dev CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 \
CODEFENDER_REQUIRE_HASH_DB=0 CODEFENDER_RUNTIME_CFG_DISABLE=1 \
CODEFENDER_WEB_COMPAT_HOST=127.0.0.1 CODEFENDER_WEB_COMPAT_PORT=8001 \
CODEFENDER_ENABLE_DEV_API=1 python -m engine.serve
```

Windows 环境变量写法见[开发启动](docs/README.md#22-启动共享模型服务推荐)。共享启动默认 SMDA；显式 `CODEFENDER_DISASM_BACKEND=bn` 才使用已安装并授权的 BinaryNinja。

| 入口 | 示例端口 | 协议 |
|---|---:|---|
| `engine.web_compat:app` | 8001 | 完整 Web 兼容响应及 `/predict-stream` |
| `engine.app:app` | 18001 | 生产业务字段投影 |
| `engine.dev.app:app` | 18002 | 开发诊断，移除三个重复字段 |

三个入口共享运行时，不要分别启动多个 Uvicorn worker。`CODEFENDER_ENV` 控制配置档位，不自动切换返回协议。只启动单独开发接口可用 `dev_model_only.cmd` / `bash dev_model_only.sh`，它不提供 Web 流式入口。

```bash
curl http://127.0.0.1:18002/readyz
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@sample.exe"
```

## 目录

| 目录/文件 | 职责 |
|---|---|
| `engine/` | 共享模型运行时、三种 HTTP 契约、响应投影 |
| `feature_extraction/` | fast 特征、SMDA/BN D/E、候选 ProgramIR 缓存 |
| `models/`、`model_registry.py` | 模型实现及通用训练注册；MalGraph 使用特殊管线 |
| `scaner/` | 签名库、静态信息、文件类型和壳检测 |
| `train/`、`experiments/` | 数据集/训练及离线实验；非默认在线自动更新链路 |
| `tools/`、`tests/` | 契约回归、真实 PE 验证与只读冻结校验 |
| `docker/`、`Dockerfile*` | 构建暂存、自检、测试和 CPU/GPU 镜像 |
| `docs/`、`papers/` | 当前指南、历史记录及参考材料 |

## 运行约束

- 样本只做静态分析，不执行待检 PE；Windows 防护拦截应先检查保护历史，不自动关闭防护。
- 训练默认写 `runs/<run-id>/`，不覆盖生产模型；验证后再显式发布。
- 签名库更新和模型重载会修改共享状态，测试时使用独立环境；生产管理接口必须限制访问。
- BinaryNinja 是商业组件；SMDA 后端无需 BN 许可证。模型来源与参考论文不代表严格复现或性能承诺。
