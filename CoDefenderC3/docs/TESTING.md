# 测试与接口验证

核对日期：2026-11-11。以下命令从 `CoDefenderC3/` 执行；启动、端口和字段定义以 [README](README.md) 为准。所有待检 PE 仅做静态分析，不执行样本。

## 1. 测试层次

| 层次 | 验证什么 | 不能证明什么 |
|---|---|---|
| 单元/契约回归 | 投影、缓存身份、训练接线、冻结内容和错误路径 | 真实权重质量、真实数据库命中、GPU/Docker可用 |
| 合成模型真实 HTTP | 三监听器共享状态、HTTP 请求及管理操作 | 33 个真实模型推理成功 |
| 真实 PE / 真实权重 | 特征、模型前向、分数覆盖及实际返回协议 | 全样本召回率、跨时间质量或数据库接入 |
| 签名/数据库集成 | 已知命中、未命中、更新与回滚 | 未接入真实库时不能宣称通过 |

不要把历史报告的测试数量或耗时当作当前测试结果。新运行应使用新文件名，禁止覆盖 `test-records/` 内已有原始证据。

## 2. 自动回归

先安装模型运行依赖，再安装回归依赖：

```bash
python -m pip install -r tests/requirements-merge.txt
python -B tests/test_ir_contract.py
python -B tests/test_stable_hash.py
python -B tests/test_smda_cpu_docker.py
python -B tests/test_multiscan_smda_docker.py
python -B -m unittest discover -s tests -p "test_merge_*.py" -v
python -B tools/run_web_regression.py
python -B tools/run_shared_listener_smoke.py
```

`test_multiscan_smda_docker.py` 检查主 Dockerfile 的无 BN 基础镜像、SMDA 启动、CPU 依赖、内嵌产物及生产配置；同样是离线检查，不执行镜像构建。

`test_smda_cpu_docker.py` 是 CPU 全引擎的离线配置/签名布局回归：验证三族门禁、CPU/生产配置、共享启动、端口与探针语法。使用临时伪数据，不读取或修改真实库；通过不能证明 Docker 构建、真实 SQLite、模型推理或签名命中。

`run_web_regression.py` 在临时镜像目录运行现有 Web 测试，不修改 `web/`；部分测试和冻结校验需要仓库的历史 Git 对象，纯导出代码包可能无法执行这些门禁。

整套编排（显式指定新报告路径）：

```bash
python -B tools/run_merge_regression.py --working-tree-only --report docs/test-records/local-regression-new.json
```

`--working-tree-only` 只改变冻结校验范围，不跳过测试。脚本默认报告名指向历史合并记录，运行时务必覆盖 `--report` 为新的文件名。完整提交/索引校验可去掉此选项；相关来源定义见 `merge_main_test_lm_sources.json`。

## 3. 真实接口检查

### 3.1 探针

按 [开发启动](README.md#2-开发环境启动)启动共享进程，默认推荐测试地址为 Web `8001`、生产 `18001`、开发 `18002`。

```bash
curl http://127.0.0.1:8001/readyz
curl http://127.0.0.1:18001/readyz
curl http://127.0.0.1:18002/readyz
curl http://127.0.0.1:18002/model-info
```

`/readyz` 要求 HTTP 200 / `ready=true`。`/health` 用于确认 `env`、`pid`、`model_path`、`disasm_backend`、`engine_mode` 和库状态；生产配置档位与生产响应协议不可混同。

### 3.2 单文件、目录和流式

```bash
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@sample.exe"
curl -X POST "http://127.0.0.1:18001/predict-single?include_de=true" -F "file=@sample.exe"
curl -X POST -G "http://127.0.0.1:18002/predict-directory" \
  --data-urlencode "directory=/data/samples" --data-urlencode "recursive=true" \
  --data-urlencode "include_de=true"
curl -N -X POST "http://127.0.0.1:8001/predict-stream?include_de=true" -F "file=@sample.exe"
```

- `include_de` 是查询参数，不是 multipart 表单字段。`false` 会跳过 D/E 相关模型，当前部署通常是 23 个模型成功、10 个跳过，不保证每个样本都达到该数量。
- `directory` 是服务端/容器绝对路径，服务按内容选择 PE。目录默认 `recursive=true`、`include_de=false`。
- 开发响应检查 `PerModelScores` 和 `ModelStats` 的成功/跳过/错误数量及 `ExcludedModels`；不再要求 `PerModelPreds`、`PerModelDetails`、`AggregatedModels`。
- 生产检查字段白名单和目录五项计数；超时并入 `ErrorCount`。开发错误总量应合计 `ErrorCount + TimeoutCount`。
- 流式接口只在 Web 入口提供。NDJSON 可能 HTTP 200 后发送终止 `error`，必须检查最终 `result` / `error`，不能仅检查 HTTP 状态。
- 哈希命中是短路结果，不能要求它提供模型覆盖统计或据此声称模型执行完毕。

### 3.3 真实 SMDA 验证工具

```bash
python -B tools/verify_smda_runtime.py --sample-dir /data/benign-pe --pattern "*.exe" \
  --report docs/test-records/smda-runtime-new.json --full-models 1
python -B tools/verify_smda_http.py --sample /data/benign-pe/sample.exe \
  --report docs/test-records/smda-http-new.json
python -B tools/run_dataset_directory_scan.py --source /data/dataset \
  --output-dir scan-results/directory-new --per-class 10
```

这些工具具有各自的本地运行/临时服务逻辑，不是任意 `BASE_URL` 客户端。执行前查看 `--help` 并准备权重、依赖和源样本；`run_dataset_directory_scan.py` 使用分类样本源，不能用其结果替代大规模质量评测。

## 4. Web 后端验证

从仓库根目录进入 `web/FastAPI`。单元测试可执行 `python -B -m unittest discover -s tests -v`；合并回归优先使用上面的临时镜像工具。

真实请求顺序：

1. `GET /upload-policy`、`/models`、`/model-health`、`/stats`、`/detection-stats`。
2. `POST /detect` 上传有效 PE，未命中返回 202；持续轮询 `GET /detect/tasks/{task_id}` 到终态，并检查 `result`。
3. 上传非 PE，应返回 unsupported 业务结果且不执行模型；数据库命中也直接返回，不进入队列。
4. 检查任务参数非法、未知/过期任务、上传超限、队列满等错误；客户端离开接口不代表运行中分析立即停止。
5. 有真实 MySQL 时补测 SHA256/MD5 查询与命中短路；没有数据库连接时必须标注该部分未验证。

## 5. 管理接口（仅独立测试环境）

`GET/POST /admin/config`、`POST /reload-model`、`POST /update-signatures` 在三个模型入口共享。先记录状态，只测试自己的服务，勿把样本签名写入线上恶意库。

```bash
curl http://127.0.0.1:18002/admin/config
curl -X POST http://127.0.0.1:18002/reload-model
# 仅在独立开发环境临时调整配置，测试后恢复原值
curl -X POST http://127.0.0.1:18002/admin/config \
  -H "Content-Type: application/json" -d '{"hash_db_enabled": false}'
```

`reload-model` 支持查询参数 `model_path` 指向服务端模型文件。开发运行时文件启用时可测试 `persist`；标准生产及本指南启动的禁用文件配置应拒绝 `persist/reload_file`（409）。模型与配置修改影响同进程全部监听器。

签名更新测试见 [签名库指南](testing_hash.md)。生产管理接口不含应用内鉴权，应放在内部网络/鉴权代理后。

## 6. Docker 冒烟与历史证据

```bash
BASE_URL=http://127.0.0.1:18001 TIMEOUT=180 bash docker/test_api.sh --expect-prod
```

脚本是有限冒烟，不是“全部接口测试”；其可选推理固定 `include_de=false`，目录展示仍读取旧计数字段，不能据此验证当前目录计数契约。详细限制见 [Docker 测试脚本说明](DOCKER_TEST_SCRIPTS_USAGE.md)。

历史测试报告见 [文档索引](INDEX.md#3-历史记录保留证据不作为当前操作说明)。本次文档核查没有重新认证 Docker、CUDA、BinaryNinja 授权或模型检测质量。
