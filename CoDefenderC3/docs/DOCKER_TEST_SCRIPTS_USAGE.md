# Docker 构建与测试脚本

核对日期：2026-11-11。命令从 `CoDefenderC3/` 执行；启动与返回结构见 [README](README.md)，完整测试步骤见 [TESTING](TESTING.md)。

## 1. 脚本一览

| 脚本 | 用途与边界 |
|---|---|
| `docker/build.sh` | 暂存签名库 → 检查上下文 → 构建标准镜像 |
| `docker/stage_signatures.py` | 解析当前签名发布目录，生成独立构建暂存树；不是在线更新接口 |
| `docker/check_context.py` | 核对 Dockerfile 的 COPY 源和忽略规则 |
| `docker/check_requirements.py` | 静态扫描第三方导入和 requirements 覆盖；不是安装/运行测试 |
| `docker/check_model_imports.py` | 模型模块导入探针；不加载全部权重做推理 |
| `docker/test_api.sh` | 探针/只读管理冒烟，可选快速单文件/目录请求 |
| `docker/Dockerfile.runtime`、`patch_runtime.py`、`runtime_endpoints.py` | 旧镜像增量兼容工具；不能替代当前三监听器标准部署 |
| `docker/patch_progress.py` | 旧部署补丁；当前代码已有 Web 流式进度，不作为常规安装步骤 |

## 2. 构建与预检

```bash
python docker/stage_signatures.py
python docker/check_context.py --list-copy
python docker/check_requirements.py .
python docker/check_requirements.py . --all -v
python docker/check_model_imports.py
bash docker/build.sh codefender-c3:prod --progress=plain
```

`build.sh` 的第一个参数为镜像标签，剩余参数传给 `docker build`；可用 `PYTHON=/path/to/python` 指定本机解释器。它构建标准 Dockerfile，不负责选择 SMDA/GPU 变体。

预检其他 Dockerfile：

```bash
python docker/check_context.py --dockerfile Dockerfile.smda --context . --list-copy
# GPU serve 需要先暂存签名库；检查器用于 COPY 源检查，不证明 Docker 多阶段构建可运行
python docker/check_context.py --dockerfile Dockerfile.smda.gpu --context . --list-copy
```

代码、模型与标准签名库通过构建进入镜像。改宿主源文件、重新打同名 tag 或仅 restart 旧容器，都不会让旧容器自动使用新的镜像文件系统；需重建容器。

## 3. API 冒烟

需要 Bash、curl 和可解析 JSON 的 Python：

```bash
BASE_URL=http://127.0.0.1:18001 bash docker/test_api.sh --expect-prod
BASE_URL=http://127.0.0.1:8001 TIMEOUT=180 bash docker/test_api.sh --sample /data/local/sample.exe
BASE_URL=http://127.0.0.1:18002 bash docker/test_api.sh --dir /data/samples
```

| 参数/变量 | 默认值 | 说明 |
|---|---|---|
| `BASE_URL` | `http://localhost:8000` | 必须改成正在测试的实际监听器/宿主映射端口 |
| `TIMEOUT` | 90 秒 | 每个 curl 请求上限 |
| `CURL_NOPROXY` | `localhost,127.0.0.1,::1` | 本机绕过代理；空字符串关闭这一设置 |
| `--sample` | 无 | 样本路径在运行脚本的机器上 |
| `--dir` | 无 | 样本目录在模型服务/容器内 |
| `--expect-prod` | 关闭 | 仅断言 `/health.env=prod`；不证明服务在容器内或哈希预检已开启 |

### 实际覆盖

- GET `/livez`、`/readyz`、`/health`、`/metrics`、`/model-info`、`/admin/config`。
- 可选 POST `/predict-single` 和 `/predict-directory`，均固定 `include_de=false`；目录固定 `recursive=false`。
- 不执行配置写入、模型重载、签名更新、Web 流式、Web 后端异步任务，也不验证全部错误码。

### 当前限制（不要误读 PASS）

1. 单文件成功主要检查 HTTP 200；生产响应没有 `Score/Status/ModelStats`，脚本对应打印空值不代表协议错误。
2. 目录打印仍读取旧 `Total/Malicious/Benign` 字段；当前结构为 `Summary` / `Results`，需额外核对 `Summary.TotalFiles` 等计数和失败项。
3. `--sample` 路径不存在记为 SKIP。最终无 FAIL 仍可能包含 SKIP，不能声称真实推理已验证。
4. `--expect-prod` 只是环境档位判断；SMDA 纯模型镜像也为 prod，不能据此断言完整签名库。
5. `--dir` 直接拼接 URL，含空格/特殊字符的路径应改用 [TESTING](TESTING.md) 中 `--data-urlencode` 请求。

需要完整 D/E 覆盖或字段契约验证时使用真实 PE 验证工具，不能只运行该脚本。

## 4. 最短排查路径

1. 模型 `/readyz`；确认 URL、端口映射、`pid` / `model_path`。
2. `docker logs` 和 `/var/log/supervisor/codefender_err.log`。
3. `/health.disasm_backend` 与依赖/授权；共享入口默认 SMDA，显式 bn 才走 BinaryNinja。
4. 对签名库查看 `engine_mode`、`require_hash_db` 及三个库状态，不硬编码历史条数。
5. 管理/变更回归在独立环境执行并保存新报告，不覆盖历史证据。
