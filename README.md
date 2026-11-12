# NKAMG-AIDefender

PE 文件检测 Web 项目，由 Vue 3 / Element Plus 前端、FastAPI 后端和 CoDefenderC3 模型服务组成。文档按 2026-11-11 的工作区代码核对；本地开发与生产 Docker 部署均受支持，不依赖旧的第三方镜像标签。

## 1. 文档入口

- [模型服务启动及返回协议](CoDefenderC3/docs/README.md)
- [全部说明文档索引](CoDefenderC3/docs/INDEX.md)
- [测试与接口验证](CoDefenderC3/docs/TESTING.md)
- [模型清单与参考材料](CoDefenderC3/docs/PAPERS.md)
- [数据集构建与训练](CoDefenderC3/train/README.md)

## 2. 检测流程与返回行为

1. 上传过程中计算 SHA256 / MD5，检查大小与可用磁盘空间。
2. 按文件内容校验 PE 结构，不依赖文件名后缀。非 PE 返回 `detection_status=unsupported`、`verdict=null`，不进入模型队列；这是正常业务响应，不是恶意或良性结论。
3. 有效 PE 优先查询已配置的样本数据库。命中直接返回，不排队、不执行模型；未命中进入后台检测队列。
4. 未命中时 `POST /detect` 返回 HTTP 202 和 `task_id`；前端轮询任务接口展示排队、进度和最终结果。
5. 模型适配器读取 Web 兼容协议的逐模型分数和集成结果。当前部署模型为 33 个 / 15 个视图，是否全部执行需检查模型覆盖，HTTP 200 不代表 33 个模型均成功。
6. 原始上传样本在检测结束或直接返回后清理；任务结果有 TTL，不提供永久保留承诺。

Web 样本数据库查询与 CoDefender 的签名库预检是两层独立功能。未配置 MySQL 时不能将空查询/统计当成数据库正常接入的证明。

## 3. 开发环境启动

准备 Python 环境、可运行 Vite 6 的 Node.js/npm、`CoDefenderC3/ensemble.pkl`。模型依赖安装和共享服务命令见[模型服务指南](CoDefenderC3/docs/README.md#2-开发环境启动)，先启动模型服务，使用下面的地址：

| 服务 | 地址 | 说明 |
|---|---|---|
| 前端 | `http://127.0.0.1:9528` | Vite，`/api-backend` 代理到后端 |
| Web 后端 | `http://127.0.0.1:5006` | FastAPI，单进程启动 |
| Web 模型入口 | `http://127.0.0.1:8001` | 开发设置 `CODEFENDER_WEB_COMPAT_PORT=8001` |
| 生产模型入口 | `http://127.0.0.1:18001` | 精简响应，不能直接供现有 Web 使用 |
| 开发模型入口 | `http://127.0.0.1:18002` | 需 `CODEFENDER_ENABLE_DEV_API=1` |

**后端：**在独立终端从仓库根目录执行，激活已安装依赖的 Python 环境。

```powershell
cd web
if (-not (Test-Path config.ini)) { Copy-Item config.example.ini config.ini }
cd FastAPI
python -m pip install -r requirements.txt
python main.py
```

Linux 使用 `test -f config.ini || cp config.example.ini config.ini` 创建配置。后端会依次读取 `web/config.example.ini`、`web/config.ini`，再接受 `CODEFENDER_<节名>_<键名>` 环境变量覆盖，例如 `CODEFENDER_SERVER_PORT`。

**前端：**在另一终端从仓库根目录执行：

```bash
cd web/Vue
npm ci
npm run dev
```

检查 `web/config.ini` 中 `server.port=5006`、`codefender.api_base=http://127.0.0.1:8001`、`scan_endpoint` 留空、`include_de=true`。前端 `public/config.ini` 的 `baseUrl=/api-backend` 与 Vite 代理保持一致。

**Web 必须连接 `engine.web_compat:app`**，不要把 `api_base` 改为生产精简接口。三个模型端口可共享同一个模型进程，但不能把它们当成三个独立推理 worker。

## 4. 生产部署

1. 按[模型服务指南](CoDefenderC3/docs/README.md#3-生产环境启动)构建基于 `multiscan_basic_v3` 的 CPU SMDA 标准全引擎、[CPU SMDA 完整签名库镜像](CoDefenderC3/docs/README.md#33-cpu-smda-完整签名库镜像)或纯模型镜像。现有 Web 使用宿主 `8001` → 容器 `8000` 的 Web 兼容端口；生产精简入口另行提供给业务客户端。
2. 配置后端数据库、上传限制和模型地址。后端绑定本机 `5006`，使用单进程服务，不使用开发热重载。
3. 在 `web/Vue` 执行 `npm ci`、`npm run build`，将 `dist/` 交给 Nginx。`npm run preview` 只用于预览构建结果，不替代生产静态服务。
4. 仓库提供 [Nginx 模板](web/deploy/nginx.conf) 和 [systemd 模板](web/deploy/nk-amg-backend.service)。按实际机器修改用户、仓库绝对路径、Python 环境及 Nginx root；模板当前监听 `9528`，代理到 `127.0.0.1:5006`。
5. 通过网关配置 TLS、访问控制及上传限额。模型管理和诊断接口不要直接公开。生产默认关闭开发入口。

默认上传上限为 1 GiB（后端可降低，但不会超过硬上限），默认 1 个扫描槽 / 8 个等待任务，报告 TTL 为 3600 秒。Nginx 请求体限制必须留出 multipart 开销。

只有配置并验证了独立模型进程/容器时才可增加 Web 扫描槽。`api_bases` 应指向独立服务的 **Web 兼容入口**，而非同一共享进程的三个协议端口；部署辅助脚本 `web/deploy/model_worker.py` 默认预演，启用前核对 `--help` 和生成的 Docker 配置。

## 5. Web 后端接口

下列路径直接调用 `5006`；浏览器同源请求使用 `/api-backend` 前缀。

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/`、`/health` | 后端存活；不代表模型就绪 |
| GET | `/upload-policy` | 上传上限、报告 TTL、样本保留策略 |
| GET | `/models`、`/model-health` | 模型目录、上游 `/readyz` 状态 |
| GET | `/stats`、`/detection-stats` | 样本统计、检测任务统计 |
| GET | `/samples/{sha256}`、`/sample-search?value=...` | 样本数据库 SHA256 / MD5 查询 |
| POST | `/detect` | multipart `file`；可携带 `X-Detection-ID`（32 位小写十六进制） |
| GET | `/detect/tasks/{task_id}` | 排队/运行/完成/失败/取消状态；完成响应中读取 `result` |
| POST | `/detect/tasks/{task_id}/leave` | 标记客户端离开；HTTP 202 不等于正在运行的推理立即终止 |

```bash
curl http://127.0.0.1:5006/model-health
curl -X POST http://127.0.0.1:5006/detect -F "file=@sample.exe"
# 上一步返回 task_id 后持续轮询，直到终态
# 将 TASK_ID 替换为上一步响应中的实际 task_id
curl "http://127.0.0.1:5006/detect/tasks/TASK_ID"
```

Windows PowerShell 使用 `curl.exe`。`/detect` 对未命中有效 PE 通常返回 202；数据库命中或非 PE 可直接返回 200。队列满/上传并发受限返回 429，超限返回 413，存储不足返回 507；上传被 Windows 防护阻止时可能返回 422，不应自动关闭系统防护。

## 6. 排查顺序

1. `GET /model-health` 及模型 `GET /readyz` 是否就绪，端口是否指向当前实例。
2. 后端配置是否连接 Web 兼容入口；`include_de` 是否为模型接口的查询参数。
3. 异步任务是否进入终态；报告是否已过期，排队请求是否仍在轮询。
4. 检查数据库连接、后端日志、模型日志和被排除模型原因。未执行/失败不等同于良性。
5. 修改镜像内代码或产物后重建镜像和容器，仅重启旧容器不会使用新镜像。
