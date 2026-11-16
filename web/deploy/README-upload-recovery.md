# Web 上传中断恢复与部署（2026-11-16）

## 为什么修改

txy 在文件尚未收完时占用 API 上传名额。部分客户端出现 10053/10054 后，服务器仍等待文件数据，直到 600 秒总超时才释放名额；两个名额占满期间返回“上传服务繁忙”429。日志证明了未完整上传和延迟超时，但还不能判定最初连接中断来自客户端、网络设备还是服务器转发。

此次只修改 `web`。不改 CoDefenderC3、模型接口、模型权重、Docker 配置或内存限额，不增加两个 API 上传名额，不自动重传样本。

## 本次行为

- 上传总时限仍为 600 秒。新增 `[uploads] api_upload_idle_timeout_seconds = 60`：只有未完成的上传连续 60 秒没有新正文数据才中止；持续传输会刷新无数据计时，但仍受总时限约束。
- 正文全部收到后，两个上传计时器均停止作用，不能因后续排队、保存或推理时间较长误取消任务。
- 9528 的 Vite dev/preview 在客户端未完成正文就关闭时，关闭对应的 5006 上游上传连接。正常完成正文后的 close 不触发取消，也不取消已受理的检测任务。
- 后端处理断开、超时、协程取消时释放名额，显式关闭 multipart 临时文件，兼容异常被包装成 ExceptionGroup 的情况。
- 浏览器原有两个上传名额保持不变，改用 ASGI 中间件避免不必要的 BaseHTTPMiddleware 异常包装。
- 超时在连接可用时返回 HTTP 408 JSON：`result=Failed`、`error_code=UPLOAD_TIMEOUT`、`task_id`、`retryable=true`；已经断开的连接无法保证收到响应。未完成的文件不创建检测任务。
- API 上传名额满时仍返回 HTTP 429，增加 `Retry-After: 60`。本次不修改桌面上传脚本的等待策略。
- 日志记录 task_id、接收字节、预期字节、接收阶段、耗时、名额释放后的 inflight，不记录样本正文。

示例配置已提供默认值；现有私有 `web/config.ini` 未配置无数据时限时自动使用 60 秒。无需运行旧配置工具，也不用改模型 revision。

## txy 部署

服务器仓库：`/home/ubuntu/github/NKAMG-AIDefender`。先暂停本地批量上传，再确认没有需要等待完成的模型分析：

```bash
curl -sS --max-time 15 http://127.0.0.1:5006/model-health | python3 -m json.tool
```

等待 `active_tasks=0`；如模型仍在分析，先等任务完成。上传停滞请求不属于模型任务。

### GitHub 更新（推荐）

确认批量已暂停、`active_tasks=0`。先查看状态；如果存在自己修改的跟踪文件，先处理这些修改，不要强行覆盖或清理。旧版跟踪文件用 Git 归档备份，避免 tar 因历史 root 所属备份文件失败：

```bash
cd /home/ubuntu/github/NKAMG-AIDefender
git status --short
umask 077
BACKUP_DIR="/home/ubuntu/web-backups/upload-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
git archive --format=tar.gz -o "$BACKUP_DIR/web-tracked-before.tar.gz" HEAD web
cp web/config.ini "$BACKUP_DIR/config.ini"
echo "旧版备份：$BACKUP_DIR"
git pull --ff-only https://github.com/nkiszhi/NKAMG-AIDefender.git main
git log -2 --oneline
```

本次新增提交仅包含 Web 文件。远端在此之前已有同事的模型优化提交；完整 pull 也会同步那些既有源码，但不会更新正在运行的 Docker 镜像。本次不 rebuild、不重启模型 Docker。

拉取后运行下面的 Web 停止检查和启动步骤即可，不需要再运行补丁安装器。两个上传时限会从配置示例和现有配置合并读取，无需覆盖私有 config.ini。

### 可选：离线补丁包

如使用本地补丁包而不从 GitHub 更新，将 `web-upload-fix-20261116.zip` 复制到 `/home/ubuntu/`，执行：

```bash
python3 -m zipfile -e /home/ubuntu/web-upload-fix-20261116.zip /home/ubuntu/web-upload-fix-20261116
cd /home/ubuntu/web-upload-fix-20261116
python3 apply_web_patch.py --repo /home/ubuntu/github/NKAMG-AIDefender
```

### 停止并启动 Web

GitHub 更新已包含下面的停止助手。它先校验两个监听进程的工作目录、命令和模型空闲状态，全部匹配后才发送 TERM；不触碰其他服务或 Docker，并等待旧进程真正退出。若服务管理器重启进程或旧进程没有退出，会报错停止流程，不要接着启动第二份 Web：

```bash
python3 web/deploy/stop_web_for_update.py --repo /home/ubuntu/github/NKAMG-AIDefender
python3 web/deploy/stop_web_for_update.py --repo /home/ubuntu/github/NKAMG-AIDefender --apply
```

仅离线补丁方式需要执行下面的安装命令；GitHub pull 方式跳过此步。安装脚本先校验全部文件、备份，再逐文件替换并回读验证；版本不符拒绝覆盖，不改私有配置、数据库或 Git 状态：

```bash
cd /home/ubuntu/web-upload-fix-20261116
python3 apply_web_patch.py --repo /home/ubuntu/github/NKAMG-AIDefender --apply
```

使用服务器原有 venv 和依赖启动。无需安装新依赖；本次没有浏览器界面或静态资源修改，旧 dist 可继续使用，但必须重启 preview 以加载新代理配置和模块：

```bash
cd /home/ubuntu/github/NKAMG-AIDefender/web/FastAPI
mkdir -p logs
nohup ./venv/bin/python -u main.py >> logs/web-runtime.log 2>&1 &

cd /home/ubuntu/github/NKAMG-AIDefender/web/Vue
mkdir -p logs
nohup npm run preview >> logs/web-preview.log 2>&1 &
```

如服务器由 systemd 等托管 Web，应改用对应服务的停止/启动方式，不要同时启动第二套进程。

## 验收及日志

```bash
curl -fsS --max-time 15 http://127.0.0.1:5006/health; echo
curl -fsS --max-time 15 http://127.0.0.1:9528/api-backend/health; echo
curl -sS --max-time 15 http://127.0.0.1:5006/model-health | python3 -m json.tool
tail -n 80 /home/ubuntu/github/NKAMG-AIDefender/web/FastAPI/logs/web-runtime.log
tail -n 80 /home/ubuntu/github/NKAMG-AIDefender/web/Vue/logs/web-preview.log
```

先用一个正常样本确认上传和结果，再继续原批次。异常日志应有 `phase=disconnected` / `phase=idle_timeout` 与“API 上传释放名额 … inflight=0/1”。正常上传应为 `phase=body_complete`；客户端没有实际断开 TCP、只是停止发数据时，靠 60 秒无数据超时回收，不保证瞬间释放。

本地验证：后端完整测试、Node 状态及代理测试、Vite dev/preview 真实本机 HTTP 断开复现和生产构建。未向 txy 上传测试样本、未执行线上故障注入；上线仍需真实 PE 验收。此改动改善接收端恢复，不保证消除最初的网络断开。

## 备份与回滚

安装后记录输出的备份目录，位于补丁目录 `backups/<时间>/`。停止 Web 后先检查再执行回滚：

```bash
python3 apply_web_patch.py --repo /home/ubuntu/github/NKAMG-AIDefender --rollback /实际输出的备份目录
python3 apply_web_patch.py --repo /home/ubuntu/github/NKAMG-AIDefender --rollback /实际输出的备份目录 --apply
```

回滚会校验备份和当前版本，不覆盖之后另行修改的文件。恢复旧文件后按上述方式启动 Web。数据库、样本和 Docker 不参与回滚。
