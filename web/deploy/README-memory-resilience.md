# txy Web：大样本调度与内存故障维护

本次只修改 web，未修改 CoDefenderC3、模型、/predict-single 或 Docker 内存配置。小于 100 MiB 的文件最多双并发，达到 100 MiB 的文件独占推理；排队遵守 FIFO。OOM 需有同一容器在请求开始后的 Docker oom 事件证据，普通断连不会冒称内存超限。

确认 OOM 后任务失败，保存 SHA256 + model_revision 保护记录，不换容器重试。同一部署版本重复上传不再请求模型。API 失败响应增加 error_code、retryable:false；旧客户端仍需读取失败 JSON，避免重试。网页持续显示失败原因，未完成模型不算 Benign。

## 更新之前

暂停所有批量客户端，等待现有分析结束，再停止本项目的 Web 后端和前端。若前台启动，在各自终端按 Ctrl+C；若后台启动，先用下面命令核对实际 PID 和工作目录，再用 kill -TERM 实际PID。不要使用历史 PID 或 pkill python。

```bash
pgrep -af '[p]ython.*main.py'
pgrep -af '[v]ite preview'
# 对实际 PID 检查：readlink /proc/实际PID/cwd
```

## 拉取与备份

在 ubuntu 用户下操作。先备份整个 Web（含配置、数据库和构建文件，排除依赖及上传临时文件），然后拉取：

```bash
cd /home/ubuntu/github/NKAMG-AIDefender
BACKUP_DIR="/home/ubuntu/web-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
tar --exclude=web/Vue/node_modules --exclude=web/FastAPI/.venv \
    --exclude=web/FastAPI/venv --exclude=web/FastAPI/uploads \
    -czf "$BACKUP_DIR/web-before.tar.gz" web
echo "备份目录：$BACKUP_DIR"
git pull --ff-only https://github.com/nkiszhi/NKAMG-AIDefender.git main
```

若 Git 提示本地代码冲突，停止并检查，不要执行 reset --hard 或覆盖同事代码。

## 设置 Web 参数

下面脚本保留现有私有配置项，并在已被 Git 忽略的 web/FastAPI/data/config-backups 中备份配置。它不改容器内存上限。model_revision 表示实际模型、权重、分析选项和资源预算的版本；不要每次启动随机修改版本名。

```bash
python3 web/deploy/configure_txy_web.py \
  --repo /home/ubuntu/github/NKAMG-AIDefender \
  --revision e4308ed-smda-cpu-10g-v1
```

此配置对应当前 18011、18012 两个模型节点和各自原有的 10 GiB 部署，不要误认为设置成了 20 GiB。主机约 30 GiB 时，两台各 20 GiB 并发没有可靠内存保证。4 GiB 可用内存门槛只是派发前观测，不能预知运行峰值。

## 启动运行监测

独立监测脚本只读 Docker 生命周期和 oom 事件，不执行启动、停止或重建。安装成 root 所有的脚本，写入 root 管理的 /run 目录；Web 只读 JSON，不需要 Docker socket 权限。

```bash
sudo install -d -m 0755 /usr/local/lib/codefender
sudo install -o root -g root -m 0755 web/deploy/model_resource_monitor.py /usr/local/lib/codefender/model_resource_monitor.py
sudo install -o root -g root -m 0644 web/deploy/codefender-resource-monitor.service /etc/systemd/system/codefender-resource-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable --now codefender-resource-monitor
sudo systemctl restart codefender-resource-monitor
sleep 3
sudo systemctl status codefender-resource-monitor --no-pager
python3 -m json.tool /run/codefender-resource-monitor/model-runtime.json
```

配置监测后，缺失或过期的快照会暂停新任务派发。因此先确认快照持续更新、节点 ready，再启动 Web。

## Docker 是否重启

此次没有更新镜像，不需要 rebuild/load，也不强制重启模型容器。若维护时希望清空旧任务，确保 Web 与客户端已停、没有需要保留的运行分析后，可重启：

```bash
sudo docker restart codefender-c3-smda-1 codefender-c3-smda-2
curl -sS --max-time 15 http://127.0.0.1:18011/readyz; echo
curl -sS --max-time 15 http://127.0.0.1:18012/readyz; echo
```

首次查询可能尚未就绪，等模型加载完成再查询。restart 不会改变 10 GiB 限额。容器退出后的自动重启依赖既有 restart policy；容器被删除需要管理员按原配置重建。

## 启动 Web

后端必须先激活原先启动 main.py 的 Python 环境；不假定虚拟环境目录名，也不需要安装新的 Python 依赖。

```bash
cd /home/ubuntu/github/NKAMG-AIDefender/web/FastAPI
python -c 'import sys,fastapi,uvicorn,requests,pymysql; print(sys.executable)'
mkdir -p logs
nohup python -u main.py >> logs/web-runtime.log 2>&1 &
```

启动前端（使用已有 node_modules；需重新 build 才能看到新提示）：

```bash
cd /home/ubuntu/github/NKAMG-AIDefender/web/Vue
npm run build && mkdir -p logs && nohup npm run preview >> logs/web-preview.log 2>&1 &
```

如果原服务由 systemd/supervisor 管理，使用原管理方式重启，避免与 nohup 启动重复实例。Web 后端仍只运行一个进程，不加 --workers 或 --reload。

## 验收和查看

```bash
curl -sS http://127.0.0.1:5006/health; echo
curl -sS http://127.0.0.1:9528/api-backend/health; echo
curl -sS http://127.0.0.1:5006/model-health | python3 -m json.tool
tail -n 80 /home/ubuntu/github/NKAMG-AIDefender/web/FastAPI/logs/web-runtime.log
sudo journalctl -u codefender-resource-monitor -n 50 --no-pager
sudo docker stats --no-stream
```

正常空闲时应看到 ready_workers=2、total_workers=2、dispatch_paused=false、active_tasks=0。用一个真实 PE 检查网页和 API，再恢复批量上传。不要在生产环境故意制造 OOM。

监测到节点重启且 readyz 就绪后可恢复后续工作。普通断连可能仍在计算，因此会等待节点新一代启动或排空时间；等待状态也会持久化，重启 Web 不会绕过等待。默认 1200 秒排空时间依赖模型端可靠的硬生命周期不超过 960 秒；若没有可靠的硬终止，应人工重启故障节点，不能仅靠 HTTP 超时认定模型已经空闲。排队超过 1800 秒会失败，不会无限等待。

## 解除单个内存失败保护

仅在资源或问题已处理、确实需要复测时使用。默认只查看，加 --unblock 才解除并先备份数据库；不会自动上传样本。

```bash
python3 web/deploy/memory_failure_admin.py \
  --db web/FastAPI/data/detection_tasks.sqlite3 \
  --sha256 实际64位SHA256 --revision e4308ed-smda-cpu-10g-v1
```

本地验证：120 项后端测试、2 项前端状态测试及生产构建通过。Docker 实际 OOM 故障注入未执行；部署后仍需按真实 PE 验收。
