# 腾讯云 Ubuntu 部署

端口：前端 9528，FastAPI 5006，Docker 模型仅本机 8001（容器内 8000）。
浏览器使用同源 `/api-backend`，Vite 或 Nginx 转发到 5006，不需要写服务器公网 IP。
以下步骤在腾讯云服务器执行，本地代码修改不会自动重启已经运行的进程。

## 1. 同步代码

```bash
cd /home/ubuntu/github/NKAMG-AIDefender
git pull --ff-only
```

如果有服务器本地修改，先查看 `git status` 并保留配置，不能直接覆盖。

## 2. 安装 Docker（Ubuntu 软件仓库版本）

```bash
sudo apt-get update
sudo apt-get install -y docker.io curl
sudo systemctl enable --now docker
sudo docker version
df -h /var/lib/docker
free -h
```

镜像包约 2.5 GB，解压后的镜像和模型运行需要额外磁盘及内存；容量以实际导入和运行为准。

## 3. 导入并启动模型容器

```bash
sudo docker load -i /home/ubuntu/github/docker/codefenderc3_v8.tar.gz
sudo docker images
sudo docker volume create nkamg-torch-cache
sudo docker run -d --name codefender-c3-v8 --restart unless-stopped \
  -p 127.0.0.1:8001:8000 \
  -v nkamg-torch-cache:/root/.cache/torch \
  codefender:latest
sudo docker logs --tail 50 codefender-c3-v8
curl --max-time 15 http://127.0.0.1:8001/readyz
curl --max-time 300 http://127.0.0.1:8001/health
```

这个包实际导入标签是 `codefender:latest`。若已有同名容器，先检查 `docker ps -a`，不要删除其他服务。
模型可能由 `/health` 触发加载；首次启动需下载约 104 MB InceptionV3 权重，故健康请求可能较慢。
预期 `/readyz` 返回 `ready:true, model_count:33, view_count:15`。

### 权重下载失败时补齐缓存

保持 HTTPS 校验，下载并校验官方文件后复制入缓存：

```bash
curl -fL --retry 3 --connect-timeout 20 \
  https://download.pytorch.org/models/inception_v3_google-0cc3c7bd.pth \
  -o /tmp/inception_v3_google-0cc3c7bd.pth
sha256sum /tmp/inception_v3_google-0cc3c7bd.pth
# SHA256 必须以 0cc3c7bd 开头，否则不要使用，重新下载。
sudo docker exec codefender-c3-v8 mkdir -p /root/.cache/torch/hub/checkpoints
sudo docker cp /tmp/inception_v3_google-0cc3c7bd.pth codefender-c3-v8:/root/.cache/torch/hub/checkpoints/
sudo docker restart codefender-c3-v8
curl --max-time 300 http://127.0.0.1:8001/health
```

本机已下载成功的同名权重也可以复制到云端 `/tmp` 后，按上述校验和复制步骤处理。

### BinaryNinja 与签名库现有限制

该包的启动脚本把许可证 JSON 解析成 list 后传给 `core_set_license`，存在初始化错误。
本机 33 模型返回成功不证明所有反汇编特征真实有效。云端也需要使用有效许可证，
并验证实际 PE 能提取函数、操作码和图特征，不能只看 `/readyz` 或子模型计数。
未核实许可证格式前不自动修改许可证或绕过校验。
如需先跑不依赖反汇编的检测，可把 `web/config.ini` 的 `include_de` 改为 `false` 并重启后端，
但这不等价于完整 33 模型链路，部分模型可能跳过或回退。

该镜像没有 `/app/signatures`、`/admin/config`、`/update-signatures`。
签名库和相关接口不能通过补一个目录获得，需要提供真正包含这些代码与数据的镜像。

## 4. 更新并重启后端（5006）

```bash
cd /home/ubuntu/github/NKAMG-AIDefender/web/FastAPI
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

若缺少 venv：`sudo apt-get install -y python3-venv`。
先停止此前占用 5006 的后端。配置已经指向 `http://127.0.0.1:8001/predict-single`，默认 `include_de=true`。

长期运行可使用 systemd（先结束上面的手动后端）：

```bash
sudo cp /home/ubuntu/github/NKAMG-AIDefender/web/deploy/nk-amg-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nk-amg-backend
curl http://127.0.0.1:5006/health
```

## 5. 前端（9528）

临时联调：在 `web/Vue` 执行 `npm ci && npm run dev`。
长期部署使用构建产物和 Nginx，Node.js 需满足 Vite 要求（项目建议 Node.js 20）：

```bash
cd /home/ubuntu/github/NKAMG-AIDefender/web/Vue
npm ci
npm run build
sudo apt-get install -y nginx
sudo cp ../deploy/nginx.conf /etc/nginx/conf.d/nkamg.conf
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

切换 Nginx 前，停止之前占用 9528 的 Vite。默认路径假设仓库由 ubuntu 用户维护。
Nginx 需有读取 dist 及其父目录的权限；若有 403，检查 `namei -l .../web/Vue/dist/index.html`。

腾讯云安全组放行 TCP 9528。使用同源代理时不必公网开放 5006 或 8001。
若服务器已开启 UFW，再执行 `sudo ufw allow 9528/tcp`。
浏览器访问 `http://服务器公网IP:9528`。

## 6. 验证上传链路

```bash
curl http://127.0.0.1:9528/api-backend/health
curl --max-time 360 -F 'file=@/实际路径/正常PE样本.exe' http://127.0.0.1:5006/detect
```

使用真实 Windows PE 文件，Linux `/usr/bin/true` 不属于 PE。
结果应包含 `exe_result` 下的实际子模型及“集成结果”，页面上传后切换“模型检测”。
若 HTTP 502，查看后端日志和容器内部服务日志：

```bash
sudo journalctl -u nk-amg-backend -n 80 --no-pager
sudo docker exec codefender-c3-v8 tail -n 80 /var/log/supervisor/codefender_err.log
```

本次已在 Windows 验证模型链路，尚未登录腾讯云执行安装或检测；云端验证以以上实际输出为准。
