# 多用户检测升级事项（2026-10-16）

## 部署基线（用户提供，非实时监测）

- 腾讯云 Linux：8 vCPU，约 30 GiB 内存；无 Swap。
- 当次可用内存约 25 GiB；模型容器空闲使用约 2.55 GiB。
- 容器未单独限制 CPU/内存。根盘 493G，已用 231G，可用 242G（用户提供）。
- docker system df：镜像 3 个，总体约 9.875GB；容器 4 个、运行 1 个，约 50MB；活动卷约 109MB；构建缓存为 0。
- 默认保持 1 个运行任务、8 个等待任务；空闲内存不能替代运行峰值测量。

## 本轮实现（待云端部署验收）

- [x] 默认上传上限 20 MiB，前端预检、后端流式文件大小校验。
- [x] 服务端发布实际上传限额；旧服务器 max_upload_size=100 MiB 时仍受 uploads.max_file_size 限制。
- [x] Nginx 模板请求体上限 21 MiB，预留 multipart 开销；须同步实际 Nginx 配置。
- [x] 磁盘可用量低于 512 MiB 加一个最大文件预算时拒绝新样本。
- [x] 保持任务结束立即删除 Web 上传文件；非 PE、超限和队列满时清理文件。
- [x] 每分钟清理超过 1 小时的服务自有孤立上传文件，排队和运行中的文件不删。
- [x] 报告与样本分开：报告默认保留 1 小时供刷新恢复，运行数据不提交 Git。
- [x] 按入队顺序处理，轮询返回前方任务数，网页动态展示等待状态。
- [x] 修复此前 SHA256 查询返回变量作用域错误。
- [x] 多地址独立运行槽分配：每个模型服务最多接收一个 Web 推理请求，容量满继续走已有队列/忙碌机制。
- [x] 显式 429 可选择另一空闲服务；超时/未知失败不自动改投其他服务重复检测。
- [x] 并发 2 必须配置两个独立服务地址；禁止混用 docker cp 路径接口。
- [x] 模型健康检查覆盖所有已配置地址，返回 ready_workers/total_workers。
- [x] 记录 Web 排队与处理耗时，多服务模型请求记录耗时。
- [ ] 云端实际创建第二容器并验证双样本，不以本地 mock 测试替代推理验证。

## 下一阶段：模型服务改造

- [ ] 快模型先推理并发布部分结果，再运行反汇编/图模型；不能重复整轮推理来模拟进度。
- [ ] 模型服务提供进度协议，Web 持久化部分结果；前端分别展示等待/运行/成功/失败/超时/跳过。
- [ ] 检测结束前仅展示部分结论，明确成功模型数和缺失模型，不伪造 33 项成功结果。
- [ ] 将 BinaryNinja/MalGraph 重任务隔离为可终止子进程，超时回收子进程、文件和运行槽。
- [ ] 核对两套 BinaryNinja 分析的重复工作、设置差异、资源释放以及 NoneType 失败堆栈。
- [ ] 独立定位 core_set_license 的动态脚本来源；不输出许可证，不将未知错误直接归因于许可证无效。
- [ ] 默认上传接口不应走 docker cp 路径；若启用路径扫描，核对容器副本和缓存的生命周期。
- [ ] 记录排队、数据库查询、各阶段特征提取、每个模型推理及总耗时。
- [ ] 收集检测中 CPU/内存峰值和磁盘 df -h 输出后，测试是否可启用 2 个隔离执行槽。
- [ ] 验证多人公平排队、位置变化、刷新恢复、超时回收、异常样本和模型故障时的部分结果。
- [ ] 基于原有完整镜像叠加补丁构建；保留挂载/许可证等配置和旧容器，不从缺权重的仓库从零构建。

## 策略说明

20 MiB 是初始运营策略，可在真实样本测试后调整；小文件也可能因代码复杂度而反汇编很久，文件大小限制不能替代阶段超时。
1 个运行加 8 个等待时，Web 队列样本上界约 180 MiB，另计并发上传、multipart 临时文件、模型临时文件、缓存和日志。
不能按 TTL 删除仍在使用的样本。超过 1 小时仍在排队/运行的文件由任务持有，待完成/失败后删除；长期卡住问题必须通过模型隔离解决。

配置合并顺序仍是 config.example.ini 后 config.ini；用户私有配置不要覆盖。新增 [uploads] 字段如本地配置已存在则以实际配置为准。

## 双任务部署设计

采用两个独立容器/进程各串行处理一个样本，不在同一个共享模型实例内直接增加线程并发。
第二容器使用现有容器实际 Image ID，并在启动前复制现有 engine/app.py 和 scan_runtime.py 补丁；共享镜像权重层，模型加载后的内存、临时文件和运行槽各自独立。
第二容器从现有容器 inspect 结果复制必要的环境/许可证和挂载，绑定 127.0.0.1:8002:8000，不开放公网；不要复制密钥到仓库。
新容器设 CODEFENDER_MAX_CONCURRENT=1、3 CPU、10 GiB 内存，OMP/MKL/OpenBLAS 线程设为 2；现有容器不自动调整，保持其当前单任务运行设置和未限制资源的状态。这是初始待测预算，不代表实测足够或主机总资源已受限。
结合真实峰值调整；限制过低可能造成 OOM，需同时监测 OOMKilled、模型日志和 docker stats。
保留现有 torch 缓存卷，先确认缓存完成再复用，不复制大模型 tar 包，不运行 docker system prune -a。

第二服务就绪并真实样本测试后，服务器 web/config.ini 合并：

```ini
[server]
max_concurrent_scans = 2
max_queued_scans = 8

[codefender]
api_bases = http://127.0.0.1:8001,http://127.0.0.1:8002
scan_endpoint =
```

不替换其余配置。只运行一个 Web uvicorn 进程，内部两个 worker 消费同一个 SQLite 队列。
双任务同时运行时，前方任务数可能一次减少两个；展示人数而非精确等待分钟。
若双任务不稳定，max_concurrent_scans 恢复 1、api_bases 留空或仅列 8001，重启 Web 即可回退。

## 磁盘清理边界

- 当前没有磁盘压力，无需为释放空间删除仍被引用的模型镜像、回滚容器、许可证或 torch 权重卷。
- docker system df 的 reclaimable 不是删除指令；镜像共享层也不能将大小直接相加估算第二容器成本。
- 已配置 Web 样本生命周期及孤立文件清理；Nginx multipart 临时目录与容器临时目录仍需云端确认。
- 容器 json 日志建议每容器 max-size=10m、max-file=3，创建容器时使用 --log-opt 配置；不截断运行中日志文件。
- Supervisor 子进程 stdout/stderr 的轮转也需独立确认，Docker 日志轮转不涵盖内部文件。
- 旧停止容器、备份镜像及镜像 tar 文件仅在新部署通过真实检测验收后，按明确名称逐个清理；当前未执行云端删除。
- 队列完成记录删除后 SQLite 会复用空闲页，不每分钟 VACUUM；必要的离线压缩安排在停止 Web 后。

## 腾讯云操作步骤

先等当前检测结束，再在腾讯云执行。以下仅启动第二模型容器，Web 后端仍保持一个进程、内部两个队列消费者。

    cd /home/ubuntu/github/NKAMG-AIDefender
    git pull --ff-only origin main
    git log -1 --oneline
    sudo python3 web/deploy/model_worker.py
    sudo python3 web/deploy/model_worker.py --apply
    curl --fail --max-time 10 http://127.0.0.1:8002/readyz

首次启动需等待加载。如 readyz 暂不可用，查看下列日志后重试 curl，不要重复 --apply：

    sudo docker logs --tail 100 codefender-c3-v8-worker2
    sudo docker exec codefender-c3-v8-worker2 supervisorctl tail -8000 codefender stderr

脚本复制现有引擎补丁，但不会复制原容器全部可写层。若许可证或其他运行依赖仅在原容器内手动写入，新容器仍可能启动失败；此时先检查日志，不启用双任务，不盲目重建原容器。
只读许可证挂载和原环境会继承，但可同时运行的实例数仍应符合实际授权。

用一份现有测试 PE 验证第二服务（下列路径必须替换为实际测试文件）：

    curl --fail --max-time 330 -F 'file=@/实际路径/测试文件.exe' 'http://127.0.0.1:8002/predict-single?include_de=true'

确认返回有效预测及模型成功/失败数量后，再启用地址池：

    sudo python3 web/deploy/model_worker.py --enable-pool
    systemctl cat nk-amg-backend
    sudo systemctl restart nk-amg-backend
    sudo systemctl status nk-amg-backend --no-pager
    curl --fail --max-time 15 http://127.0.0.1:5006/model-health

如果 systemctl cat 提示服务不存在，按原来的启动方式重启唯一后端，避免额外启动重复 Web 进程。仓库已有 systemd 模板，不能假定服务器已经安装。
健康检查预期 ready_workers=2、total_workers=2；它只验证服务就绪，不代表每个样本 33 个模型都成功。

构建前端，使用已有依赖即可；若 node_modules 不存在则先 npm ci：

    cd /home/ubuntu/github/NKAMG-AIDefender/web/Vue
    npm run build
    sudo nginx -t
    sudo systemctl reload nginx
    sudo docker stats --no-stream codefender-c3-v8 codefender-c3-v8-worker2

Nginx 实际生效配置也应将该站点 client_max_body_size 调整为 21m；保留域名/TLS 等私有配置，不整站覆盖模板。
两个不同浏览器各提交一个小 PE，确认同时运行、后续任务显示前方人数，并观察持续检测期间内存/CPU。
第二容器仅本机访问；不复制镜像 tar，不执行全局 Docker prune。

回退：将 web/config.ini 的 max_concurrent_scans 改回 1、api_bases 改为 http://127.0.0.1:8001，重启唯一 Web 后端。
待第二容器任务结束后可 sudo docker stop codefender-c3-v8-worker2；保留它以便检查，不自动删除。
本轮没有修改 MalGraph/BinaryNinja 的卡顿流程或逐模型结果协议，双容器提升并发容量，不承诺单个样本变快。
