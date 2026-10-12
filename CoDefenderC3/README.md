# CoDefenderC3

多视图 PE 恶意软件检测系统（33 子模型集成 / 15 特征视角 / BinaryNinja + PyTorch）。

> **说明文档已归档到 [`docs/`](docs/)，训练代码已归档到 [`train/`](train/)（2026-09-16 整理）。**
> 本文件仅作入口索引。

---

## 快速开始

### 推理服务（FastAPI）

```bash
# 依赖：先装 PyTorch CPU 版，再装其余（详见 requirements.txt / docker/check_requirements.py）
pip install "torch>=2.0" torchvision --index-url https://download.pytorch.org/whl/cpu
pip install torch_geometric
pip install -r requirements.txt
uvicorn engine.app:app --host 0.0.0.0 --port 8000
# 健康检查
curl http://127.0.0.1:8000/health

# 【本机开发】纯模型链路：四级哈希库预检全关，全部样本走模型
#   Windows:  dev_model_only.cmd
#   Ubuntu:   ./dev_model_only.sh
# 等价的手动写法（仅作用于当前命令行窗口的进程）
CODEFENDER_ENV=dev CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 \
  CODEFENDER_REQUIRE_HASH_DB=0 \
  uvicorn engine.app:app --host 0.0.0.0 --port 8000
```

> 过滤引擎 = `sha256 → md5 → fuzzy(ssdeep/imphash/authentihash) → tlsh` 四级哈希签名库预检，
> 命中即毫秒短路返回 `Malicious`、不进模型。关闭后所有样本无条件走 33 模型集成，
> 用于模型真实性能评估 / 误报溯源 / 训练集打标。
> 确认生效看 `GET /health` 的 `engine_mode`（`model_only` / `hash_db+model`）与 `hash_db` 段
> （`enabled=false` + 三个计数为 `null`），或启动日志
> `[hashdb] 过滤引擎未启用 → 所有样本走模型集成（纯模型模式）`。
> 详见 [`docs/README.md`](docs/README.md) 启动章节。

**开发 / 生产档位隔离**（本机可纯模型，容器必全引擎）——三层防护，互不干扰：

| 层 | 机制 | 作用 |
|----|------|------|
| 构建期 | `.dockerignore` 排除 `runtime_config.json` | 开发期开关文件不进镜像 |
| 运行期 | 容器内 / `CODEFENDER_ENV=prod` → 覆盖文件不加载也不落盘 | 即使挂载了整个项目目录也不生效 |
| 启动期 | Dockerfile 固化 `CODEFENDER_REQUIRE_HASH_DB=1` | 三库缺一即**拒绝启动**，不再静默降级为纯模型 |

> 生产想临时做纯模型对照：只能走内存内热切换（`POST /admin/config`，重启即恢复全引擎）；
> `"persist": true` 在生产档位被 409 拒绝。回归探针：`python _probe_env_profile.py`。

> ✅ 签名库**已打进镜像**（代码 + `ensemble.pkl` + sha256/md5/fuzzy 三族库全部内嵌），
> `docker run` **不需要任何 `-v`**；也**不要**挂 `/app/signatures` —— 挂卷只会让容器
> 读到卷里的旧库，与镜像版本脱钩。`REQUIRE_HASH_DB=1` 负责兜底：镜像里三族库若缺一，
> 容器会在启动期直接拒绝启动（刻意的：那种状态下生产其实一直在跑纯模型，漏检且无告警）。
> 要临时做纯模型对照，把 `codefender.ini` 里的 `CODEFENDER_REQUIRE_HASH_DB` 改成 `"0"`。

**改配置不生效 / 不想重启**：不必和 env 语法或容器 env 固化较劲，直接用运行时覆盖
（优先级 `POST /admin/config` > `runtime_config.json`（仅 dev 档） > 环境变量 > 默认值）：

```bash
curl -X POST http://127.0.0.1:8000/admin/config -H "Content-Type: application/json" \
     -d '{"hash_db_enabled": false}'          # 约 0.2s 生效，免重启；加 "persist": true 可落盘（仅 dev）
curl -s http://127.0.0.1:8000/admin/config    # 每项的值/来源/能否热生效
curl -s http://127.0.0.1:8000/health          # pid / started_at / env / engine_mode / hash_db
```

> 或编辑项目根 `runtime_config.json`（`{"overrides": {"HASH_DB_ENABLED": false}}`）→ 重启即生效，
> 或 `POST /admin/config -d '{"reload_file": true}'` 免重启生效（两者都**只在 dev 档**有效）。
> ⚠️ `docker restart` 不会重读 `-e`；容器内代码是 `COPY` 的，改宿主机源码须重建镜像。

开发环境也支持 `./start_codefender.sh`（Linux）或 Docker：

```bash
bash docker/build.sh                            # ① 暂存签名库 → ② 上下文预检 → ③ docker build
docker run -p 8000:8000 codefender-c3:v8        # 零挂载：代码/模型/签名库都在镜像里
```

> ⚠️ **不要**挂 `/app/signatures`：镜像自带完整三族库；且 `signatures/` 是 SQLite 分片库，
> 挂到 hgfs / VMware 共享目录上 POSIX 锁不可靠（**严禁**）。
> 改了代码 / 模型 / 库后必须**重建镜像 + 重建容器**（`docker rm` 后重跑 `run`）——
> 旧容器的 rootfs 在 `docker run` 时就固化了，`docker restart` 不会更新代码，也不会重读 `-e`。

### 训练

```bash
PYTHONIOENCODING=utf-8 python -u CoDefenderC3/train/build_minimal_dataset.py --help
PYTHONIOENCODING=utf-8 python -u CoDefenderC3/train/train_minimal.py --help
PYTHONIOENCODING=utf-8 python -u CoDefenderC3/train/verify_trained_ensemble.py --help
```

详见 [`train/README.md`](train/README.md)。

---

## 目录导航

| 路径 | 内容 |
|---|---|
| [`docs/`](docs/) | 全部说明文档（见下方索引） |
| [`train/`](train/) | 训练侧代码：数据集构建、集成训练、checkpoint、复验 |
| `engine/` | FastAPI 推理服务（11 个端点 + 生产加固） |
| `core/` | SDD 谱漂移检测引擎 + 7 个基线方法 |
| `models/` | 33 个子模型实现 + `MultiModelEnsemble` 集成类 |
| `feature_extraction/` | 特征提取层（15 种视角 / BN 48 项底层特征）← 引擎与训练共用 |
| `scaner/` | 哈希库扫描器（与 nkrepo 项目同步） |
| `signatures/` | 哈希签名库分片（sha256 / md5 / fuzzy） |
| `runs/` | 训练产物 `runs/<run_id>/` |
| `config.py` | 全局配置（路径 / 参数 / 视图组 / 运行时覆盖 / 档位）← 引擎与训练共用 |
| `model_registry.py` | 模型中心注册表 ← 引擎与训练共用 |
| `ensemble.pkl` | 预训练集成权重（834 MB，K=33 / V=15） |
| `dev_model_only.cmd` / `.sh` | 本机开发启动纯模型链路（带端口占用预检；`.cmd` 刻意 ASCII-only） |
| `_probe_env_profile.py` | 档位隔离回归探针（41 项断言） |
| `_probe_runtime_cfg.py` | 运行时配置热切换探针（20 项断言） |

### `docs/` 索引

| 文档 | 内容 |
|---|---|
| [`docs/README.md`](docs/README.md) | 项目总览：架构、API 端点、配置参考、常见问题 |
| [`docs/增量训练与Checkpoint技术方案.md`](docs/增量训练与Checkpoint技术方案.md) | 增量训练 + checkpoint 完整技术方案（缺陷清单 B1–B8 / 附录 C 最小数据集 / 附录 D MalGraph 接入） |
| [`docs/TESTING.md`](docs/TESTING.md) | 测试说明 |
| [`docs/PAPERS.md`](docs/PAPERS.md) | 33 个子模型的论文与架构参考 |
| [`docs/BINARYNINJA_OPTIMIZATION_GUIDE.md`](docs/BINARYNINJA_OPTIMIZATION_GUIDE.md) | BinaryNinja 分析选项优化指南 |
| [`docs/testing_hash.md`](docs/testing_hash.md) / [`docs/testing_hash_simple.md`](docs/testing_hash_simple.md) | 哈希库测试记录 |

---

## 运行纪律（Windows 开发环境）

- **必须** `PYTHONIOENCODING=utf-8`：否则中文输出崩溃且无报错信息。
- 长任务加 `python -u`：stdout 重定向时是块缓冲，print 长时间不可见。
- 批量特征提取加 `CODEFENDER_KEEP_BNDB=1`：避免清理动作累计触发安全删除钩子杀进程。
- **不要移动数据集目录**：`metadata.jsonl` 记的是绝对路径，`per_sample` 缓存键是路径的 md5，一搬就全失效。

---

## License

见 [`license.txt`](license.txt)。
