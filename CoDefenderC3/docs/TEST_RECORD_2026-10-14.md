# CoDefenderC3 · docker/ 自动化测试脚本 测试记录

| 项目 | 内容 |
|---|---|
| 被测对象 | `CoDefenderC3/docker/` 下 6 个脚本（`test_api.sh` / `check_requirements.py` / `check_context.py` / `check_model_imports.py` / `stage_signatures.py` / `build.sh`） |
| 被测服务版本 | 工作区当前 HEAD（`D:\VM_Share\CoDefenderC3_v8\CoDefenderC3`），`ensemble.pkl` md5 `6cb4c2b9861d189f8d8e59f1677d3300` |
| 执行时间 | 2026-10-14 15:03 – 15:15 (GMT+8) |
| 执行环境 | Windows 宿主，Python 3.14.7 (miniconda `D:/work/tools/miniconda3`)，torch 2.11.0+cu128 |
| 靶标 | 宿主本机 dev 档位服务实例（`http://127.0.0.1:8000`），见 §1 |
| 总体结论 | **`test_api.sh` 与 3 个静态校验脚本功能正常；发现 2 个脚本缺陷 + 1 个应用级缺陷。容器本体因网络不可达未能实测。** |

---

## 1. 靶标说明：容器不可达，改用功能等价的本地实例

本次**未能**直接对 Docker 容器执行测试，原因如下（证据已留档）：

| 检查项 | 命令 | 结果 |
|---|---|---|
| VM 是否在运行 | `vmrun -T ws list` | ✅ running（`D:\病毒中心项目运行环境\Ubuntu 64 位 22.04.vmx`） |
| VMware Tools | `vmrun checkToolsState` | ✅ running |
| VM 网络模式 | 读 `.vmx` | `ethernet0.connectionType = "nat"`，MAC `00:0C:29:8C:63:D3` |
| VM IP（DHCP 租约） | `vmnetdhcp.leases` | `192.168.186.128`，**最后一次租约 2026-10-13 12:17 UTC 到期后未续约** |
| ICMP | `ping 192.168.186.128` | ❌ 100% 丢包（"无法访问目标主机"，ARP 解析失败） |
| TCP 8000 | `curl http://192.168.186.128:8000/livez` | ❌ `000`（无响应） |
| 客户机 IP 查询 | `vmrun getGuestIPAddress` | ❌ `Unable to get the IP address` |
| 宿主 docker | `command -v docker` | ❌ 宿主无 docker CLI/daemon（与 10-13 记录一致） |

> 对照 2026-10-13 的记录：当时该 VM **ping 通**，但 22 / 2375 / 2376 / 8000 / 8080 / 5000 **全 closed**
> ⇒ 既无 ssh 也无 docker API，本来就进不了容器。本次连 ICMP 都不通，VM 侧网络进一步退化。
> **结论：宿主→容器的通道在本次执行时完全不可用。**

因此按"被测对象是脚本本身"的目标，改用**同一份代码、同一份 `ensemble.pkl`** 在本机启动一个
功能等价的 dev 档位实例作为靶标，用于验证脚本的采集/判定/汇总能力。**此替代不覆盖**容器专有项
（`env=prod`、`model_path=/app/ensemble.pkl`、三库计数、prod 档位 `persist` 409 等），已在 §5 标注。

启动方式（为不污染宿主环境，依赖装在隔离目录 `D:/work/tools/apideps`）：

```bash
cd CoDefenderC3
PYTHONPATH=D:/work/tools/apideps PYTHONIOENCODING=utf-8 \
CODEFENDER_ENV=dev CODEFENDER_HASH_DB_ENABLED=0 CODEFENDER_FUZZY_DB_ENABLED=0 CODEFENDER_REQUIRE_HASH_DB=0 \
D:/work/tools/miniconda3/python.exe -u -m uvicorn engine.app:app --host 127.0.0.1 --port 8000
```

新增隔离依赖：`fastapi 0.143.0`、`uvicorn 0.54.0`、`starlette 1.8.0`、`pydantic 2.14.1`、`python-multipart 0.0.32`。

---

## 2. 用例结果矩阵

### 2.1 `docker/test_api.sh`

| # | 用例 | 预期 | 冷启动首跑 | 预热后复跑 | 结论 |
|---|---|---|---|---|---|
| TC-01 | 可达性 `GET /livez` | HTTP 200 | PASS | PASS | ✅ |
| TC-02 | `GET /livez` 存活字段 | `alive=true` | PASS | PASS | ✅ |
| TC-03 | `GET /readyz` 就绪 | 200 + `ready=true` | **FAIL（503）** | PASS | ❌ 见 D1 |
| TC-04 | `GET /health` 健康 | HTTP 200 | PASS | PASS | ✅ |
| TC-05 | 档位识别 `env`/`engine_mode` | 正确回显 | PASS（`dev` / `model_only`） | PASS | ✅ |
| TC-06 | `GET /metrics` | HTTP 200 | PASS | PASS | ✅ |
| TC-07 | `GET /model-info` | 200 + `status=loaded` | PASS（33 模型 / 15 视角） | PASS | ✅ |
| TC-08 | `GET /admin/config` | HTTP 200 | PASS | PASS | ✅ |
| TC-09 | `POST /predict-single?include_de=false` | 200 + 判定字段 | SKIP（未指定） | PASS（3s，`Status=0` `IsMalicious=False` `Score=0.368`） | ✅ |
| TC-10 | `POST /predict-directory` | 200 + 统计 | SKIP（未指定） | PASS（6s，HTTP 200）但**统计列为空** | ⚠️ 见 D2 |

| 轮次 | 命令 | 结果 | 退出码 |
|---|---|---|---|
| 冷启动首跑 | `bash docker/test_api.sh`（服务启动后 1s 立即执行） | `PASS 6  FAIL 1  SKIP 2` | **1** |
| 预热复跑 | `bash docker/test_api.sh` | `PASS 7  FAIL 0  SKIP 2` | **0** |
| 预热完整跑 | `bash docker/test_api.sh --sample <benign> --dir <samples>` | `PASS 9  FAIL 0  SKIP 0` | **0** |

### 2.2 静态校验脚本

| # | 脚本 | 结果 | 退出码 | 关键输出 |
|---|---|---|---|---|
| TC-11 | `check_requirements.py` | ✅ 通过 | **0** | 运行时闭包触达本地模块 29 / 第三方 15；硬依赖 `fastapi/numpy/starlette/torch` 全覆盖；`requirements.txt` 启用 10 条 / 注释 15 条 |
| TC-12 | `check_context.py` | ✅ 通过 | **0** | 16 条 COPY 源全部 `[ ok ]`；未过滤上下文 13,962 文件 / 1.8GB → 入镜像 2,669 文件 / 1.7GB |
| TC-13 | `check_model_imports.py` | ✅ 通过 | **0** | REGISTRY 34 模型 / 去重后 30 模块全部 `[ ok ]`；**无 FATAL，WARN 0** |

`build.sh` 与 `stage_signatures.py` **未执行**：两者会写 1GB 级构建上下文并触发 `docker build`，
宿主无 docker daemon，执行无意义（`stage_signatures.py` 的执行结果已间接验证 —— `.docker_build/signatures/`
存在且 `check_context.py` 读到 2,564 文件 / 1008.5MB 全部 `[ ok ]`）。

### 2.3 推理能力抽查（脚本之外，用于交叉验证 D2）

直接调用 `POST /predict-directory?directory=<samples>&recursive=false&include_de=false`：

```
HTTP 200   耗时 4.70s
Summary: TotalFiles=3  ScannedFiles=3  MaliciousCount=1  BenignCount=2
         ErrorCount=0  TimeoutCount=0  SkippedNonPE=0
Timing : AvgSampleTime=1.564s  Throughput=0.639 文件/秒
```

样本构成：2 个良性（13KB / 20KB）+ 1 个恶意（23KB）。**检出 1 恶意 / 2 良性，与预期完全一致**，
说明接口与模型链路本身工作正常 —— 脚本打印为空纯属字段名解析错（D2）。

`POST /predict-single` 的完整模型统计（同一响应里脚本只读了前两项）：

```json
{"TotalModels": 33, "OkModels": 20, "SkippedModels": 10, "ErrorModels": 3,
 "MaliciousVotes": 3, "BenignVotes": 17, "AgreementRate": 0.15,
 "EnsembleScore": 0.368145, "EnsemblePred": 0, "ScoreRange": [0.0515, 1.0]}
```

---

## 3. 缺陷与发现清单

### D1 ❌ 【应用级·高】`/readyz` 在冷启动后恒为 503 —— 模型是懒加载

**现象**：进程刚起来时 `/livez` 1 秒即可用，但 `/readyz` 无论等多久都返回 503 `model not loaded`；
直到**任意调用一次 `/health`（或 `/model-info` / `/predict-*`）**之后，`/readyz` 才立刻变 `ready: true`（`model_count=33`）。

**根因（代码定位）**：`engine/app.py` 中没有任何启动期预热。

- `readyz()`（`engine/app.py:1687`）只读模块全局 `_ENSEMBLE`，**自身不触发加载**：
  ```python
  if _ENSEMBLE is None:
      return JSONResponse(status_code=503, content={"ready": False, "reason": "model not loaded", ...})
  ```
- 模型加载只发生在 `_load_ensemble()`（`engine/app.py:219`），调用点全部是**惰性**的：
  `:244`（`_get_sdd_engine`）、`:1728`（`/health`）、`:2566`（`/predict-single`）、`:3020`（`/predict-directory`）。
- 启动期只执行了 `_init_hash_dbs()`（`engine/app.py:1390`）与 `_log_engine_context()`，**都不加载集成模型**；
  全文没有 `@app.on_event("startup")` / `lifespan` / 预热线程。

**实测**：冷启动后 `/readyz` 连续 503；调用 `/health` 一次（返回 `model_count=33`）后 `/readyz` 立即转为：
```json
{"ready": true, "model_count": 33, "view_count": 15}
```

**影响（三处，均需修）**：

1. **`test_api.sh` 冷启动首跑必然误报 1 个 FAIL**（TC-03）。本次实测 `PASS 6 / FAIL 1 / SKIP 2`，退出码 1。
   对 CI 环境而言，这意味着"容器刚起来就跑冒烟"必然红灯。
2. **`docs/TESTING.md §2` 的等待循环会死循环**。该段教用户：
   ```bash
   while ! curl -s http://localhost:8000/readyz | grep -q '"ready":true'; do ... done
   ```
   由于 `/readyz` 永远不触发加载，容器冷启动时这个循环**永远转不出去**。
3. **K8s `readinessProbe` 指向 `/readyz` 会导致 Pod 永远 NotReady**（`docs/TESTING.md §3.2` 正是这么建议的），
   流量永远得不到调度。

**修复建议（三选一，推荐 a）**：

- **(a) 启动期预热**（最贴合原设计意图）：加 FastAPI 启动钩子同步或后台预热。
  ```python
  @app.on_event("startup")
  async def _warmup():
      import anyio
      await anyio.to_thread.run_sync(_load_ensemble)   # 771MB 反序列化，别阻塞事件循环
  ```
- **(b) 让 `/readyz` 自身触发加载**：`if _ENSEMBLE is None: _load_ensemble()`。
  缺点是把探针变成阻塞调用（首次命中要等十几秒），K8s 探针超时容易误判。
- **(c) 只改文档/脚本**：`/readyz` 语义改为"不预热、只报状态"，把等待循环和探针都换成 `/health`。
  改动最小，但 Pod 就绪语义仍然反直觉。

> 本次实测模型加载耗时约 15–20s（CPU，771MB pkl，33 模型），与 `docs/TESTING.md` 所称"30~60 秒"同量级。

### D2 ❌ 【脚本缺陷·中】`test_api.sh` 解析 `/predict-directory` 统计的字段名与真实响应不符

**位置**：`docker/test_api.sh:217`

```bash
ok "/predict-directory" "$((t1-t0))s total=$(jget Total) malicious=$(jget Malicious) benign=$(jget Benign)"
```

**真实响应结构**：顶层只有 `Summary` 与 `Results`，统计在 `Summary` 下：

```
Summary.TotalFiles  Summary.TotalFilesInDirectory  Summary.SkippedNonPE
Summary.ScannedFiles  Summary.MaliciousCount  Summary.BenignCount
Summary.ErrorCount  Summary.TimeoutCount  Summary.Directory  Summary.Timing
```

**后果**：TC-10 打印成 `total= malicious= benign=`（全空），把"扫描了 3 个文件、检出 1 恶意 2 良性"
这一关键信息完全吞掉 —— 用例显示 PASS，但**实际证据为零**，回归时无法发现结果异常。

**修复补丁**：

```diff
-  ok "/predict-directory" "$((t1-t0))s total=$(jget Total) malicious=$(jget Malicious) benign=$(jget Benign)"
+  ok "/predict-directory" "$((t1-t0))s total=$(jget Summary.TotalFiles) scanned=$(jget Summary.ScannedFiles) malicious=$(jget Summary.MaliciousCount) benign=$(jget Summary.BenignCount) errors=$(jget Summary.ErrorCount) timeout=$(jget Summary.TimeoutCount)"
```

### D3 ⚠️ 【脚本缺陷·低】`/predict-single` 回显遗漏 `ErrorModels`，掩盖部分模型失效

**位置**：`docker/test_api.sh:199`

```bash
ok "/predict-single" "... ok/skip=$(jget ScanResult.ModelStats.OkModels)/$(jget ScanResult.ModelStats.SkippedModels)"
```

`ModelStats` 实际有 4 个计数字段（`TotalModels` / `OkModels` / `SkippedModels` / `ErrorModels`），
脚本只回显前两类。本次实测 `20 / 10 / 3`（20+10+3=33）：**有 3 个模型是"报错缺席"而非"被跳过"**，
但从脚本输出完全看不出来，`AgreementRate=0.15`（只有 20 个模型参与、17 票良性）这一异常信号也被隐藏。

同时 `docker/test_api.sh:201` 的提示阈值 `-ge 9` 是写死的经验值，与 `include_de=false` 的实际跳过数（10）
耦合；一旦模型注册表增删就会失真。

**修复补丁**：

```diff
-  ok "/predict-single" "$((t1-t0))s  Status=$(jget Status) Score=$(jget Score) IsMalicious=$(jget IsMalicious) ok/skip=$(jget ScanResult.ModelStats.OkModels)/$(jget ScanResult.ModelStats.SkippedModels)"
+  ok "/predict-single" "$((t1-t0))s  Status=$(jget Status) Score=$(jget Score) IsMalicious=$(jget IsMalicious) ok/skip/err=$(jget ScanResult.ModelStats.OkModels)/$(jget ScanResult.ModelStats.SkippedModels)/$(jget ScanResult.ModelStats.ErrorModels) agreement=$(jget ScanResult.ModelStats.AgreementRate)"
+  ERR="$(jget ScanResult.ModelStats.ErrorModels)"
+  if [ -n "$ERR" ] && [ "$ERR" != "0" ] 2>/dev/null; then
+    printf '         [note] ErrorModels=%s —— 这些模型是"报错缺席"，不是被 include_de 跳过，需查容器日志\n' "$ERR"
+  fi
```

### D4 ℹ️ 【文档不一致·低】`view_count` 与 `TESTING.md` 示例不符

`docs/TESTING.md §3.2 / §3.4` 的示例写 `"view_count": 16`，实测 `ensemble.pkl` 为 **15**
（`/health`、`/readyz`、`/model-info` 三处一致；视角列表 `V1_byte … V10_metadata` 共 15 项）。
脚本本身只做回显不判定，不影响结论，但示例值宜同步。

### D5 ℹ️ 【环境】容器通道不可用（非脚本问题）

见 §1。若要让 `test_api.sh` 覆盖容器专有项，需先把通道打通（VM 内起 ssh，或开放 2375/tcp，
或直接在 VM 内在容器旁执行 `bash docker/test_api.sh`）。

---

## 4. 结论

1. **`docker/test_api.sh` 的采集与判定逻辑基本可靠**：可达性探测、探针、健康、指标、模型档案、
   运行时配置六类只读用例在预热后全部 PASS（`PASS 9 / FAIL 0 / SKIP 0`，退出码 0），
   自动识别档位（`[note] model_path 不是 /app/ensemble.pkl`）、自动绕过代理、`include_de` 走 query 等
   历史踩坑均已固化进脚本，行为符合预期。
2. **3 个静态校验脚本在真实仓库上全部通过**（退出码均为 0）：依赖覆盖、构建上下文、模型导入三者
   无阻断性问题。`check_model_imports.py` 明确报 `WARN 0 / 无 FATAL`，可认为 `torch`↔`torchvision` 代际匹配正常。
3. **存在 2 个脚本缺陷（D2、D3）与 1 个应用级缺陷（D1）**，其中 **D1 影响面最大** ——
   它同时污染了 CI 冒烟（必然误报 FAIL）、文档给的等待循环（死循环）和 K8s 就绪语义（永不 Ready）。
   建议优先处理 D1，再顺手修 D2/D3 两个回显缺陷（均为一行级 diff，不改变脚本通过/失败口径）。
4. **本次未取得任何容器内证据**：`env=prod` / `model_path=/app/ensemble.pkl` / `require_hash_db=true` /
   三库计数 / prod 档位 `persist` 返回 409 等项目**均未验证**。待容器通道恢复后应按
   `docs/DOCKER_TEST_SCRIPTS_USAGE.md §1.5` 加 `--expect-prod` 重跑并补入本记录。

---

## 5. 未覆盖项（需容器可达后补测）

| 用例 | 说明 |
|---|---|
| `--expect-prod` 硬判据 | 要求 `/health.env == prod`，本次为 dev 实例，未执行 |
| `/health` 三库计数 | 本次 `HASH_DB_ENABLED=0`，`sha256/md5/fuzzy` 均为 `null`；容器应返回真实条数 |
| `POST /reload-model` | 改状态，脚本刻意不覆盖；容器内需验证 `model_path` 为 query 参数、不持久化 |
| `POST /update-signatures` | 改状态，脚本刻意不覆盖；需验证 400/409/`no_new_rows`/`published` 四类返回 |
| `GET|POST /admin/config` 写入 | prod 档位 `persist`/`reload_file` 应返回 409 |
| `predict-directory` 容器内路径 | 需 `docker cp` 样本进容器后执行 |

---

## 6. 附录

### 6.1 原始日志

| 文件 | 内容 |
|---|---|
| `docs/test-records/2026-10-14/smoke_cold_start.txt` | 冷启动首跑（`PASS 6 / FAIL 1 / SKIP 2`，退出码 1） |
| `docs/test-records/2026-10-14/smoke_warm.txt` | 预热复跑（`PASS 7 / FAIL 0 / SKIP 2`，退出码 0） |
| `docs/test-records/2026-10-14/smoke_warm_full.txt` | 预热完整跑（`PASS 9 / FAIL 0 / SKIP 0`，退出码 0） |
| `docs/test-records/2026-10-14/check_model_imports.txt` | 模型导入探针完整输出 |
| `docs/test-records/2026-10-14/predict_directory_response.json` | `/predict-directory` 原始响应（D2 证据） |

### 6.2 复现命令

```bash
cd CoDefenderC3

# 冷启动首跑（复现 D1）
#   先启动服务，等 /livez 返回 200 后立即执行：
bash docker/test_api.sh                                   # 期望看到 /readyz FAIL(503)

# 预热复跑（D1 消失）
curl -s http://localhost:8000/health > /dev/null           # 触发懒加载
bash docker/test_api.sh                                   # 期望 PASS 7 / FAIL 0

# 完整跑（含推理）
bash docker/test_api.sh --sample <良性样本路径> --dir <样本目录>

# D2 证据：对照脚本字段与真实响应
curl -s -X POST "http://localhost:8000/predict-directory?directory=<样本目录>&recursive=false&include_de=false" \
  | python -c "import json,sys;print(json.load(sys.stdin)['Summary'])"

# 静态校验
python docker/check_requirements.py     ; echo "exit=$?"
python docker/check_context.py          ; echo "exit=$?"
python docker/check_model_imports.py    ; echo "exit=$?"
```

### 6.3 被测脚本与代码位置索引

| 对象 | 位置 |
|---|---|
| 冒烟脚本主流程 | `docker/test_api.sh:104-243` |
| `/predict-single` 回显（D3） | `docker/test_api.sh:199-203` |
| `/predict-directory` 回显（D2） | `docker/test_api.sh:212-223` |
| `/readyz` 实现（D1） | `engine/app.py:1685-1702` |
| `_load_ensemble()` 懒加载入口（D1） | `engine/app.py:219-230` |
| 模型加载调用点（全部惰性） | `engine/app.py:244, 1728, 2566, 3020` |
| 启动期初始化（不含模型预热） | `engine/app.py:1390-1391` |
