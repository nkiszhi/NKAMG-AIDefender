# 签名库预检、更新与验证

核对日期：2026-11-11。部署见 [README](README.md#3-生产环境启动)，本文件不再使用旧 docker commit/双挂载方案或固定历史库条数。

## 1. 两层命中机制

| 层次 | 状态/行为 |
|---|---|
| Web 样本 MySQL 查询 | 有效 PE 的 SHA256/MD5 查询，已知样本直接返回，不进模型队列 |
| CoDefender 签名库预检 | SHA256 → MD5 → fuzzy/ssdeep → TLSH 各级按配置检查，命中短路模型 |

两层配置独立；Web 未连接 MySQL不代表模型签名库关闭，模型纯模型运行也不代表 Web 样本库无效。

## 2. 启动配置与布局

- 标准全引擎镜像设置 `CODEFENDER_HASH_DB_ENABLED=1`、`CODEFENDER_FUZZY_DB_ENABLED=1`、`CODEFENDER_REQUIRE_HASH_DB=1`；必需库缺失拒绝启动。
- SMDA CPU 纯模型（`Dockerfile.smda`）/ GPU train 变体关闭这三个开关；CPU 全引擎（[Dockerfile.smda.cpu-serve](../Dockerfile.smda.cpu-serve)）/ GPU serve 变体开启，均可为 prod。CPU 全引擎还要求三族非空布局门禁。
- `REQUIRE_HASH_DB=0` 只是取消强制启动门禁，**不等于关闭哈希预检**；是否预检看 ENABLED 配置。
- 构建签名源可以使用版本化 `current/releases`，`stage_signatures.py` 解析当前版本后将完整库暂存打包；标准镜像内初始库是扁平布局。
- 库根由 `CODEFENDER_HASH_DB_DIR` 指定。运行时 active 版本、构建源版本和镜像内版本要分开核对，不把挂卷覆盖当成标准部署步骤。

```bash
# 从 CoDefenderC3/ 执行
python docker/stage_signatures.py
bash docker/build.sh codefender-c3:prod --progress=plain
# 按 README 启动后
curl http://127.0.0.1:18001/readyz
curl http://127.0.0.1:18001/health
```

查看 `env`、`engine_mode`、`require_hash_db`、`hash_db`，不要硬编码历史条数或仅按环境为 prod 判断库已启用。

## 3. 命中与未命中验证

使用隔离测试服务和可信测试签名/样本。不要把良性样本的哈希写进线上恶意库来制造命中。

```bash
curl -X POST "http://127.0.0.1:18002/predict-single?include_de=true" -F "file=@known-sample.exe"
curl -X POST "http://127.0.0.1:18001/predict-single?include_de=true" -F "file=@known-sample.exe"
```

- 开发命中可提供 `Source`、`ScanResult.HashMatch`；模型可能完全未执行，缺模型统计属于该路径正常边界。
- 生产命中仅保留业务投影：MD5、SHA256、IsMalicious、VirusName、Packed，不暴露库内病毒名、命中细节和分数。SHA256 命中输出 `Malicious`；TLSH/SSDeep 命中输出 `Suspicious`；MD5、imphash、authentihash 保持 `Malicious`。按实际 `Source` / `HashMatch.fuzzy_type` 命名，不把 fuzzy 记录关联的 SHA256 当成精确命中。
- 开发/Web（含流式）保留的 `StatusLabel` 同步采用以上名称；字段结构、`Status=1`、`IsMalicious=true`、`Score=1.0`、目录计数和预检短路不变。`Suspicious` 不是新增数值状态或计数桶。
- 命中短路的默认 Packed 值不证明已做完整壳分析；未命中才继续有效模型聚合。
- 目录扫描按内容选 PE；成功/失败/超时区分见 [返回契约](README.md#4-接口返回数据差异)。

## 4. 更新接口（会写库）

`POST /update-signatures` 在三个入口共享，不含应用内鉴权，只供内网/鉴权代理后的运维操作。全流程为独立 staging 导入、计数检查、可选 VACUUM、发布版本和热切换；模型重载不是签名库更新/回滚接口。

| 参数 | 位置 | 默认/要求 |
|---|---|---|
| `file` | multipart | 单个 csv/hdb/zip；与 dir_path 二选一 |
| `dir_path` | query | 服务端本地目录，收集该层 csv/hdb；不是客户端路径 |
| `week_id` | query | 不填使用时间标识；输入记录带前缀，每次新投递使用新标识 |
| `malicious_only` | query | true，CSV 仅保留有威胁标注的记录 |
| `vacuum` | query | true，对受影响分片执行整理 |

源文件按内容自动探测 CSV、hashBase 9 字段 hdb、ClamAV hdb；zip 中只导入接受的源文件。不承诺所有任意 CSV/schema 都可用。

```bash
# 只在独立签名测试环境执行；变更前记录当前库版本和计数
curl -X POST "http://127.0.0.1:18001/update-signatures?week_id=local-batch-new&vacuum=true" \
  -F "file=@test-signatures.csv"
curl -X POST -G "http://127.0.0.1:18001/update-signatures" \
  --data-urlencode "dir_path=/data/test-signatures" --data-urlencode "week_id=local-directory-new"
```

`status=published` 表示本次发布；`no_new_rows` 表示未产生新行、不发布，不是异常。行级去重不等于可以复用同一个投递记录名；相同 week_id/文件名可能被导入记录跳过。

| HTTP | 常见情况 |
|---|---|
| 400 | 哈希预检关闭、输入未二选一、目录/文件/zip 或格式不合法 |
| 409 | 新库计数回退，拒绝发布 |
| 500 | 导入/发布/实例切换失败；需查看日志和 active 版本 |

## 5. 持久化、回滚和验收

- 更新后检查 `/health.hash_db`、发布目录/current 指向及真实命中；单看行数不能证明每条签名可查询。
- 容器 API 写入位于容器文件系统：同一容器重启不等于镜像变更；删除/重建容器可能丢失这些增量。长期保留须有明确导出/备份与重建流程，不能把运行中增量误认为已进入原镜像。
- 回滚需让 active 指针恢复到已验证旧版并重新初始化服务；`/reload-model` 不会重置签名库。按实际发布布局/平台处理，避免直接编辑在线分片。
- staging 与发布额外占磁盘；变更前核对空间、权限、版本保留和备份。计数不回退是有限门禁，不是签名正确性或完整事务安全承诺。
- 未接入真实签名库、MySQL 或只测关闭库错误码时，报告必须明确“未验证真实命中/写入”。历史证据不改写。

代码依据：[共享管理接口](../engine/app.py)、[签名库实现](../scaner/scanner.py)、[构建暂存](../docker/stage_signatures.py)。
