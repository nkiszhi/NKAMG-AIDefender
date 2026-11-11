# 签名库快速检查

核对日期：2026-11-11。本页只保留入口，避免与完整指南重复维护。部署、数据布局、命中协议、更新和持久化详见 [签名库指南](testing_hash.md)。

## 只读检查

标准镜像按 [README](README.md#3-生产环境启动)启动后：

```bash
curl http://127.0.0.1:18001/readyz
curl http://127.0.0.1:18001/health
BASE_URL=http://127.0.0.1:18001 TIMEOUT=180 bash docker/test_api.sh --expect-prod
```

- `ready=true` 表示模型服务就绪；再看 `engine_mode=hash_db+model`、`require_hash_db=true` 和库状态。
- `env=prod` 本身不能证明签名库启用，SMDA 纯模型镜像也是 prod。
- 不固定历史库条数；真实命中需隔离样本/测试库验证，不能只看冒烟 PASS。
- 开发命中诊断可含 Source/HashMatch，生产响应不返回这些字段，见 [字段差异](README.md#4-接口返回数据差异)。

## 写操作

`/update-signatures`、运行配置修改和 active 版本回滚仅用于明确授权的独立测试/运维环境。不要把良性哈希注入线上恶意库；更新后的容器文件系统不自动成为新镜像，重建前须备份增量。详细流程见[完整指南](testing_hash.md#4-更新接口会写库)。
