# BN 基线特征快照（golden fixture）—— W1

> 2026-11-05 落地。SMDA 迁移 Phase 1（IR 抽象）的**验收基准**。

## 为什么需要

Phase 1 要把「BinaryNinja → 特征」这条链路重构一遍（引入 `ProgramIR` + `backend_bn.py`）。
重构完成后必须能回答一个问题：**在仍然是 BN 后端的前提下，特征有没有变？**

没有这个基准，Phase 7 的指标对比就分不清三件事混在一起：

1. IR 重构引入的 bug
2. hash 修复（W0）带来的语义变化 —— 本来就该变
3. 后端从 BN 换成 SMDA 带来的分布漂移 —— 也本来该变

所以基准必须是「**同一份代码、同一套后端**」下的输出指纹。

## 产物

| 位置 | 内容 |
|---|---|
| `tests/fixtures/bn_baseline/samples.json` | 88 个样本的清单 + 元数据（41 KB） |
| `tests/fixtures/bn_baseline/manifest.json` | 2640 个特征指纹（530 KB） |
| `tests/fixtures/bn_baseline/README.md` | 目录说明 |
| `tests/baseline_fixture.py` | 采集 / 校验工具（select / capture / verify） |

全量特征数组不入库（单样本约 10 MB × 88 = 900 MB）。
需要具体数值时用 `--arrays <目录>` 导到仓库外。

## 指纹的判据

每个特征向量算 `sha256(ascontiguousarray(arr).tobytes())`。

* **sha256 相同 = 逐位相同** —— 这是 Phase 1 的硬判据；
* 维度 / dtype / `sum` / `nz` 是辅助信息，用于人眼快速定位差异；
* `sum` 在不同 numpy 版本下末位可能不同（浮点实现差异），**不作为判据**。

## 覆盖范围

| 特征组 | 数量 | 状态 |
|---|---|---|
| A01-A08 / B01-B07 / C01-C04 / F01-F04 / G01-G04 / H01-H03 | 30 | ✅ 已采集，verify 88/88 逐位一致 |
| D01-D07 / E01-E04（需 BN） | 9 | ❌ BN 许可过期，未采集 |

## 🔴 许可阻塞（本 W1 最重要的发现）

采集 D/E 特征时发现 **BinaryNinja 在本机无法创建任何 BinaryView**：

```
BNIsLicenseValidated = False
core_product      = 'Binary Ninja'
core_serial       = ''          ← 空
core_license_count = 0           ← 0
core_expires      = epoch 0

bn.load("C:\\Windows\\System32\\notepad.exe")
  → OSError: [WinError -529697949] Windows Error 0xe06d7363   （C++ 异常）
```

### 根因

仓库里的 `license.txt`（`Dockerfile:219` 会 `COPY` 成镜像里的 `/root/.binaryninja/license.dat`）：

```json
{
  "serial": "0fe0e1fe9acbc4670fa5f0905be71890",
  "created": "2024-09-24T06:10:02+00:00",
  "expires": "2026-09-24T06:10:02+00:00",     ← 已过期 6 周
  "data": "<加密载荷>",
  "signature": "<签名>"
}

宿主机的 `%APPDATA%\Binary Ninja\license.dat` 是**同一个 serial、同一份加密载荷与签名**，
只是 JSON 里的 `expires` 字段被改成了 `2027-09-24`。但 BN 校验的是**签名载荷里的真实到期日**，
所以两个文件都被拒绝（`core_set_license` 静默失败：不抛错，只是 `license_count` 不变，
随后创建 BinaryView 失败）。

> 结论：**BinaryNinja 许可已于 2026-09-24 到期，需要续期。**

### 影响面（比 W1 本身重要）

**生产容器里的 BN 用的是同一份过期许可**，所以：

* `engine/app.py:666` 的 `ext.extract_de_only()` 必然抛异常；
* 该异常被 `de_status = "failed: ..."` 吞掉（`engine/app.py:668-669`）——**服务不报错**；
* D/E 视角缺失 → 回落 EMBER 切片或直接标记视角缺席；
* 最终 **10 个模型静默不参与推理**：OpcodeLSTM、OpcodeTransformer、OpcodeStatNet、
  AsmEmbedNet、MalGraph、CFGGAT、CFGGCN、CFGDGCNN、CallGraphGNN、GraphStatNet。

集成权重里最重的一块在生产上并没有生效，而 API 看起来一切正常。**这是 P0。**

### 补救步骤

1. 续期 BinaryNinja 许可，把新的 `license.dat` 放到
   `%APPDATA%\Binary Ninja\license.dat`（Windows）或替换仓库里的 `license.txt`（容器用）。
2. 重新构建镜像（`Dockerfile:219` 会把 `license.txt` COPY 进去）。
3. 用下面这条命令验证 BN 是否真的活了（**不要只看 `core_license_count`**，它会骗人）：

```bash
python tests/baseline_fixture.py capture --samples tests/fixtures/bn_baseline/samples.json \
    --out /tmp/x.json --require-de
```

4. 许可修好后**重新采集**，把 D/E 的 9 个特征补进 fixture：

```bash
"C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" tests/baseline_fixture.py capture \
    --samples tests/fixtures/bn_baseline/samples.json \
    --out    tests/fixtures/bn_baseline/manifest.json \
    --require-de
```

5. 顺手把 `start_codefender.sh` 的许可激活加上**结果校验**（现在只 print，不检查是否生效）：

```bash
python3 -c "
import binaryninja as bn, os
lic = os.path.expanduser('~/.binaryninja/license.dat')
if os.path.exists(lic):
    bn.core_set_license(open(lic).read())
    if bn.core_license_count() == 0:
        print('[startup] WARNING: BinaryNinja 许可未生效，D/E 视角将缺失')
"
```

## 与 SMDA 迁移的关系

* Phase 0（SMDA PoC）**不受影响** —— 不需要 BN。
* Phase 1（IR 抽象）**需要** BN 后端基准 → 建议先解许可，再做 Phase 1 的回归对照。
* Phase 2 之后 SMDA 后端接管，BN 只作为对照 —— 但对照本身仍需 BN 可用。

## 跑测试

```bash
python tests/baseline_fixture.py verify \
    --samples tests/fixtures/bn_baseline/samples.json \
    --manifest tests/fixtures/bn_baseline/manifest.json
```

退出码 0 = 特征逐位不变；1 = 有差异（Phase 1 验收不通过）。
