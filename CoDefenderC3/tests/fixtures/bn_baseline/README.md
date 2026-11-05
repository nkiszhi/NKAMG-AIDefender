# BN 基线特征快照（golden fixture）

> 采集日期：2026-11-05　|　采集环境：BN 5.2.8722 / Python 3.10.10 / numpy 1.26.4 / Windows

## 这是什么

Phase 1（IR 抽象）会重构「BinaryNinja → 特征」这条链路。重构后必须能证明
**在仍然是 BN 后端时，特征逐位不变** —— 否则分不清是「重构引入的 bug」还是
「后端换了导致的分布漂移」。本目录就是那个判据。

| 文件 | 内容 |
|---|---|
| `samples.json` | 88 个样本的清单 + 元数据（sha256 / 位数 / 节数 / 导入数 / 熵 / 疑似加壳） |
| `manifest.json` | 每个样本每个特征的**指纹**（sha256 of 原始字节 + 维度 + dtype + 统计量） |

全量特征数组（每个样本约 10 MB）**不入库**，需要时用 `--arrays` 导到仓库外。

## 样本构成

确定性分层选取（标签 × 位数），选样规则写在 `tests/baseline_fixture.py` 的 `select` 子命令里：

| 层 | 数量 |
|---|---|
| benign / 32 位 | 25 |
| benign / 64 位 | 25 |
| malicious / 32 位 | 25 |
| malicious / 64 位 | 13（该层候选只有 13 个） |
| **合计** | **88**（其中 53 个带「疑似加壳」启发式标记） |

样本来自 `E:\nkproject\` 下的恶意/白样本库与测试集。**`samples.json` 里存的是绝对路径**，
换机器要改路径（或重跑 `select`）。

## 当前覆盖范围 ⚠️

| 特征组 | 状态 |
|---|---|
| A01-A08、B01-B07、C01-C04、F01-F04、G01-G04、H01-H03（**30 项**） | ✅ 已采集并验证可复现 |
| D01-D07、E01-E04（**9 项**，需 BinaryNinja） | ❌ **未采集 —— BN 许可已过期** |

D/E 缺失的原因：BinaryNinja 许可的签名载荷到期日为 **2026-09-24**（已过期 6 周），
BN 无法创建 BinaryView，于是 `extract_de_only()` 抛异常。
仓库里的 `license.txt`（`Dockerfile:219` COPY 进镜像的那份）用的是同一个已过期的载荷。

> 这不是 fixture 的问题，而是**生产问题**：容器里 `include_de=true`（默认）时，
> D/E 视角取不到 → V6_*/V7_graph 的 **10 个模型静默不参与推理**（API 不报错）。
> 详见 `docs/BASELINE_FIXTURE.md` 的「许可阻塞」一节。

## 怎么用

```bash
# 校验（回归门禁）：重跑一遍并与 manifest 逐位比对
python tests/baseline_fixture.py verify \
    --samples tests/fixtures/bn_baseline/samples.json \
    --manifest tests/fixtures/bn_baseline/manifest.json

# 重新采集（BN 许可修好后，带 --require-de 可作 CI 门禁）
"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests/baseline_fixture.py capture \
    --samples tests/fixtures/bn_baseline/samples.json \
    --out    tests/fixtures/bn_baseline/manifest.json \
    --require-de
```

## 环境说明

* BN 自带的 python（`bnpython3.exe`）**没有 numpy / pefile** —— 工具会用 `--pkgs` 指定的目录补齐
  （本机是 `D:\VM_Share\CoDefenderC3_v9\_tools\py310_pkgs`，**不入库**，需自行准备）。
* 采集与校验必须在**同一环境**下做：numpy 版本的浮点实现差异会让 `sum` 等统计量末位不同，
  但 sha256 指纹是逐位判据，不受影响。
* `manifest.json` 里记了采集时的完整环境（`env` 段），verify 会打印本次环境供对照。
