# BN 基线特征快照（golden fixture）

> 采集日期：2026-11-05　|　G1 用 python 3.12 / numpy 2.3.5，G2 用 BN 5.2.8722 / python 3.10 / numpy 1.26.4

## 这是什么

Phase 1（IR 抽象）会重构「BinaryNinja → 特征」这条链路。重构后必须能证明
**在仍然是 BN 后端时，特征逐位不变** —— 否则分不清是「重构引入的 bug」还是
「后端换了导致的分布漂移」。本目录就是那个判据。

| 文件 | 内容 |
|---|---|
| `samples.json` | 88 个样本的清单 + 元数据（sha256 / 位数 / 节数 / 导入数 / 熵 / 疑似加壳） |
| `manifest.json` | **G1**：fast 路径 30 个特征 × 88 样本 = 2640 个指纹（PE 锚定） |
| `bndb_manifest.json` | **G2**：D/E 路径 9 个特征 × 32 个 bndb = 288 个指纹（bndb 锚定） |

全量特征数组（每个样本约 10 MB）**不入库**，需要时用 `--arrays` 导到仓库外。

## 🔑 为什么分两级

**「PE → BN 实时分析」这一步是不确定的**（多线程分析、函数发现顺序、机器负载）：
同一批 88 个样本两次采集，25 个样本的 D/E 指纹不同。

而「固定 .bndb → 抽特征」是**确定**的（288/288 逐位一致）。
bndb 也正是训练管线的真实中间产物（PE → bndb 缓存 → 从 bndb 抽特征）。

| 门禁 | 锚点 | 覆盖 | 命令 |
|---|---|---|---|
| G1 | PE | fast 路径 30 个特征 | `verify --fast-only` |
| G2 | .bndb | D/E 路径 9 个特征 | `verify-bndb` |

## 样本构成

确定性分层选取（标签 × 位数），选样规则在 `tests/baseline_fixture.py` 的 `select` 子命令里：

| 层 | 数量 |
|---|---|
| benign / 32 位 | 25 |
| benign / 64 位 | 25 |
| malicious / 32 位 | 25 |
| malicious / 64 位 | 13（该层候选只有 13 个） |
| **合计** | **88**（其中 53 个带「疑似加壳」启发式标记） |

样本来自 `E:\nkproject\` 下的恶意/白样本库与测试集。**`samples.json` 里存的是绝对路径**，
换机器要改路径（或重跑 `select`）。

> ⚠ 样本路径含中文 → **BinaryNinja 打不开**（详见 `docs/BASELINE_FIXTURE.md`）。
> 工具已内置规避：分析前把非 ASCII 路径镜像到 ASCII 临时目录。

## 怎么用

```bash
# G1（不需要 BN，秒级）
python tests/baseline_fixture.py verify --fast-only \
    --samples tests/fixtures/bn_baseline/samples.json \
    --manifest tests/fixtures/bn_baseline/manifest.json

# G2（需要 BN + 联网）
"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests/baseline_fixture.py verify-bndb \
    --manifest tests/fixtures/bn_baseline/bndb_manifest.json
```

## 环境说明

* BN 自带的 python（bnpython3.exe）**没有 numpy / pefile** —— 工具会用 `--pkgs` 指定的目录补齐
  （本机是 `D:\VM_Share\CoDefenderC3_v9\_tools\py310_pkgs`，**不入库**，需自行准备）。
* **BN 的许可校验需要联网**，断网时表现为「Unable to create new BinaryView」，
  和「许可过期」一模一样 —— 别误判。
* `bn.core_license_count()` 不可信（许可有效时也可能是 0）；唯一可信的判据是
  「能否真的开出一个 view」。
* `manifest.json` 里记了采集时的完整环境（`env` 段），verify 会打印本次环境供对照。
