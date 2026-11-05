# BN 基线特征快照（golden fixture）—— W1

> 2026-11-05 落地。SMDA 迁移 Phase 1（IR 抽象）的**验收基准**。

## 为什么需要

Phase 1 要把「BinaryNinja → 特征」这条链路重构一遍（引入 `ProgramIR` + `backend_bn.py`）。
重构完成后必须能回答：**在仍然是 BN 后端的前提下，特征有没有变？**

没有这个基准，Phase 7 的指标对比就分不清三件事混在一起：

1. IR 重构引入的 bug
2. hash 修复（W0）带来的语义变化 —— 本来就该变
3. 后端从 BN 换成 SMDA 带来的分布漂移 —— 也本来该变

## 🔑 核心结论：两级门禁，锚点不同

这是本次 W1 最重要的产出。**「PE → BN 分析」这一步是不确定的**，
所以 D/E 特征不能拿 PE 当锚点：

| 环节 | 确定性 | 实测 |
|---|---|---|
| PE → BN 实时分析 | ❌ **不确定** | 同批 88 样本两次采集，25/88 的样本 D/E 指纹不同（124 个特征），且差异集中在**耗时较长的样本**上 |
| 固定 .bndb → 抽特征 | ✅ **确定** | 32 个 bndb × 9 特征，两次采集 **288/288 逐位一致** |
| fast 路径（纯 Python + numpy + pefile） | ✅ **确定** | 88 样本 × 30 特征，两次采集 **2640/2640 逐位一致**；且**跨 numpy 版本**（1.26.4 / 2.3.5）也一致 |

BN 不确定的原因：多线程分析（`bn.set_worker_thread_count(8)`）、函数发现顺序、
机器负载 —— 同样的 PE，分析结果会随时间变化。

> 这也解释了训练管线为什么要先做 `PE → .bndb` 缓存再抽特征：**bndb 就是那个确定性的锚点**。

### 所以门禁分两级

| 门禁 | 锚点 | 覆盖 | 命令 |
|---|---|---|---|
| **G1** | PE | fast 路径 30 个特征（A/B/C/F/G/H） | `verify --fast-only` |
| **G2** | **.bndb** | D/E 路径 9 个特征（D01-D07 / E03-E04） | `verify-bndb` |

Phase 1 改造的正是「BN 输出 → 特征」这一段，**G2 才是它的主判据**；G1 覆盖 fast 路径，
顺带守住 PE 解析相关的改动。

## 产物

| 位置 | 内容 |
|---|---|
| `tests/fixtures/bn_baseline/samples.json` | 88 个样本的清单 + 元数据（41 KB） |
| `tests/fixtures/bn_baseline/manifest.json` | fast 路径 2640 个特征指纹（PE 锚定） |
| `tests/fixtures/bn_baseline/bndb_manifest.json` | D/E 路径 288 个特征指纹（bndb 锚定） |
| `tests/fixtures/bn_baseline/README.md` | 目录说明 |
| `tests/baseline_fixture.py` | 采集 / 校验工具（5 个子命令） |

全量特征数组不入库（单样本约 10 MB × 88 = 900 MB）。
需要具体数值时用 `--arrays <目录>` 导到仓库外。

## 指纹的判据

每个特征向量算 `sha256(ascontiguousarray(arr).tobytes())`。

* **sha256 相同 = 逐位相同** —— 硬判据；
* 维度 / dtype / `sum` / `nz` 是辅助信息，用于人眼快速定位差异；
* `sum` 在不同 numpy 版本下末位可能不同（浮点实现差异），**不作为判据**。

## ⚠️ 用 BN 采集必须满足的两个前置条件

都不是「许可过期」—— 许可本身是好的（已续期，expires=2027-09-24）。

### 条件一：BN 的许可校验需要联网

断网时表现为：

```
core_serial = ''
core_license_count = 0
bn.load("C:\\Windows\\System32\\notepad.exe")
  → OSError: [WinError -529697949] Windows Error 0xe06d7363   （C++ 异常）
```

——和「许可过期」的表现**一模一样**。容器里有网，生产不受影响；
但在断网环境（本机沙箱）里跑采集会全线失败。

> 另：`bn.core_license_count()` 在许可有效时也可能是 0，**不能作为判据**。
> 唯一可信的是「能不能真的开出一个 view」—— 工具里的 `_bn_functional_probe` 就是干这个的。

### 条件二：BN 打不开路径含非 ASCII 字符的文件

**同一个样本，两种路径：**

```
ASCII  D:\...\sample_000028670db2.exe                       -> OK, 280 个函数
中文   E:\nkproject\00 样本库\01 白样本\...\000028670db2...  -> FAIL: Unable to create new BinaryView
```

工具已内置规避：`_ascii_path()` 会把非 ASCII 路径的样本镜像到 ASCII 临时目录再分析。

#### 影响面

| 场景 | 是否受影响 | 说明 |
|---|---|---|
| 推理 API（/predict-single 等上传接口） | ❌ 不受影响 | 落盘走 tempfile.mkstemp() → ASCII 临时路径 |
| 推理目录扫描（/predict-directory） | ⚠ **受影响** | 直接就地分析；目录名含中文就整批拿不到 D/E |
| 训练 / 数据集构建 | ⚠ **受影响** | 样本在 E:\nkproject\00 样本库\...（中文路径） |

> 训练侧这条很可能就是历史 `bndb_fail.log` 里大量「永久失败」记录的真正原因，
> 也是 `train/README.md` 里「D/E 覆盖率 98~99%，重跑却毫无进展」这类问题的根因之一。
> **建议：把训练数据集放到纯 ASCII 路径**（如 `D:\VM_Share\datasets\...`）。

## 怎么用

```bash
# G1：fast 路径门禁（不需要 BN，秒级）
python tests/baseline_fixture.py verify --fast-only \
    --samples tests/fixtures/bn_baseline/samples.json \
    --manifest tests/fixtures/bn_baseline/manifest.json

# G2：D/E 路径门禁（需要 BN + 联网）
"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests/baseline_fixture.py verify-bndb \
    --manifest tests/fixtures/bn_baseline/bndb_manifest.json

# 重新采集
python tests/baseline_fixture.py capture --fast-only \
    --samples tests/fixtures/bn_baseline/samples.json \
    --out    tests/fixtures/bn_baseline/manifest.json

"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests/baseline_fixture.py bndb \
    --dir "<含 .bndb 的目录>" \
    --out tests/fixtures/bn_baseline/bndb_manifest.json
```

退出码 0 = 逐位不变；1 = 有差异（Phase 1 验收不通过）。

## 环境说明

* BN 自带的 python（bnpython3.exe，3.10）**没有 numpy / pefile** ——
  工具用 `--pkgs` / `CODEFENDER_PY310_PKGS` 指定的目录补齐
  （本机是 `D:\VM_Share\CoDefenderC3_v9\_tools\py310_pkgs`，**不入库**，需自行准备：
  `pip download numpy==1.26.4 --python-version 310 --implementation cp --abi cp310 --platform win_amd64`）。
* G1 门禁**不需要 BN**，普通 python + numpy + pefile 即可（G1 基线就是在 python 3.12 / numpy 2.3.5 下采的）。
* `manifest.json` 的 `env` 段记了采集时的完整环境，verify 会打印本次环境供对照。
