# 特征哈希稳定性（W0）

> 2026-11-05 落地。**这是 SMDA 迁移前必须先做的第一件事**。

## 一句话

项目原先有 13 处用 Python 内置 `hash()` 做 feature hashing，而内置 `hash(str)` **每个进程都不一样**，
导致训练（子进程）与推理（主进程）对同一个 PE 算出**不同的特征向量**。现已全部改为 
`zlib.crc32` 的纯函数哈希。

## 问题

CPython 3.3+ 起 `str.__hash__` 默认使用 SipHash-1-3，**每个进程启动时随机生成一个 secret**
（来自 `PYTHONHASHSEED`，未设置则随机）。设计目的是防哈希表 DoS，但代价是：

| |
|---|
| 同一进程内 | `hash(s)` 稳定 |
| 不同进程 | `hash(s)` 是**完全另一套映射** |

### 错位是怎么发生的

| 环节 | 进程 | 代码 |
|---|---|---|
| 训练抽 A/B/C/F/G/H | 子进程（4~16 个 worker） | `train/data_loader.py` → `ext.extract_fast()` |
| 训练抽 D/E | 子进程 | `feature_extraction/_de_worker_persistent.py` |
| 推理抽 A/B/C/F/G/H | 主进程 | `engine/app.py:659` → `ext.extract_fast()` |
| 推理抽 D/E | 主进程 | `engine/app.py:666` → `ext.extract_de_only()` |

两边都调用**同一个函数**，但在不同进程里 → 桶号不同 → 特征语义错位。

实测（同一份模拟样本，两个进程各算一遍）：

| 特征 | 内置 hash() | 改用 crc32 |
|---|---|---|
| A06 导入分桶 | cos = 0.0000 | cos = 1.0000 |
| C01 字符串 | cos = 0.9169 | cos = 1.0000 |
| C04 字符串 n-gram | cos = 0.1160 | cos = 1.0000 |
| D01 opcode 序列 | cos = 0.3835 | cos = 1.0000 |
| D02 opcode bigram | cos = 0.0000 | cos = 1.0000 |
| D03 opcode trigram | cos = 0.0000 | cos = 1.0000 |
| D07 函数嵌入 | cos = 0.1000 | cos = 1.0000 |

`D02`/`D03` 余弦恰好为 0 —— 两个进程算出的 n-gram 桶**一位都不重叠**。

### 训练集自身也不自洽

- `data_loader.py` 起 4~16 个 worker，每个 worker 一个独立 seed；
- 分多轮抽取（first_round / stage2），每轮 seed 又不同；
- 于是**同一个文件在同一个数据集里对应多个互相矛盾的特征向量**。

模型学到的是一堆随机映射的统计平均 ≈ 噪声。

## 改动

| 文件 | 改动 |
|---|---|
| **新增** `feature_extraction/_stable_hash.py` | `stable_hash()` / `stable_bucket()` / `stable_seed()`，基于 `zlib.crc32` |
| `feature_extraction/extract_feature.py` | 10 处 hash → stable_hash；抽出 `_string_features()` 统一 C01-C04 口径 |
| `feature_extraction/unified.py` | 3 处 hash → stable_hash / stable_seed |
| `Dockerfile` | `ENV PYTHONHASHSEED=0`（第 0 段 + 第 6 段）——**兜底**，防将来有人再引入内置 hash() |
| **新增** `tests/test_stable_hash.py` | 11 项守门测试（跨进程一致性 / 端到端特征比对 / AST 静态检查） |
| `feature_extraction/_de_worker_persistent.py` | 去掉硬编码 v8 路径 → 改为按 `__file__` 定位（原来在 v9 里加载的是 **v8 的代码**） |
| `train/_drain_bndb_to_de.py`、`train/_probe_link_place.py` | 同上，去掉硬编码 v8 路径 |

### 为什么 `extract_feature.py` 的导入写成三级兜底

`train/data_loader.py::_extract_fast_chunk` 用 importlib **按文件路径**加载 `extract_feature.py`
（module name = `"extract_feature"`，不属于任何包），此时 `feature_extraction/` **不在** sys.path 上。
因此导入必须三级兜底：

1. `from ._stable_hash import ...` —— 包内导入（`feature_extraction.extract_feature`）
2. `from _stable_hash import ...` —— 同目录在 sys.path 上
3. 按 `__file__` 用 importlib 直接加载 —— 不依赖 sys.path

测试 `test_data_loader_style_import_works` 专门守住第 3 级。

### C01-C04 口径统一

此前 `_extract_strings_fast`（纯 regex，生产路径）与 `_extract_strings`（BinaryNinja 全量路径）
两套实现口径不一致：

| | fast 版（生产） | BN 版 |
|---|---|---|
| C02[4] | URL 字符串「个数」 | 含大写字母字符串「比例」 |
| C01 归一化 | `/= max` | `log1p` 后 `/= max` |
| 字符串截断 | 2000 条 | 不截断 |

现统一到 `_string_features()`：截断 5000 / C01 取 2000 / C04 取 200，
C02[4] = URL 字符串**个数**，C01/C04 统一 `log1p` → 归一化。

> 注：推理与训练当前都走 `extract_fast`（`engine/app.py:659`），BN 版 `_extract_strings`
> 仅用于 `extract()` 全量路径（离线/调试）。统一是为了 Phase 1 的 IR 改造把两条路径合并时不咬人。

## ⚠️ 必须重训

**换了 hash 函数 = 受影响特征的语义全部改变。**以下视角组的模型权重**作废，必须重训**：

| 特征 | 视角组 | 模型 |
|---|---|---|
| A06 | V4_import | DrebinImport, ALOHANet, EmberGBDT_Import |
| C01 / C04 | V5_string | RaffFeatureNet, DrebinString |
| D01 | V6_opcode_seq | OpcodeLSTM, OpcodeTransformer |
| D02 / D03 | V6_opcode_stat | OpcodeStatNet |
| D07 | V6_func_embed | AsmEmbedNet |
| unified opcode_seq / func_embed | V6_opcode_seq / V6_func_embed | 同上 |

不受影响（纯字节 / 结构 / 图，不经 hash）：V1_byte、V2_byte_stat、V3_pe_struct、V7_graph。

> 顺带：C02[4] 的口径也变了（C01 也多了 log1p），V5_string 同样要重训。

重训是**必然**的 —— 旧权重本来就是在随机映射上训出来的，从来就没有"正确"过。

## 跑测试

```bash
python tests/test_stable_hash.py          # 无需 pytest
pytest tests/test_stable_hash.py -v       # 有 pytest
```

11 项测试，含：

- 跨进程桶号一致性（**核心回归**）
- 端到端：训练子进程与推理主进程算出的 C01-C04 **逐位一致**
- canary：证明内置 `hash()` 确实是每进程随机的
- AST 静态守门：`feature_extraction/` 下不允许再出现裸用内置 `hash()`
- D01 的 opcode → ID 映射跨进程一致
- 复刻 `data_loader.py` 的加载方式，验证三级导入兜底有效

## 为什么排在 SMDA 迁移之前

1. **归因**：先修 hash 得到一个干净的 BN 基线，再叠 SMDA，差值才可解释；
2. **省一轮训练**：hash 变更与 SMDA 迁移都要求重训，合并成一次做；
3. **基线 fixture 的前提**："特征逐位不变"的回归测试在 hash 随机时根本测不出来。
