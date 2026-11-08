# ProgramIR 契约 —— SMDA 迁移 Phase 1 的设计基线

> 2026-11-05　|　配套代码：[`feature_extraction/ir.py`](../feature_extraction/ir.py)

## 0. 一句话

把「反汇编后端」和「特征计算」之间插入一层**后端中立、可缓存、顺序敏感**的中间表示：

```
    PE ──[后端: BN / SMDA]──> ProgramIR ──[特征层]──> D01-D07 / E03-E04
```

这样：后端可替换（BN → SMDA 不用动特征层）、缓存中立（不再依赖 BN 私有格式）、
口径可审计（每个特征用哪些 IR 字段一目了然）。

## 1. 设计目标

| 目标 | 说明 |
|---|---|
| 后端可替换 | BN 与 SMDA 产出同构 IR；特征层代码**一份** |
| 缓存中立 | IR 像现在的 .bndb 一样缓存，但格式与后端无关 |
| 隔离不确定性 | 后端的不确定性被关在「生成一次 IR」里；**IR → 特征是纯函数** |
| 口径可审计 | 特征 ↔ IR 字段映射表（本文件第 4 节）完整可查 |
| 逐位可回归 | Phase 1 改造后特征必须逐位不变（用 G2 门禁验收） |

### 为什么第 3 条最重要

W1 实测：**「PE → BN 实时分析」这一步不确定**（同批样本两次采集，25/88 的 D/E 指纹不同），
而「固定 .bndb → 抽特征」确定（288/288 一致）。

IR 把这个结构**显式化**了：

```
PE ──[后端，不确定]──> IR ──[纯函数，确定]──> 特征
```

好处：换特征算法、重训、改后端，都可以只重跑「IR → 特征」这段（秒级），
不必重跑昂贵的反汇编。训练管线的 .bndb 缓存本来就是这个思路，
IR 只是把缓存格式从「BN 私有」换成「跨后端中立」。

## 2. 数据类（完整定义见 `feature_extraction/ir.py`）

```python
@dataclass(frozen=True)
class BasicBlock:
    start: int                       # 块起始地址（身份标识）
    length: Optional[int]            # 字节长度；后端拿不到 → None
    instructions: Tuple[str, ...]    # 助记符序列（非空、已小写）
    successors: Tuple[int, ...]      # 后继块起始地址

@dataclass(frozen=True)
class Function:
    start: int                       # 函数起始地址（身份标识）
    size: int                        # 字节数
    blocks: Tuple[BasicBlock, ...]   # 有序
    callees: Tuple[int, ...]         # 被调函数起始地址（**保留重复**）
    callees_known: bool = True       # 后端是否成功取到 callees（见 I7）

@dataclass(frozen=True)
class ProgramIR:
    functions: Tuple[Function, ...]  # 有序
    imports: Tuple[str, ...]         # 导入符号全名
    arch: str
    bitness: int                     # 32 / 64
    backend: str                     # "bn" / "smda"
    backend_version: str
    schema_version: str = "codefender-ir/1"
```

辅助方法：`mnemonic_stream()`（展平全部助记符 = 现有的 `all_opcodes`）、
`block_stream()`、`function_map()`（按地址回查，调用深度用）、`validate()`（结构校验）、
`to_dict()/from_dict()/to_json()/save()/load()`（规范化序列化）。

### 2.1 设计不变量（**硬约束，破坏即改变特征**）

| # | 不变量 | 为什么 |
|---|---|---|
| I1 | **顺序即语义**：functions / blocks / instructions / callees 全是有序列表，顺序 = 后端遍历顺序 | D01（opcode 序列）、D02/D03（n-gram）直接依赖顺序；用 set/dict 去重会改变特征 |
| I2 | **callees 保留重复** | 现有代码 `cg_edges += 1` 按重数计调用边；两次调用同一被调方 = 2 条边 |
| I3 | **助记符非空且小写**（.strip().lower()） | 等价于现有代码的 `if m:` 过滤 + `_parse_mnemonic` 的规范化 |
| I4 | **地址用 int**，一切身份比较用起始地址 | 与现有代码一致（func.start / bb.start / edge.target.start） |
| I5 | **不可变**（frozen + tuple） | 可哈希、可安全缓存、可做等值比对 |
| I6 | **successors 原样透传**（不排序、不去重） | E03 回边判定依赖 `target.start <= bb.start` 的地址序 |
| I7 | **callees 未知 ≠ callees 为空** | 原代码在 `func.callees` 抛异常时：n_callees=0，但 is_leaf/is_recursive 保持 False；而 E04 的叶子计数用的是「len(callees)==0」，出错时**也算叶子**。两处语义不同 → 用 `callees_known` 区分 |

## 3. BN API 表面 → IR 字段（**完备性证明**）

现有代码用到的每一个 BN API，都在下表里有落点 —— 这是「IR 够不够用」的判据。

| BN API | 现有用途 | IR 字段 |
|---|---|---|
| `bv.functions` | 函数集合与**顺序** | `ProgramIR.functions`（顺序保留） |
| `func.start` | 函数身份 | `Function.start` |
| `func.total_bytes` / `func.highest_address - func.start` | 函数大小 | `Function.size` |
| `func.basic_blocks` | 基本块集合与**顺序** | `Function.blocks`（顺序保留） |
| `func.callees` | 被调函数（**含重复**）、自递归判定 | `Function.callees` |
| `block.start` | 块身份、回边判定基准 | `BasicBlock.start` |
| `block.length` | 块字节数（D06） | `BasicBlock.length` |
| `block.outgoing_edges` → `edge.target.start` | CFG 边（D06/E03）、回边 | `BasicBlock.successors` |
| `block.disassembly_text`（或迭代块）→ `tokens[0].text` | 助记符（D01-D04/D07） | `BasicBlock.instructions` |
| `bv.get_symbols_of_type(ImportedFunctionSymbol)` → `sym.full_name` | 导入表（A06 的 BN 变体） | `ProgramIR.imports` |
| `bv.strings` | 字符串（仅 BN 版 C01-C04 用） | **不进 IR** —— C 特征由 fast 路径（PE 字节）负责 |

> `bv.strings` 不进 IR 是刻意的：C01-C04 已经在 fast 路径（pefile/regex）里算好，
> 把字符串塞进 IR 只会让缓存变大；且两套 C 特征口径本来就该统一（见 W0）。

### 后端适配器必须遵守的两条

1. **过滤空助记符**：现有代码 `if m:` 才计数 —— 适配器在生成 IR 时就丢掉空串；
2. **callees 用地址且保留重复**：不能去重、不能排序。

## 4. feature ID → IR 字段映射表

| 特征 | 维度 | 计算式 | IR 来源 |
|---|---|---|---|
| **D01** | 4096 | `stable_hash(op) % 511 + 1` 逐位 | `mnemonic_stream()` |
| **D02** | 256 | 相邻二元组计数 → log1p → L2 | 同上（相邻对） |
| **D03** | 256 | 相邻三元组计数 → log1p → L2 | 同上（相邻三元组） |
| **D04** | 15 | 指令类别占比（`_CAT_LOOKUP`） | 同上；**类别字典属特征层，不进 IR** |
| **D05** | 12 | 函数统计 | `n_functions`、`Function.size`、`n_blocks`、`n_callees`、`is_leaf`、`is_recursive`、`n_instructions`、去重助记符数 |
| **D06** | 10 | 基本块统计 | `BasicBlock.length`、`len(successors)` |
| **D07** | 48×128 | 每函数助记符 Counter → `stable_hash % 128` → L2 | `Function.blocks[*].instructions` |
| **E03** | 12 | CFG 统计 | 块数、边数（successors 长度）、回边数（successor <= 本块 start）、每函数块数 |
| **E04** | 10 | 调用图统计 | `Function.callees`（含重复）、调用深度（每层最多前 5 个 callee、最深 10 层、按地址回查） |
| **A06** | 256 | 导入名分桶 | `ProgramIR.imports`（BN 变体；fast 路径另有 pefile 版本，两套口径需统一） |

**不属于 IR 的特征**（fast 路径，纯 Python + PE 字节，Phase 1 不动）：

A01-A05、A07、A08_A15、B01-B07、C01-C04、F01-F04、G01-G04、H01-H03。

## 5. 序列化格式（v1）

canonical JSON（sort_keys=True），助记符表压缩：

```json
{
  "schema": "codefender-ir/1",
  "backend": "bn",
  "backend_version": "5.2.8722",
  "arch": "x86_64",
  "bitness": 64,
  "mnemonics": ["mov", "push", "call", "..."],
  "imports": ["kernel32.dll.CreateFileW", "..."],
  "functions": [
    { "start": 4198400, "size": 128, "callees": [4198512, 4198512],
      "blocks": [ { "start": 4198400, "length": 64, "succ": [4198464],
                    "ins": [0, 1, 0, 2] } ] } ]
}
```

* `ins` 是 `mnemonics` 表的下标；
* `callees` 里出现两次同一个地址 = 两条调用边（I2）；
* 默认 .json，需要压缩时用 .json.gz（`ProgramIR.save()` 自动处理）。

## 6. Phase 1 的实施顺序

| 步 | 内容 | 状态 | 验收 |
|---|---|---|---|
| 1 | `ir.py`（数据类 + 序列化 + 校验） | ✅ 完成 | `tests/test_ir_contract.py` 17/17 |
| 2 | `backend_bn.py`：`bv → ProgramIR` | ✅ 完成 | 内含 mock 适配器规范（测试里） |
| 3 | `backend_smda.py`：SMDA → IR | ⬜ Phase 2 | 与 BN 的 IR 做字段级对比 |
| 4 | `features_from_ir.py`：IR → D/E 特征 | ✅ 完成 | **逐位等价已验证（见下）** |
| 5 | 训练管线接 IR 缓存，替掉 .bndb | ✅ 已实现（开关式，默认关闭） | `CODEFENDER_DE_CACHE=ir` 开启；见第 7 节 |

### ✅ 第 2+4 步的验收结果（2026-11-06）

在 32 个 `.bndb` 上跑 `tests/verify_ir_equivalence.py`：

```
bndb ──[现有代码]─────────────> 特征
bndb ──[backend_bn]→ IR ──[features_from_ir]──> 特征

共比对 288 个特征（D01-D07 / E03 / E04 × 32 个 bndb）
→ 0 个差异 → 结论：OK —— IR 路径与原路径逐位一致
```

样本覆盖度不错：函数数从 0（BN 没分析出来的加壳/损坏样本）到 9247，指令数 0~1773。

### 💾 缓存体积实测（IR 的意外收益）

| 缓存 | 平均 | 最大 | 6k 样本估算 |
|---|---|---|---|
| `.bndb`（现状，BN 私有格式） | 6.0 MB | 36.9 MB | **35 GB** |
| IR `.json` | 908 KB | 13.2 MB | 5.3 GB |
| IR `.json.gz` | **105 KB** | 1.4 MB | **0.60 GB** |

→ **IR 缓存比 .bndb 小 58 倍**。训练管线的磁盘压力会大幅下降，
而且重抽特征不再需要 BN 许可（IR 是后端中立的）。

### 第 4 步的验收方式（关键）

用 **G2 门禁**（bndb 锚定）：

```
bndb ──[backend_bn]──> IR ──[特征层]──> 特征      ← 与「bndb ──[旧特征代码]──> 特征」逐位比对
```

中间多了一层 IR，但**两边的特征必须完全一致** —— 这就是 Phase 1 的硬判据。
（G2 门禁已经就位：`python tests/baseline_fixture.py verify-bndb`）

## 7. 明确不做的事（非目标）

* **不引入 SMDA** —— 那是 Phase 2；Phase 1 只做 IR 抽象。
* **不改特征语义** —— 逐位不变是硬约束；任何「顺便优化一下」都要另开 PR。
* **不动 fast 路径** —— A/B/C/F/G/H 不经过 IR。
* **不做完整反汇编** —— IR 只保留特征需要的助记符序列，不存操作数/寄存器/字节码。
  否则 IR 会长成「另一个 IDA」，缓存体积和实现成本都会失控。
* **不在 IR 里放后端特有的东西** —— 例如 BN 的 SymbolType、SMDA 的指令 id。
  后端特有信息只能出现在 `backend` / `backend_version` 字段里。

## 7. 第 5 步落地情况（2026-11-06）

### 7.1 接线方式

| 组件 | 说明 |
|---|---|
| `feature_extraction/ir_cache.py` | `generate_irs_batch()` / `extract_de_from_ir_batch()`，语义与 bndb 版一一对应 |
| `feature_extraction/_ir_worker.py` | PE → IR 的批量子进程（与 `_bndb_worker.py` 同构） |
| `feature_extraction/_ir_de_worker.py` | IR → D/E 特征 → npz 的持久化 worker（不加载 BN） |
| `train/data_loader.py` | 新增 `CODEFENDER_DE_CACHE` 开关：`bndb`（默认）/ `ir` |

**默认仍是 `bndb`** —— 生产行为零改变。要切换：

```bash
export CODEFENDER_DE_CACHE=ir
```

切过去之后：

* D/E 中间产物从 `.cache/bndb/*.bndb` 变成 `.cache/ir/*.ir.json.gz`；
* 抽特征不再需要 BN（IR 是纯数据）→ BN 许可过期时也能重抽 D/E 特征；
* 中间产物体积小 58 倍（105 KB vs 6.0 MB）；
* 现有数据集的 `.cache/bndb` 不会被自动复用（格式不同），首次切换需重新生成。

### 7.2 两条路径的等价性边界（重要，别误读）

| 比较方式 | 结论 |
|---|---|
| 同一中间产物（同一个 .bndb）→ 抽特征 | ✅ 逐位一致（G2 门禁：32 个 bndb × 9 个特征 = 288/288） |
| 同一个 PE → 各自走两条路径 | ⚠ 不完全一致 |

为什么后者不一致？根因是 **BN 自己的 .bndb 序列化是"有损"的**：

```
PE ─[BN 分析]─> 内存里的 bv          （无损）
  ├─ IR 路径：直接从这个 bv 提取        → 忠实于分析结果
  └─ bndb 路径：create_database → 重开 → 提取   ← 经过 BN 的存盘/读盘往返
```

实测（3 个真实样本，同一次分析下逐特征比对）：

| 样本 | 结果 |
|---|---|
| s0 | ✅ 9 个特征全部一致 |
| s1 | ⏭ 跳过 —— BN 的 create_database() 原生崩溃（0xC0000409） |
| s2 | ⚠ D01 / D02 / D03 / D05 / D07 不一致；D04 / D06 / E03 / E04 一致 |

差异集中在**顺序/结构类**特征（指令序列 D01、n-gram D02/D03、函数统计 D05、
函数嵌入 D07），**统计类**特征（D04 类别分布、D06 块统计、E03 CFG、E04 调用图）不受影响。

> 这不影响切换决策：W0 已经要求这 6 组视角的模型全部重训，
> 所以 D/E 特征本来就会变一次。而且 IR 路径更忠实于 BN 的分析结果
>（没有有损的存盘往返），长期看是改进而非退步。
>
> 但要如实记录：**历史训练数据里的 D/E 特征来自"有损"的 bndb 快照**，
> 新数据来自 IR，两者不可直接混用。

### 7.3 实测中踩到的三个坑（都写进了代码注释）

1. **bnpython3.exe 不支持 python 的 -c**（只接受脚本文件）——
   验证脚本最初用 `sp.run([sys.executable, "-c", code, ...])` 起子进程，
   全部报 `Unknown option -c`。改成落临时脚本文件才通。
2. **同一 PE 的两个 view 不能并存** —— 父进程持有 view 时，子进程再开一个
   会触发 BN 原生崩溃（0xC0000409，无 Python traceback）。
   所以「同一次分析下两条路径对比」必须整体放进一个子进程。
3. **BN 的 create_database() 会偶发原生崩溃** —— 生产管线早就知道
   （`_bndb_worker.py` 的"零连坐"设计），补救轮用 `batch_size=1` 重跑。
   IR 路径不需要 create_database，反而少一个崩溃点。

### 7.4 批量 API 验证

```
generate_irs_batch(批, batch_size=2)   → ok=2 fail=1（BN 原生崩溃）
generate_irs_batch(补救轮, batch=1)    → ok=1 fail=0      → 合计 3/3
extract_de_from_ir_batch                → ok=3 fail=0
  → 三个 npz 都含 10 个特征（D01-D07 + E03 + E04）
```

### 7.5 切换前建议先做的验证

* 在**小数据集**上跑一遍 `CODEFENDER_DE_CACHE=ir`，对比 D/E 覆盖率；
* 确认 `.cache/ir` 的体积符合预期；
* 确认 IR 路径下 MalGraph 的 `features.jsonl` 生成正常（图特征同样走 BN）；
* 再切全量。**BN 许可续期后**，D/E 特征重抽不再需要 BN 许可 —— 这正是
  这次改造最实在的运维收益。

## 8. 风险与开放问题

| 问题 | 影响 | 现状 |
|---|---|---|
| BN 与 SMDA 的**函数发现顺序**不同 | D01/D02/D03 序列类特征会变 | 不可避免；Phase 7 用分布对比量化。IR 至少让「哪里变了」可定位 |
| BN 与 SMDA 的**函数发现数量**不同 | D05/E03/E04 的计数类特征会变 | 同上 |
| SMDA 的**函数识别质量**不足 | E 视角特征弱、MalGraph 掉点 | Phase 0 PoC 必须实测 |
| BN 分析不确定 | 同一 PE 两次分析结果不同 | 已由 W1 量化；IR 缓存把影响关在一次生成里 |
| 32 位样本的函数发现 | 覆盖率低 | Phase 0 单列评估 |
| IR 缓存体积 | 6k 样本要占多少磁盘？ | ✅ 已实测：gz 后平均 105 KB/样本 → 约 0.6 GB（比 .bndb 小 58 倍） |
| IR schema 演进 | 旧缓存失效 | `schema_version` + 重建策略（旧版本直接重算） |

## 9. 相关文档

* [`docs/FEATURE_HASH_STABILITY.md`](FEATURE_HASH_STABILITY.md) —— W0：跨进程 hash 一致性
* [`docs/BASELINE_FIXTURE.md`](BASELINE_FIXTURE.md) —— W1：两级门禁与 BN 的两个前置条件
## 10. Phase 2（SMDA 后端）与跨后端对比

### 10.1 交付物

| 文件 | 内容 |
|---|---|
| `feature_extraction/backend_smda.py` | SMDA → ProgramIR 适配器（与 backend_bn.py 同构） |
| `tests/compare_ir_backends.py` | 跨后端对比工具：bn / smda / compare 三个子命令 |

### 10.2 SMDA 后端的三个关键点

1. 地址基准：SMDA 对原生 PE 给的函数/块偏移**已经是 VA**（不是 RVA）；
   而对 .NET（IL 模式）给的是很小的 IL 偏移。适配器用 addr_mode="auto" 自动判定
   （取所有函数偏移的最小值与 imagebase 比较），避免把 VA 再加一次 base
   （踩过：一度把地址整体抬高了一个 imagebase，导致地址重合率算成 0%）。
2. 强制原生后端：SMDA 会自动识别 .NET 程序集并按 **CIL/IL** 反汇编
   （助记符是 ldarg.0/call/castclass），与 BN 的原生 x86 视角完全不可比。
   适配器默认 backend="intel" 强制走原生后端。
3. 助记符口径：SMDA 的 block.instructions[].mnemonic 直接就是助记符，无需处理。

### 10.3 跨后端对比结果（12 个原生样本，非 .NET）

字段级：

| | BN | SMDA |
|---|---|---|
| 函数数（合计） | 2841 | 2101（少 26%） |
| 指令数 | 与 SMDA 几乎一致（21046/19624、22271/23242、3000/2985、1211/1210） | |
| 函数起始地址重合 | — | **71.6%**（2035/2841） |

特征级（同一特征层喂两份 IR，余弦相似度）：

| 特征 | 平均余弦 | 判读 |
|---|---|---|
| E03 CFG 统计 | **0.927** | 高度一致 |
| D04 指令类别分布 | **0.905** | 高度一致 |
| D05 函数统计 | **0.891** | 高度一致 |
| D06 基本块统计 | **0.888** | 高度一致 |
| D03 opcode trigram | 0.814 | 较一致 |
| D02 opcode bigram | 0.790 | 较一致 |
| E04 调用图统计 | 0.683 | 中等 |
| D01 opcode 序列 | 0.641 | 中等（顺序敏感） |
| D07 每函数嵌入 | 0.562 | 中等偏低（顺序 + 函数划分敏感） |

12/12 样本的每个特征都不逐位相同（预期：后端不同）。

### 10.4 结论

* **SMDA 可以替换 BN**：结构类特征（E03/D04/D05/D06）余弦 0.89~0.93，
  指令序列类 0.56~0.81 → 特征语义高度接近，迁移的分布漂移是温和的；
* 差异最大的两个是 D01（指令序列）与 D07（每函数嵌入）—— 顺序敏感 + 函数划分差异；
* SMDA 发现的函数比 BN 少 26%，但七成函数的起始地址完全相同 → 函数发现能力略弱，覆盖率尚可；
* 指令量几乎一致 → 差距主要在「怎么切函数/块」，不在「看到多少代码」。

### 10.5 跑法

```bash
# ① BN-IR（需 BN + 联网，用 bnpython3 跑）
"C:\\Program Files\\Vector35\\BinaryNinja\\bnpython3.exe" tests\\compare_ir_backends.py bn \\
    --pe a.exe --out-dir _ir_bn

# ② SMDA-IR（普通 python，无需网络）
python tests/compare_ir_backends.py smda --pe a.exe --out-dir _ir_smda

# ③ 对比
python tests/compare_ir_backends.py compare --bn-dir _ir_bn --smda-dir _ir_smda
```


## 11. 生产缺陷：opcode 类特征取不到助记符

这是 Phase 2 的对照实验**顺带挖出来的既有生产问题**，与 SMDA 迁移无关，但影响很大。

### 症状

`feature_extraction/extract_feature.py::_extract_disassembly._parse_mnemonic` 取
`tokens[0].text`。而 BN 5.x 的 `DisassemblyTextLine.tokens[0]` 是**空串**（缩进/地址占位）：

```
tokens = ["", "lea", "     ", "rax", ", ", "["]
                       ^^^^ 真正的助记符在 tokens[1]
line.il_instruction.mnemonic == "lea"        ← 正确取法
```

于是 `if m:` 把几乎所有指令都过滤掉了。实测（BN 原生 API 直接验证）：

| | 修正前（生产现状） | 修正后（backend_bn.py） |
|---|---|---|
| 有指令的基本块 | **11.6%** | 100% |
| 指令总数 | **3767** | 约 10 万 |
| 平均每块指令 | **0.12** | 4~5 |

### 影响

D01（opcode 序列）、D02/D03（n-gram）、D04（类别分布）、D07（每函数嵌入）
以及 D05 的「指令总数 / 去重助记符数」这几项，**在生产上基本是空的**。
直接受害的模型：**OpcodeLSTM、OpcodeTransformer、OpcodeStatNet、AsmEmbedNet**
—— 它们的输入几乎全是常量/噪声。

### 为什么 Phase 2 之前没发现

因为 BN 的分析是**不确定**的（同一 PE 两次分析结果不同），特征指纹本来就不稳定，
「空」与「变」混在一起看不出来。直到把两个后端放在一起比，
「BN 只有 0.12 条指令/块 vs SMDA 5.25 条/块」才暴露出来。

### 处理建议（需要单独决策）

* 本轮**没有改生产代码**（`extract_feature.py` 未动）—— 改它会变更现有特征语义；
* `backend_bn.py`（新模块，无生产引用）已按正确口径取助记符；
* 建议像 W0 那样**单独立项**：先修 `extract_feature.py` 的 `_parse_mnemonic`、
  重训出干净基线，**再**切 SMDA —— 否则两件事混在一起，Phase 7 无法归因
  （到底是「修好了 opcode 特征」还是「换了后端」导致指标变化）。

> 顺带修正第 7.2 节的一个说法：那里的「BN 的 .bndb 序列化有损」，
> 实际上主要不是序列化的问题，而是**助记符取法缺陷** —— 修正取法后，
> 两条路径的指令数就几乎一致了。

## 12. Phase 3：MalGraph 切干净（BN 依赖已从 models/ 移除）

### 12.1 交付物

| 文件 | 作用 |
|---|---|
| `feature_extraction/ir.py` | 新增 `CallSite`；`BasicBlock` 增 `constant_count` / `n_outgoing` / `keywords`；`Function` 增 `name` / `call_sites`；`ProgramIR` 增 `external_symbols`；新增常量 `OP_KEYWORDS` |
| `feature_extraction/backend_bn.py` | 填新字段：MLIL 调用点、块级 token 统计、导入槽表、函数名 |
| `feature_extraction/backend_smda.py` | 同上（SMDA 版）：capstone 操作数还原调用点 |
| `feature_extraction/backend.py` | **新增**：后端调度（`CODEFENDER_DISASM_BACKEND=bn\|smda`）+ 两个分析档位 |
| `feature_extraction/bn_runtime.py` | **新增**：BN 路径注入 + 许可激活（自包含，不依赖 bn_bootstrap） |
| `models/MalGraph_2022/graph_from_ir.py` | **新增**：IR → MalGraph 图特征（11 维块特征 + FCG） |
| `models/MalGraph_2022/utils.py` | 删掉 `from binaryninja import ...`；`extract_cfg_and_fcg` 变成走 IR 的薄包装 |
| `models/MalGraph_2022/build_malgraph_cache_fast.py` | 删掉自己那份 BN 直读副本，改用统一实现 |
| `tests/compare_malgraph_backends.py` | **新增**：BN 等价性验证 + BN/SMDA 跨后端对比 |

### 12.2 MalGraph 现在完全不需要 BinaryNinja

```
PE ──▶ ProgramIR ──▶ MalGraph 特征
      (backend_bn / backend_smda，由 CODEFENDER_DISASM_BACKEND 选)
```

`models/` 目录下**已无任何 `import binaryninja`**。实测：

```
$ CODEFENDER_DISASM_BACKEND=smda python -c "...extract_cfg_and_fcg(...)"
ok funcs 1003 edges 2020 acfg 603 hash 002eae3bb1e9 vocab 400 1.8s
binaryninja imported? False        ← SMDA 路径完全不碰 BN
```

### 12.3 两个"分析档位"（不能混用）

| 档位 | 用途 | BN 分析模式 | 说明 |
|---|---|---|---|
| `features` | D01-D07 / E03-E04 | `basic` + 线性扫描 | 快；与 .bndb 门禁口径一致 |
| `graph` | MalGraph 的 CFG/FCG | 默认全量分析 | **必须**：只有全量分析才算 MLIL |

⚠ 实测：`basic` 档下 612 个函数里 **521 个 `mlil` 为 `None`**。拿 basic 档的 IR
做 FCG 会得到空调用图。旧实现（`BinaryViewType["PE"].open` + 默认分析）
本来就是全量分析，所以 `graph` 档对齐它。

### 12.4 等价性验证结果（**本次改造的硬判据**）

命令：

```
python tests/compare_malgraph_backends.py bn-equivalence --samples <样本目录>
```

判据（16 个样本，良性/恶意 × 32/64 位）：

```
等价性: 15 个一致 / 0 个不一致 / 1 个跳过
BN 自身不稳定（同一 view 跑三遍就不一致）的块×维: 1021
扣除不稳定项后，新实现与旧实现的不一致: 0
结论: OK —— 同一 BinaryView 上，IR 路径与旧 BN 直读实现逐字段一致
```

比对的字段：函数数、函数名表、FCG 边、块数、块边、11 维块特征、外部函数词表。

**唯一的"跳过"**：`s09_malicious_32.bin` —— 旧实现在某个函数上 `func.mlil`
为 `None`，直接抛 `TypeError` → 整份样本返回 `None`（MalGraph 推理直接失败）。
新实现跳过该函数继续跑。**这是修复，不是回归。**

#### 为什么判据要"扣除 BN 自身不稳定项"

BN 在**同一个 BinaryView 上重复渲染**时，「地址操作数」有时渲染成
`IntegerToken`（算常量）、有时渲染成代码符号（不算常量）——取决于 BN 内部
惰性分析的状态。实测：旧实现自己在同一个 view 上跑三遍，`constants` 维度
就有 1021 个「块×维」不一致。

所以判据改成：

* 旧实现跑三遍都不同的维度 → 判定为「BN 自身不稳定」，不计入失败
* 旧实现跑三遍相同的维度 → 新实现必须**完全一致**

结论：除 `constants` 外，**其余 10 个维度 + 全部结构字段逐字段一致**。

### 12.5 为了 1:1 复刻，IR 里多了一个 `keywords` 字段

旧实现的块特征是**逐 token 按优先级 elif 匹配**：

```
call > transfer > arithmetic > logic > compare > move >
termination > data_declaration > constants
```

因为是 elif 链，**一个文本恰好是关键字的 token 会被算进它的类别，而不是
算成常量**。实测撞到的真实例子：BN 把 `je xxx [0xa] { "or" }` 里的
字符串 `"or"` 渲染成 `StringToken`，旧实现会把它算成**一次 logic**
（而不是常量）。

所以 IR 的 `BasicBlock` 里除了 `constant_count`（非关键字的 Integer/String
个数）还带了 `keywords`（关键字 token 文本序列），MalGraph 直接按它统计。
少了这个字段，这一类块就会对不上。

### 12.6 BN ↔ SMDA 的 MalGraph 特征差异（16 个样本）

```
函数数     BN 14660   SMDA 12875   (87.8%)
FCG 边     BN 28242   SMDA 29656   (105.0%)
基本块     BN 70730   SMDA 59497   (84.1%)
外部函数名 Jaccard 平均 0.755（BN 2594 / SMDA 2571）

11 维块特征总量：
  call                35233    34276    -2.7%
  transfer            32492    30363    -6.6%
  arithmetic          46770    17034   -63.6%   ← 见下
  logic               18411    13048   -29.1%
  compare             17691    16762    -5.3%
  move               127223   122615    -3.6%
  termination           133     7527  +5559.4%   ← 见下
  total_instructions 424648   351283   -17.3%
  constants          141477    54700   -61.3%   ← 见下
  offspring           88356    75629   -14.4%
```

#### 差异 1：`termination` +5559% —— BN 渲染 `retn`，SMDA 渲染 `ret`

BN 的 x86 打印器把 near return 渲染成 **`retn`**，而关键字表里只有 `ret`。
所以 BN 侧的 termination 几乎恒为 0（16 个样本才 133 次）。SMDA 用 capstone，
助记符是 `ret`，于是 termination 正常计入。

**这是 BN 侧的渲染怪癖（老实现一直如此），不是 SMDA 的问题。**
要跟 BN 基线对齐，SMDA 侧需要把 `ret` 映射成 `retn`；要"正确"，就保留 `ret`。
**建议保留 `ret`**（MalGraph 本来就该统计返回指令），并在重训时一并处理。

#### 差异 2：`arithmetic` -63.6% —— BN 的线性扫描把数据当代码解

逐样本查下来，差距几乎全部集中在 `add` 一个助记符上（6 个样本：BN 20539
次 vs SMDA 3730 次）。抽样看 BN 里 `add` 最密集的块：

```
(204, '0x56859b9b', 'sub_56859b9b', ['add','add','add','add','add','rol','add','add'])
```

—— 整块都是 `add byte ptr [eax+edx*2], 0x0` 这种**把数据字节当指令解**
的结果。BN 的线性扫描（linear sweep）会把 .text 里的非代码区域也扫成函数；
SMDA 的递归下降不会。

**方向性结论：BN 偏"过近似"（多出数据噪声函数），SMDA 偏"欠近似"。**
两边都要盯：

* BN 多出来的：噪声函数（会拉高 basic-block 数与 arithmetic 计数）
* SMDA 少掉的：**真实函数漏检** —— 实测 `s00_benign_32.bin` BN 找到 280 个
  函数、SMDA 只找到 6 个；`s05_benign_64.bin` SMDA 一条指令都没解出来。
  **这是 SMDA 的覆盖率缺口，比 BN 的噪声更严重，必须在切换前解决。**

#### 差异 3：`constants` -61.3% —— 口径不同

BN 数的是 `IntegerToken + StringToken`（**地址操作数也算**，只要被渲染成
整数）；SMDA 只能从 capstone 的操作数类型推断（`CS_OP_IMM`），而且分支/
调用目标的立即数被排除（BN 把它们渲染成代码符号，不算常量）。

这是**两个后端口径不同**，不是某一方算错。要对齐得统一口径：
建议后续把 `constants` 定义改成"操作数里的立即数"，两个后端都按操作数类型算。

#### 差异 4：FCG 边数 SMDA 反而更多（+5%）

因为 BN 的 `MLIL_IMPORT` 分支靠 `bv.get_symbol_at(调用指令地址)` 拿导入名，
实测 **83% 的情况下取不到符号**（6004/7204），这些导入调用边直接丢了；
SMDA 从 capstone 的 RIP 相对寻址直接算出 IAT 地址，**不丢**。

也就是说 SMDA 的 FCG 更完整 —— 老实现在导入调用上是有缺陷的。

### 12.7 还没切干净的部分（MalGraph 相关）

* `engine/app.py:481` 的调用**不用改**（`extract_cfg_and_fcg` 签名保持不变）
* `engine/app.py` 的其它 BN 专用路径（`extract_de_only` 等）还没切 —— 属
  于整体迁移的 P0-1/P0-2 项，不在 MalGraph 范围内
* `models/MalGraph_2022/saved/` 与 `output/` 里的**旧权重和旧图特征缓存
  必须作废重训**：函数集合、FCG 边、11 维块特征全都变了
* 外部函数词表 `train_external_function_name_vocab.jsonl` 要用 SMDA 的
  导入表重建（BN 2594 个 vs SMDA 2571 个，Jaccard 0.755）

## 13. Phase 4：MalGraph 作废 + SMDA 重建 + 重训；BN 专用路径切除

### 13.1 为什么旧产物必须作废

BN → SMDA 切换后 MalGraph 的输入**全变了**，而旧产物是**静默失效**的：

| 产物 | 变化 | 后果 |
|---|---|---|
| 函数集合 | BN 12032 个里只有 2792 个带正常序言（77% 是数据噪声），SMDA 10269 个里 2836 个带序言 | 块特征分布整体偏移 |
| FCG 边 | BN 的 MLIL_IMPORT 分支 83% 取不到符号 → 导入调用边被丢 | FCG 少了大半导入边 |
| 11 维块特征 | retn/ret 渲染差异、常量口径差异 | 每维都有偏移 |
| 外部函数词表 | 两后端导入名集合 Jaccard 只有 0.755 | 外部函数嵌入的索引映射整体错位 |

⇒ 直接复用 = 推理输入与训练分布完全错位，**而且不会报错**，只是分数没有意义。

### 13.2 新鲜度指纹（防止再次静默失效）

`models/MalGraph_2022/artifact_guard.py` 给每个训练产物打指纹：

```
{feature_schema, ir_schema, backend, built_at, ...}
```

* 词表文件第一行写指纹（`artifact_guard.stamp_vocab_file`）
* `Vocab.__init__` 加载时比对：指纹缺失 / backend 不同 / 口径不同 → **直接抛
  StaleArtifactError**，而不是默默用旧词表跑出新分数
* 权重 `best_model.pt` 里也存了同样的指纹（诊断用）
* `saved/feature_manifest.json` 记录这次重建用的后端、样本数、目录、随机种子

### 13.3 重建与重训（可复现）

```
# ① 作废旧产物 + 用 SMDA 重抽特征 + 重建词表 + 转 .pt
python models/MalGraph_2022/rebuild_smda.py --dirs-file <样本目录.json> --limit-per-class 600 --workers 8

# ② 训练（吃 .pt）
python models/MalGraph_2022/train_malgraph.py --epochs 30
```

* 样本抽样是**确定性**的（排序 + 固定 seed），抽样清单写进 manifest
* 词表排序也是确定性的（`(-count, name)`）—— 否则并行提取的完成顺序会
  随机改变同频词的先后，而 `Counter.most_common()` 对同频项按插入顺序决胜，
  于是"同一个词表"在不同机器上会得到不同的索引映射 → 权重对不上词表
* 仓库里原本**没有** MalGraph 的训练脚本（只有特征抽取 + .pt 转换），
  `train_malgraph.py` 是这次补上的；模型结构与推理侧
  `engine/app.py::DEFAULT_MALGRAPH_PARAMS` 一致（graphsage / global_max_pool /
  11→128→128→128）

### 13.4 BN 专用路径的切除

| 删除的东西 | 替代 |
|---|---|
| `feature_extraction/_bndb_worker.py` | `feature_extraction/_ir_worker.py`（改成走 backend 调度，bn/smda 都行） |
| `BinjaExtractor.generate_bndbs_batch` | `feature_extraction/ir_cache.py::generate_irs_batch` |
| `BinjaExtractor.extract_de_from_bndb_batch` | `feature_extraction/ir_cache.py::extract_de_from_ir_batch` |
| `BinjaExtractor._extract_disassembly(bv)` | `feature_extraction/features_from_ir.py::disassembly_features` |
| `BinjaExtractor._extract_graphs(bv)` | `feature_extraction/features_from_ir.py::graph_features` |
| `BinjaExtractor._call_depth` | `features_from_ir.py::_call_depth_ir` |
| `BinjaExtractor.extract()`（48 特征一次抽完的 BN 路径，仓库内无人调用） | `extract_fast()` + `extract_de_only()` |
| `_extract_pe_structure(bv,…)` / `_extract_strings(bv,…)` / `_extract_hashes(bv,…)` / `_extract_metadata(bv,…)` | 对应的 `*_fast` 纯 Python 版本 |
| `train/_drain_bndb_to_de.py` / `_fix_de_gap.py` / `_probe_de_coverage.py`（BN 时代的一次性修补脚本） | —— |
| `train/apply_bn_optimizations.py` / `benchmark_bn_optimization.py` | —— |
| `train/data_loader.py` 的 `CODEFENDER_DE_CACHE=bndb` 分支 | 只剩 `ir`（旧环境变量值会打告警并按 ir 处理） |
| `train/build_rawpe.py::binja_prevalidate` | `ir_prevalidate`（IR 生成即验证，缓存 key 与 data_loader 一致） |

**注意**：`extract_de_only` 换成 IR 之后，**D01-D07 的语义变了** ——
旧实现取 `tokens[0].text` 当助记符，而 BN 5.x 的 `tokens[0]` 是**空的地址
分隔符**，所以旧 D01-D07 装的是 `"{ Does not return }"` 这类注解文本；
IR 路径装的是真正的助记符。⇒ **依赖 D01-D07 的 V6 系列模型
（opcode_seq / func_embed / opcode_stat）必须重训**，否则推理输入与训练
分布错位。（详见第 11 节。）

### 13.5 还没切的部分

* ~~`feature_extraction/smda_extract.py`~~（另一条并行的 SMDA 实现）**已删除**：
  它的 `extract_de` 与本文件的 `backend_smda.py + features_from_ir.py` 是同一套
  算法的两份实现（哈希都是 crc32、维度口径一致），留两套必然漂移。
  `engine/analysis_worker.py` 现在**不分后端**：一次 ProgramIR 分析同时产出
  D/E 特征与 MalGraph 输入。
* `unified.py` 的 `_extract_opcode_seq` / `_extract_func_embeddings` /
  `_extract_graph_stat` 还在直接调 BN（属 P0-5）
* `engine/app.py` 的 `include_de` 现在走 IR 了，但**没有**后端开关 ——
  推理侧要能分别用 bn/smda 跑一遍做对比，还需要把
  `CODEFENDER_DISASM_BACKEND` 贯通到推理链
