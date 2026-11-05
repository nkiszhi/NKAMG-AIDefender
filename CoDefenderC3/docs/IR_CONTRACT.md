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

| 步 | 内容 | 产出 | 验收 |
|---|---|---|---|
| 1 | `ir.py`（本设计已给出代码） | 数据类 + 序列化 + 校验 | `tests/test_ir_contract.py` |
| 2 | `backend_bn.py`：`bv → ProgramIR` | 纯适配器，不碰特征计算 | 单测：mock bv → IR |
| 3 | `backend_smda.py`：SMDA → IR | 同构产出（Phase 2） | 与 BN 的 IR 做字段级对比 |
| 4 | `_extract_disassembly(ir)` / `_extract_graphs(ir)` | 特征层改为消费 IR | **G2 门禁逐位不变** |
| 5 | 训练管线接 IR 缓存 | 替掉 .bndb 缓存 | D/E 覆盖率不降 |

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

## 8. 风险与开放问题

| 问题 | 影响 | 现状 |
|---|---|---|
| BN 与 SMDA 的**函数发现顺序**不同 | D01/D02/D03 序列类特征会变 | 不可避免；Phase 7 用分布对比量化。IR 至少让「哪里变了」可定位 |
| BN 与 SMDA 的**函数发现数量**不同 | D05/E03/E04 的计数类特征会变 | 同上 |
| SMDA 的**函数识别质量**不足 | E 视角特征弱、MalGraph 掉点 | Phase 0 PoC 必须实测 |
| BN 分析不确定 | 同一 PE 两次分析结果不同 | 已由 W1 量化；IR 缓存把影响关在一次生成里 |
| 32 位样本的函数发现 | 覆盖率低 | Phase 0 单列评估 |
| IR 缓存体积 | 训练集 6k 样本的 IR 有多大？ | 待实测（助记符表压缩后预计单样本 100~500 KB） |
| IR schema 演进 | 旧缓存失效 | `schema_version` + 重建策略（旧版本直接重算） |

## 9. 相关文档

* [`docs/FEATURE_HASH_STABILITY.md`](FEATURE_HASH_STABILITY.md) —— W0：跨进程 hash 一致性
* [`docs/BASELINE_FIXTURE.md`](BASELINE_FIXTURE.md) —— W1：两级门禁与 BN 的两个前置条件
