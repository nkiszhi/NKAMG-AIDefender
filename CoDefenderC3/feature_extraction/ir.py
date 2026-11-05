# -*- coding: utf-8 -*-
"""ProgramIR —— 后端中立的程序中间表示（契约草案）。

为什么要 IR
-------------
SMDA 迁移要把「反汇编后端」和「特征计算」解耦：

    PE ──[后端: BN / SMDA]──> ProgramIR ──[特征层]──> D01-D07 / E03-E04

中间这层 IR 同时解决三个问题：

1. **后端可替换**：BN 与 SMDA 产出同构的 IR，特征层代码一份就够；
2. **缓存中立**：IR 可像现在的 .bndb 一样缓存，但不再依赖某个后端的私有格式。
   后端的不确定性被隔离在「生成一次 IR」这一步 —— 「IR → 特征」是纯函数；
3. **口径可审计**：特征用到了 IR 的哪些字段，在这里一目了然（见 docs/IR_CONTRACT.md）。

设计不变量（改代码前先读这段）
--------------------------------
* **顺序即语义**：functions / blocks / instructions / callees 全部是**有序列表**，
  顺序与后端的遍历顺序一致。D01（opcode 序列）、D02/D03（n-gram）直接依赖这个顺序，
  所以**不能**用 set / dict 去重，否则特征会变。
* **callees 保留重复**：一个函数两次调用同一个被调方，计 **2 条调用边**
  （现有代码 cg_edges += 1 是按重数计的）。所以 callees 是元组，不是集合。
* **助记符非空且小写**：后端适配时丢弃空助记符（等价于现有代码的 if m: 过滤），
  其余统一 .strip().lower()。
* **地址用 int**：函数/基本块的标识与比较一律用起始地址（现有代码亦如此）。
* **不可变**：全部 frozen dataclass + tuple，可哈希、可安全缓存。

2026-11-05
"""
from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

SCHEMA_VERSION = "codefender-ir/1"


class IRValidationError(ValueError):
    """IR 结构不满足契约时抛出。"""


@dataclass(frozen=True)
class BasicBlock:
    """一个基本块。

    Attributes:
        start:        起始地址（块的身份标识）
        length:       字节长度；后端拿不到时为 None（现有代码遇到 None 会跳过该样本）
        instructions: 助记符序列（非空、已小写），顺序即执行顺序
        successors:   后继基本块的起始地址列表（有序、原样透传：
                     E03 的回边判定依赖 target 的地址大小关系）
    """

    start: int
    length: Optional[int]
    instructions: Tuple[str, ...]
    successors: Tuple[int, ...] = ()

    def to_dict(self):
        return {
            "start": int(self.start),
            "length": (None if self.length is None else int(self.length)),
            "instructions": list(self.instructions),
            "successors": [int(s) for s in self.successors],
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            start=int(d["start"]),
            length=(None if d.get("length") is None else int(d["length"])),
            instructions=tuple(d.get("instructions") or ()),
            successors=tuple(int(s) for s in (d.get("successors") or ())),
        )


@dataclass(frozen=True)
class Function:
    """一个函数。

    Attributes:
        start:    起始地址（函数的身份标识）
        size:     字节数；后端按「total_bytes，否则 highest_address - start」的口径填
        blocks:   基本块列表（有序）
        callees:  被调用函数的起始地址列表（**保留重复**，见模块 docstring）
    """

    start: int
    size: int
    blocks: Tuple[BasicBlock, ...]
    callees: Tuple[int, ...] = ()

    @property
    def n_blocks(self) -> int:
        return len(self.blocks)

    @property
    def n_callees(self) -> int:
        return len(self.callees)

    @property
    def is_leaf(self) -> bool:
        return len(self.callees) == 0

    @property
    def is_recursive(self) -> bool:
        """自递归：callees 里含自己。与现有代码 any(c == func for c in callees) 等价。"""
        return self.start in self.callees

    def to_dict(self):
        return {
            "start": int(self.start),
            "size": int(self.size),
            "callees": [int(c) for c in self.callees],
            "blocks": [b.to_dict() for b in self.blocks],
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            start=int(d["start"]),
            size=int(d.get("size") or 0),
            blocks=tuple(BasicBlock.from_dict(b) for b in (d.get("blocks") or ())),
            callees=tuple(int(c) for c in (d.get("callees") or ())),
        )


@dataclass(frozen=True)
class ProgramIR:
    """一个程序的中间表示。

    Attributes:
        functions:        函数列表（有序）
        imports:          导入符号全名（如 "kernel32.dll.CreateFileW"）
        arch:             架构标识（"x86_64" / "x86" / "arm64"）
        bitness:          32 / 64
        backend:          产出该 IR 的后端名（"bn" / "smda"）
        backend_version:  后端版本字符串（如 BN 的 "5.2.8722"）
    """

    functions: Tuple[Function, ...]
    imports: Tuple[str, ...] = ()
    arch: str = "unknown"
    bitness: int = 0
    backend: str = "unknown"
    backend_version: str = "unknown"
    schema_version: str = SCHEMA_VERSION

    @property
    def n_functions(self) -> int:
        return len(self.functions)

    @property
    def n_blocks(self) -> int:
        return sum(f.n_blocks for f in self.functions)

    @property
    def n_instructions(self) -> int:
        return sum(len(b.instructions) for f in self.functions for b in f.blocks)

    def mnemonic_stream(self) -> Iterator[str]:
        """按「函数顺序 → 块顺序 → 指令顺序」展平全部助记符。

        这就是现有代码里的 all_opcodes，D01/D02/D03/D04/D07 都基于它。
        """
        for f in self.functions:
            for b in f.blocks:
                for m in b.instructions:
                    yield m

    def block_stream(self) -> Iterator[BasicBlock]:
        for f in self.functions:
            for b in f.blocks:
                yield b

    def function_map(self) -> dict:
        """起始地址 → Function 的索引。

        调用图统计（E04 的调用深度）需要按地址回查被调函数。
        契约：**callees 里的地址应能在本索引中找到**；
        找不到的视为「外部/未知目标」，深度不再下探（与 BN 里 callee 一定是已知
        Function 对象的行为一致）。
        """
        return {f.start: f for f in self.functions}

    def validate(self) -> None:
        """检查结构不变量；不满足则抛 IRValidationError。

        只检查**契约层**的不变量（身份唯一、字段合法），
        不检查「后端分析是否正确」—— 那是后端的责任。
        """
        if self.schema_version != SCHEMA_VERSION:
            raise IRValidationError("schema_version 不匹配: %r != %r"
                                   % (self.schema_version, SCHEMA_VERSION))
        if self.bitness not in (0, 32, 64):
            raise IRValidationError("bitness 非法: %r" % (self.bitness,))
        seen_func = set()
        for f in self.functions:
            if f.start in seen_func:
                raise IRValidationError("函数起始地址重复: 0x%x" % f.start)
            seen_func.add(f.start)
            if f.size < 0:
                raise IRValidationError("函数 size 为负: 0x%x" % f.start)
            seen_bb = set()
            for b in f.blocks:
                if b.start in seen_bb:
                    raise IRValidationError("函数 0x%x 内基本块地址重复: 0x%x"
                                           % (f.start, b.start))
                seen_bb.add(b.start)
                if b.length is not None and b.length < 0:
                    raise IRValidationError("基本块 length 为负: 0x%x" % b.start)
                for m in b.instructions:
                    if not m:
                        raise IRValidationError("助记符为空串（后端适配器应过滤）")
                    if m != m.strip().lower():
                        raise IRValidationError("助记符未规范化: %r" % m)

    def to_dict(self) -> dict:
        """规范化字典（助记符表压缩 + 固定键序）。

        压缩：助记符去重成一张表，块内用下标引用。典型样本可缩小 3~5 倍。
        """
        vocab = []
        index = {}

        def mid(m):
            i = index.get(m)
            if i is None:
                i = len(vocab)
                vocab.append(m)
                index[m] = i
            return i

        funcs = []
        for f in self.functions:
            blocks = []
            for b in f.blocks:
                blocks.append({
                    "start": int(b.start),
                    "length": (None if b.length is None else int(b.length)),
                    "succ": [int(s) for s in b.successors],
                    "ins": [mid(m) for m in b.instructions],
                })
            funcs.append({
                "start": int(f.start),
                "size": int(f.size),
                "callees": [int(c) for c in f.callees],
                "blocks": blocks,
            })
        return {
            "schema": SCHEMA_VERSION,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "arch": self.arch,
            "bitness": int(self.bitness),
            "mnemonics": vocab,
            "imports": list(self.imports),
            "functions": funcs,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProgramIR":
        vocab = list(d.get("mnemonics") or ())
        funcs = []
        for f in d.get("functions") or ():
            blocks = []
            for b in f.get("blocks") or ():
                ins = tuple(vocab[i] for i in (b.get("ins") or ()))
                blocks.append(BasicBlock(
                    start=int(b["start"]),
                    length=(None if b.get("length") is None else int(b["length"])),
                    instructions=ins,
                    successors=tuple(int(s) for s in (b.get("succ") or ())),
                ))
            funcs.append(Function(
                start=int(f["start"]),
                size=int(f.get("size") or 0),
                blocks=tuple(blocks),
                callees=tuple(int(c) for c in (f.get("callees") or ())),
            ))
        return cls(
            functions=tuple(funcs),
            imports=tuple(d.get("imports") or ()),
            arch=str(d.get("arch") or "unknown"),
            bitness=int(d.get("bitness") or 0),
            backend=str(d.get("backend") or "unknown"),
            backend_version=str(d.get("backend_version") or "unknown"),
            schema_version=str(d.get("schema") or SCHEMA_VERSION),
        )

    def to_json(self, indent=None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":") if indent is None else None, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "ProgramIR":
        return cls.from_dict(json.loads(text))

    def save(self, path: str) -> str:
        """写到 path（.gz 自动压缩）。返回实际写入路径。"""
        data = self.to_json()
        if path.endswith(".gz"):
            with gzip.open(path, "wt", encoding="utf-8") as f:
                f.write(data)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
        return path

    @classmethod
    def load(cls, path: str) -> "ProgramIR":
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8") as f:
                return cls.from_json(f.read())
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())
