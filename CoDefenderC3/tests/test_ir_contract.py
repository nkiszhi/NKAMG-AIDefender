# -*- coding: utf-8 -*-
"""ProgramIR 契约测试（不需要 BN / numpy / torch）。

作用：
· 守住 IR 的**结构不变量**（顺序、重复、规范化、不可变）
· 守住**序列化往返**（to_dict → from_dict → 一致）
· 用一个 **mock 后端**固化「适配器该做什么」—— 它就是 backend_bn.py 的行为规范：
    - 过滤空助记符
    - 助记符 strip().lower()
    - callees 用地址且**保留重复**
    - successors 原样透传（不排序、不去重）

2026-11-05
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# 直接按文件加载，绕开 feature_extraction/__init__.py（它会 import torch）
ir_mod = _load("ir", os.path.join("feature_extraction", "ir.py"))
ProgramIR = ir_mod.ProgramIR
Function = ir_mod.Function
BasicBlock = ir_mod.BasicBlock
IRValidationError = ir_mod.IRValidationError


# ── mock 后端：模拟 BN 的 bv 对象 ─────────────────────────────


class _Tok:
    def __init__(self, text):
        self.text = text


class _Line:
    def __init__(self, text):
        self.tokens = [_Tok(text)]


class _Edge:
    def __init__(self, target):
        self.target = target


class _Block:
    def __init__(self, start, length, mnemonics, succ_blocks):
        self.start = start
        self.length = length
        self.disassembly_text = [_Line(m) for m in mnemonics]
        self.outgoing_edges = [_Edge(b) for b in succ_blocks]


class _Func:
    def __init__(self, start, size, blocks, callees):
        self.start = start
        self.total_bytes = size
        self.highest_address = start + size
        self.basic_blocks = blocks
        self.callees = callees


def _adapt(mock_funcs, mock_imports=()):
    """**参考适配器** —— backend_bn.py 必须与它行为一致。

    规则：
      1. 助记符取 tokens[0].text，strip().lower()，空串丢弃
      2. callees 取 callee.start，**保留重复与顺序**
      3. successors 取 edge.target.start，原样透传
      4. size = total_bytes（为 0/None 时退化为 highest_address - start）
    """
    funcs = []
    for f in mock_funcs:
        blocks = []
        for b in f.basic_blocks:
            ins = []
            for line in b.disassembly_text:
                m = line.tokens[0].text.strip().lower()
                if m:                       # 规则 1：过滤空助记符
                    ins.append(m)
            blocks.append(BasicBlock(
                start=b.start,
                length=b.length,
                instructions=tuple(ins),
                successors=tuple(e.target.start for e in b.outgoing_edges),   # 规则 3
            ))
        size = f.total_bytes
        if not size:
            size = f.highest_address - f.start                             # 规则 4
        funcs.append(Function(
            start=f.start,
            size=size,
            blocks=tuple(blocks),
            callees=tuple(c.start for c in f.callees),                       # 规则 2
        ))
    return ProgramIR(functions=tuple(funcs), imports=tuple(mock_imports),
                      arch="x86_64", bitness=64, backend="mock",
                      backend_version="0")


def _sample_ir():
    """构造一个小的 IR：
       f0 (0x1000): bb0 → bb1；bb1 → bb0（回边）
                  callees: [f1, f1]   ← 故意重复
       f1 (0x2000): 单块
    """
    b0 = _Block(0x1000, 32, ["MOV", "push", "", "CALL"], [])
    b1 = _Block(0x1020, 16, ["RET"], [])
    b0.outgoing_edges = [_Edge(b1)]
    b1.outgoing_edges = [_Edge(b0)]        # 回边：target.start(0x1000) <= bb.start(0x1020)
    f1 = _Func(0x2000, 8, [_Block(0x2000, 8, ["nop"], [])], [])
    f0 = _Func(0x1000, 48, [b0, b1], [f1, f1])
    return _adapt([f0, f1], ["kernel32.dll.CreateFileW"])


# ── 测试 ─────────────────────────────────────────────────────


def test_mnemonic_stream_is_flattened_in_order():
    ir = _sample_ir()
    got = list(ir.mnemonic_stream())
    assert got == ["mov", "push", "call", "ret", "nop"], got
    assert ir.n_functions == 2
    assert ir.n_blocks == 3
    assert ir.n_instructions == 5


def test_empty_mnemonics_are_dropped():
    """b0 的助记符里有空串 —— 必须被过滤（等价于现有代码的 if m:）。"""
    ir = _sample_ir()
    b0 = ir.functions[0].blocks[0]
    assert "" not in b0.instructions
    assert b0.instructions == ("mov", "push", "call")


def test_mnemonics_are_lowercased_and_stripped():
    ir = _sample_ir()
    for m in ir.mnemonic_stream():
        assert m == m.strip().lower()


def test_callees_keep_duplicates_and_order():
    """I2：同一被调方出现两次 = 两条调用边。"""
    ir = _sample_ir()
    f0 = ir.functions[0]
    assert f0.callees == (0x2000, 0x2000)
    assert f0.n_callees == 2
    assert not f0.is_leaf


def test_self_recursion_detected():
    f = Function(start=0x10, size=4, blocks=(), callees=(0x10, 0x20))
    assert f.is_recursive
    assert not f.is_leaf
    f2 = Function(start=0x10, size=4, blocks=(), callees=(0x20,))
    assert not f2.is_recursive


def test_successors_preserved_unsorted():
    """I6：successors 原样透传，不排序 —— E03 回边判定依赖地址序。"""
    b = BasicBlock(start=0x1020, length=8, instructions=("ret",),
                   successors=(0x1000, 0x2000, 0x1500))
    assert b.successors == (0x1000, 0x2000, 0x1500)


def test_roundtrip_dict_is_equal():
    ir = _sample_ir()
    ir2 = ProgramIR.from_dict(ir.to_dict())
    assert ir2 == ir
    assert list(ir2.mnemonic_stream()) == list(ir.mnemonic_stream())


def test_roundtrip_json_and_gz():
    import tempfile
    ir = _sample_ir()
    txt = ir.to_json()
    assert ProgramIR.from_json(txt) == ir
    with tempfile.TemporaryDirectory() as d:
        p1 = os.path.join(d, "ir.json")
        p2 = os.path.join(d, "ir.json.gz")
        ir.save(p1)
        ir.save(p2)
        assert ProgramIR.load(p1) == ir
        assert ProgramIR.load(p2) == ir
        assert os.path.getsize(p2) < os.path.getsize(p1)


def test_json_is_canonical():
    """同一 IR 序列化两次结果一致（可缓存、可比对）。"""
    ir = _sample_ir()
    assert ir.to_json() == ir.to_json()
    d = json.loads(ir.to_json())
    assert d["schema"] == ir_mod.SCHEMA_VERSION
    assert d["mnemonics"][0] == "mov"


def test_ir_is_immutable_and_hashable():
    """I5：frozen dataclass + tuple。"""
    ir = _sample_ir()
    try:
        ir.bitness = 32
        raise AssertionError("ProgramIR 不应可改")
    except Exception as e:
        assert "frozen" in str(e).lower() or "cannot assign" in str(e).lower()
    assert isinstance(hash(ir.functions[0]), int)


def test_function_map_lookup():
    ir = _sample_ir()
    m = ir.function_map()
    assert set(m.keys()) == {0x1000, 0x2000}
    assert m[0x1000].start == 0x1000


def test_validate_rejects_duplicate_function_starts():
    f = Function(start=0x10, size=1, blocks=(), callees=())
    ir = ProgramIR(functions=(f, f), bitness=64)
    try:
        ir.validate()
        raise AssertionError("重复函数地址应被拒绝")
    except IRValidationError:
        pass


def test_validate_rejects_bad_mnemonics():
    b = BasicBlock(start=0x1, length=1, instructions=("MOV",), successors=())
    ir = ProgramIR(functions=(Function(start=0x1, size=1, blocks=(b,), callees=()),),
                   bitness=64)
    try:
        ir.validate()
        raise AssertionError("未规范化助记符应被拒绝")
    except IRValidationError:
        pass
    b2 = BasicBlock(start=0x1, length=1, instructions=("",), successors=())
    ir2 = ProgramIR(functions=(Function(start=0x1, size=1, blocks=(b2,), callees=()),),
                    bitness=64)
    try:
        ir2.validate()
        raise AssertionError("空助记符应被拒绝")
    except IRValidationError:
        pass


def test_validate_rejects_bad_schema_and_bitness():
    ir = _sample_ir()
    bad = ProgramIR(functions=ir.functions, schema_version="codefender-ir/999")
    try:
        bad.validate()
        raise AssertionError("schema 不匹配应被拒绝")
    except IRValidationError:
        pass
    bad2 = ProgramIR(functions=ir.functions, bitness=99)
    try:
        bad2.validate()
        raise AssertionError("非法 bitness 应被拒绝")
    except IRValidationError:
        pass


def test_valid_ir_passes_validate():
    ir = _sample_ir()
    ir.validate()


def main() -> int:
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print("  PASS  %s" % name)
        except Exception as e:
            failed.append((name, e))
            print("  FAIL  %s :: %s" % (name, e))
    print("\n%d/%d passed" % (len(tests) - len(failed), len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
