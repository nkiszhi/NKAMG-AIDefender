"""x86 指令类别表（BN 与 SMDA 两个后端共用）。

从 extract_feature.py 抽到这里，避免两套后端各维护一份类别定义。
"""

# x86 instruction categories (15 classes, D04)
INSN_CATEGORIES = {
    "arithmetic": {"add", "sub", "mul", "imul", "div", "idiv", "inc", "dec", "neg", "adc", "sbb"},
    "logic": {"and", "or", "xor", "not", "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"},
    "transfer": {"mov", "movzx", "movsx", "lea", "xchg", "cmov", "movaps", "movdqa"},
    "branch": {"jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe",
               "call", "ret", "loop", "int"},
    "stack": {"push", "pop", "pusha", "popa", "pushf", "popf", "enter", "leave"},
    "string": {"movs", "cmps", "scas", "lods", "stos", "rep", "repe", "repne"},
    "flag": {"stc", "clc", "cmc", "std", "cld", "sti", "cli", "lahf", "sahf"},
    "float": {"fld", "fst", "fstp", "fadd", "fsub", "fmul", "fdiv", "fcom", "fxch"},
    "simd": {"addps", "mulps", "subps", "divps", "paddb", "paddw", "paddd", "pxor",
             "xmm", "ymm", "zmm"},
    "system": {"syscall", "sysenter", "rdtsc", "cpuid", "rdmsr", "wrmsr", "hlt", "in", "out"},
    "nop": {"nop"},
    "interrupt": {"int", "int3", "iret"},
    "io": {"in", "out", "ins", "outs"},
    "prefix": {"lock", "rep", "repz", "repnz", "cs", "ds", "es", "fs", "gs", "ss"},
}

# Flatten for lookup
CAT_LOOKUP = {}
for _cat, _mnemonics in INSN_CATEGORIES.items():
    for _m in _mnemonics:
        CAT_LOOKUP[_m] = _cat

CAT_NAMES = list(INSN_CATEGORIES.keys()) + ["other"]  # 15 categories
