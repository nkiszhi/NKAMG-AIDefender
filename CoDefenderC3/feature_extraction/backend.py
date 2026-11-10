"""Candidate D/E-only backend dispatcher. Never used by main MalGraph."""
import os
from importlib.metadata import version


def current_backend():
    backend = os.environ.get("CODEFENDER_DISASM_BACKEND", "smda").strip().lower()
    if backend not in {"bn", "smda"}:
        raise ValueError(f"unsupported disassembly backend: {backend}")
    return backend


def backend_version(backend):
    if backend == "smda":
        from .backend_smda import _smda_import
        _smda_import()
        try:
            return version("smda")
        except Exception:
            import smda
            value = str(getattr(smda, "__version__", "unknown"))
            if value == "unknown":
                raise ValueError("cannot identify SMDA version")
            return value
    if backend == "bn":
        from .bn_runtime import ensure_binaryninja
        return str(ensure_binaryninja().core_version())
    raise ValueError(f"unsupported backend: {backend}")


def analysis_config(backend):
    if backend == "smda":
        return {"backend": "intel", "addr_mode": "auto", "with_calls": False,
                "timeout": max(30, int(os.environ.get("CODEFENDER_SMDA_TIMEOUT", "120")))}
    return {"analysis.mode": "basic", "analysis.linearSweep.autorun": True,
            "analysis.limits.maxFunctionSize": 262144, "with_calls": False}


def build_ir_for_features(path, backend=None):
    from dataclasses import replace
    backend = backend or current_backend()
    expected_version = backend_version(backend)
    if backend == "smda":
        from .backend_smda import build_ir
        ir = build_ir(path, with_calls=False)
    elif backend == "bn":
        from .backend_bn import build_ir_from_path
        ir = build_ir_from_path(path, analysis="basic", with_calls=False)
    else:
        raise ValueError(f"unsupported backend: {backend}")
    ir = replace(ir, backend=backend, backend_version=expected_version)
    ir.validate()
    return ir
