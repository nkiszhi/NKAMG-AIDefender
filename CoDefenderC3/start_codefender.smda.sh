#!/bin/bash
# ── SMDA 版启动脚本 ──────────────────────────────────────────
# 与 BinaryNinja 版的差异：不激活 BN license、不需要 /opt/binaryninja。
# 反汇编后端由 CODEFENDER_DISASM_BACKEND=smda 决定（默认即 smda）。
exec python3 -m uvicorn engine.app:app --host 0.0.0.0 --port 8000
