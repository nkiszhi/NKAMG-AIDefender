#!/bin/bash
# Default to SMDA; explicit CODEFENDER_DISASM_BACKEND=bn retains licensed BN.
set -e
CODEFENDER_DISASM_BACKEND="$(python3 -m engine.startup)"
export CODEFENDER_DISASM_BACKEND

if [ "$CODEFENDER_DISASM_BACKEND" = "bn" ]; then
    export PATH="/opt/binaryninja:$PATH"
    export LD_LIBRARY_PATH="/opt/binaryninja:${LD_LIBRARY_PATH:-}"
    export PYTHONPATH="/opt/binaryninja/python:${PYTHONPATH:-}"
    python3 -c '
import binaryninja as bn, os
lic = os.path.expanduser("~/.binaryninja/license.dat")
if os.path.exists(lic):
    with open(lic) as handle:
        bn.core_set_license(handle.read())
    print("[startup] BinaryNinja license activated")
'
fi
exec python3 -m engine.serve
