@echo off
cd /d D:\VM_Share\CoDefenderC3_v9\CoDefenderC3
set PYTHONIOENCODING=utf-8
set PYTHONPATH=D:\VM_Share\CoDefenderC3_v9\_tools\py310_pkgs
"C:\Program Files\Vector35\BinaryNinja\bnpython3.exe" tests\verify_ir_equivalence.py --bndb-dir "D:\VM_Share\CoDefenderC3_v8\minimal_dataset\.cache\bndb" --ir-out D:\VM_Share\CoDefenderC3_v9\_ir_out
echo ===EXIT=%ERRORLEVEL%===