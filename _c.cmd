@echo off
cd /d D:\VM_Share\CoDefenderC3_v9
git rm -r --cached -f -q --ignore-unmatch _ir_out _c.cmd _eq.cmd _pa.cmd _probe_arch.py
git add -A
git reset -q -- _m.txt 2>nul
git commit -F _m.txt
del _m.txt
del _restore.cmd 2>nul
echo ===EXIT=%ERRORLEVEL%===
git log --oneline -3
echo ===STATUS===
git status --short
echo ===TRACKED_TEMP===
git ls-files | findstr /i "ir_out _c.cmd _eq.cmd _pa.cmd"