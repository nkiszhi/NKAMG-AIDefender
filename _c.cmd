@echo off
cd /d D:\VM_Share\CoDefenderC3_v9
git add -A
git reset -q -- _m.txt 2>nul
git commit -F _m.txt
del _m.txt
echo ===EXIT=%ERRORLEVEL%===
git log --oneline -3
echo ===STATUS===
git status --short