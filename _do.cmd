@echo off
cd /d D:\VM_Share\CoDefenderC3_v9
git add -A
git commit -F _msg.txt
del _msg.txt
echo ===EXIT=%ERRORLEVEL%===
git log --oneline -3
git status --short