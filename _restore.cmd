@echo off
cd /d D:\VM_Share\CoDefenderC3_v9
mkdir _wheels
C:\Users\lenovo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m pip download numpy==1.26.4 --only-binary=:all: --python-version 310 --implementation cp --abi cp310 --platform win_amd64 --no-deps -d _wheels
C:\Users\lenovo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m pip download pefile --no-deps -d _wheels
mkdir _tools\py310_pkgs
C:\Users\lenovo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -c "import zipfile,glob;[zipfile.ZipFile(w).extractall(chr(95)+chr(116)+chr(111)+chr(111)+chr(108)+chr(115)+chr(92)+chr(112)+chr(121)+chr(51)+chr(49)+chr(48)+chr(95)+chr(112)+chr(107)+chr(103)+chr(115)) for w in glob.glob(chr(95)+chr(119)+chr(104)+chr(101)+chr(101)+chr(108)+chr(115)+chr(92)+chr(42)+chr(46)+chr(119)+chr(104)+chr(108))]"
dir /b _tools\py310_pkgs
echo ===EXIT=%ERRORLEVEL%===