@echo off
setlocal EnableExtensions

REM ===================================================================
REM  DEV ONLY - start CoDefenderC3 in 100% MODEL-ONLY mode
REM  (all four hash-precheck stages sha256/md5/fuzzy/tlsh disabled)
REM
REM  Why a launcher script instead of a config file:
REM    * the environment variables apply to THIS process only and nothing
REM      is written to disk, so there is no way this leaks into a Docker
REM      image or into a later production start
REM    * it sidesteps the three classic CMD pitfalls: inline "VAR=value cmd"
REM      (not a command), a trailing space in the value ("0 " != "0"), and
REM      variables being lost when the window closes
REM
REM  Production containers must NOT use this script. The Dockerfile pins
REM  CODEFENDER_ENV=prod + HASH_DB_ENABLED=1 + REQUIRE_HASH_DB=1, so a
REM  container always runs the full engine and refuses to start when the
REM  signature DB is missing.
REM
REM  Verify with:  curl http://127.0.0.1:8000/health
REM                expect  "env":"dev"  and  "engine_mode":"model_only"
REM
REM  NOTE: this file is intentionally ASCII-ONLY. Non-ASCII text in a .cmd
REM        breaks the CMD parser once the console codepage is switched -
REM        comment lines get executed as commands and the script half-runs.
REM        Keep every message here in English / ASCII.
REM ===================================================================

if not defined CODEFENDER_PYEXE set "CODEFENDER_PYEXE=D:\work\tools\miniconda3\python.exe"
if exist "%CODEFENDER_PYEXE%" goto cf_py_ok
echo [dev] ERROR: python interpreter not found: %CODEFENDER_PYEXE%
echo [dev] set "CODEFENDER_PYEXE=D:\path\to\python.exe" then rerun this script
exit /b 1

:cf_py_ok
if not defined CODEFENDER_PORT set "CODEFENDER_PORT=8000"
cd /d "%~dp0"

set "PYTHONIOENCODING=utf-8"
set "CODEFENDER_ENV=dev"
set "CODEFENDER_HASH_DB_ENABLED=0"
set "CODEFENDER_FUZZY_DB_ENABLED=0"
set "CODEFENDER_REQUIRE_HASH_DB=0"

REM Port probe via python (more robust than netstat|findstr quoting).
REM A stale instance holding the port is the classic reason why "I changed
REM the config but nothing happened" - requests keep hitting the OLD
REM process. Fail fast instead of starting a second doomed instance.
REM exit 0 = port free, exit 2 = port already listening.
"%CODEFENDER_PYEXE%" -c "import socket,sys;s=socket.socket();s.settimeout(1.0);r=s.connect_ex(('127.0.0.1',int(sys.argv[1])));s.close();sys.exit(2 if r==0 else 0)" %CODEFENDER_PORT%
if not errorlevel 2 goto cf_port_ok
echo [dev] ERROR: port %CODEFENDER_PORT% is already in use - refusing to start.
echo [dev] A stale process on that port makes every request hit the OLD instance,
echo [dev] which looks exactly like "the config change did not take effect".
netstat -ano | findstr ":%CODEFENDER_PORT%"
echo [dev] fix: taskkill /F /PID ^(pid in the last column^)
echo [dev]  or : set "CODEFENDER_PORT=8001" and rerun this script
exit /b 1

:cf_port_ok
echo.
echo [dev] ===== CoDefenderC3 : MODEL-ONLY MODE (local dev) =====
echo [dev] CODEFENDER_ENV=dev   HASH_DB_ENABLED=0   FUZZY_DB_ENABLED=0
echo [dev] every sample goes through the 33-model ensemble, no hash precheck
echo [dev] listening on :%CODEFENDER_PORT%    Ctrl+C to stop
echo [dev] ====================================================
echo.

"%CODEFENDER_PYEXE%" -u -m uvicorn engine.app:app --host 0.0.0.0 --port %CODEFENDER_PORT%

endlocal
