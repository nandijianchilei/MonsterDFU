@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================
echo   DFU Prototype - One-Click Start
echo ============================================

rem 1. check python available
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

rem 2. auto install missing dependencies
echo [1/3] Checking dependencies...
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [WARN] Dependency install failed, trying to continue...
)

rem 3. start web_server.py in background
echo [2/3] Starting web_server.py ...
start "DFU Web Server" cmd /c "python web_server.py"

rem 4. wait for server and open browser
echo [3/3] Waiting for server...
powershell -NoProfile -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:8000/monster'"

echo.
echo Started. Browser will open http://127.0.0.1:8000/monster
echo If DFU_WEB_TOKEN not set, token will be printed in server console window.
endlocal
