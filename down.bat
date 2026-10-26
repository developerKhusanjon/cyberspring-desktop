@echo off
REM ==============================================================================
REM 🛑 CyberSpring — Stop / Down Server Script for Windows (CMD)
REM ==============================================================================
echo [INFO] Stopping CyberSpring server on port 8787...

REM Terminate process holding port 8787
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8787" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
    echo [OK] Stopped process with PID %%a
)

REM Also terminate any remaining cyberspring.exe
taskkill /F /IM cyberspring.exe >nul 2>&1

echo [OK] CyberSpring server is down.
