@echo off
setlocal
echo ==========================================================
echo    CyberSpring SOC Controlling Center - Windows Installer
echo ==========================================================
echo Running PowerShell installer...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %errorlevel% neq 0 (
    echo.
    echo Installation encountered an error.
    pause
    exit /b %errorlevel%
)
echo.
pause
