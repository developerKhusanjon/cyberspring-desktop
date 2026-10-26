@echo off
setlocal
echo ==========================================================
echo    CyberSpring SOC Controlling Center - Windows Uninstaller
echo ==========================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
pause
