@echo off
REM CyberSpring — One-Click Windows Desktop Launcher
setlocal
cd /d "%~dp0"

echo ========================================================
echo   🌿 CyberSpring SOC Controlling Center & SAST Scanner
echo   Cross-Platform Desktop Suite for Windows
echo ========================================================

if not exist cyberspring.exe (
    echo [INFO] Building CyberSpring standalone binary for Windows...
    go build -o cyberspring.exe cmd\cyberspring\main.go
    if errorlevel 1 (
        echo [ERROR] Build failed. Please verify Go is installed and available in PATH.
        pause
        exit /b 1
    )
)

echo [INFO] Launching CyberSpring Desktop GUI on http://127.0.0.1:8787 ...
start "" cyberspring.exe -gui -port 8787
