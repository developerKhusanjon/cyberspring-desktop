# CyberSpring — One-Click Windows PowerShell Desktop Launcher
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  🌿 CyberSpring SOC Controlling Center & SAST Scanner" -ForegroundColor Green
Write-Host "  Cross-Platform Desktop Suite for Windows (PowerShell)" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan

if (-not (Test-Path ".\cyberspring.exe")) {
    Write-Host "[INFO] Building CyberSpring standalone binary for Windows..." -ForegroundColor Yellow
    go build -o cyberspring.exe cmd\cyberspring\main.go
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[ERROR] Build failed. Please ensure Go is installed."
        exit 1
    }
}

Write-Host "[INFO] Launching CyberSpring Desktop GUI on http://127.0.0.1:8787 ..." -ForegroundColor Green
Start-Process -FilePath ".\cyberspring.exe" -ArgumentList "-gui", "-port 8787"
