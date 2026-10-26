# ==============================================================================
# 🛑 CyberSpring — Stop / Down Server Script for Windows (PowerShell)
# ==============================================================================
Write-Host "[INFO] Stopping CyberSpring server on port 8787..." -ForegroundColor Yellow

$connections = Get-NetTCPConnection -LocalPort 8787 -ErrorAction SilentlyContinue
if ($connections) {
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($p in $pids) {
        Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Stopped process ID $p" -ForegroundColor Green
    }
}

Stop-Process -Name "cyberspring" -Force -ErrorAction SilentlyContinue
Write-Host "[OK] CyberSpring server is down." -ForegroundColor Green
