# ==============================================================================
# 🗑️ CyberSpring Windows Uninstaller (PowerShell)
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   CyberSpring Standalone Uninstaller                     " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Stop any running instance
Write-Host "[*] Stopping any active CyberSpring processes..." -ForegroundColor Cyan
Stop-Process -Name "cyberspring" -Force -ErrorAction SilentlyContinue

$InstallDir = "$env:LOCALAPPDATA\Programs\CyberSpring"
$DesktopShortcut = "$([Environment]::GetFolderPath('Desktop'))\CyberSpring.lnk"
$StartShortcut = "$([Environment]::GetFolderPath('Programs'))\CyberSpring.lnk"

# 2. Remove Shortcuts
if (Test-Path $DesktopShortcut) {
    Remove-Item -Path $DesktopShortcut -Force
    Write-Host "[+] Removed Desktop shortcut." -ForegroundColor Green
}

if (Test-Path $StartShortcut) {
    Remove-Item -Path $StartShortcut -Force
    Write-Host "[+] Removed Start Menu shortcut." -ForegroundColor Green
}

# 3. Remove Program Files
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "[+] Removed CyberSpring program directory: $InstallDir" -ForegroundColor Green
}

# 4. Clean User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -like "*$InstallDir*") {
    $NewPath = ($UserPath -split ';' | Where-Object { $_ -ne $InstallDir -and $_ -ne "" }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
    Write-Host "[+] Cleaned CyberSpring from User PATH." -ForegroundColor Green
}

Write-Host ""
Write-Host "[SUCCESS] CyberSpring has been uninstalled from this device." -ForegroundColor Green
