# ==============================================================================
# 🌸 CyberSpring Windows Installer (PowerShell)
# ==============================================================================
# Installs CyberSpring standalone binary, configures User PATH, creates Start
# Menu and Desktop shortcuts. No Administrator privileges required.
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   CyberSpring SOC Controlling Center & SAST Scanner      " -ForegroundColor Yellow
Write-Host "   Windows Standalone Installer                           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "$env:LOCALAPPDATA\Programs\CyberSpring"
$BinSource = ""

# Look for Windows executable
$Candidates = @(
    "$ScriptDir\bin\cyberspring-windows-amd64.exe",
    "$ScriptDir\cyberspring-windows-amd64.exe",
    "$ScriptDir\cyberspring.exe",
    "$ScriptDir\bin\cyberspring.exe"
)

foreach ($c in $Candidates) {
    if (Test-Path $c) {
        $BinSource = $c
        break
    }
}

if (-not $BinSource) {
    Write-Host "[!] Error: Could not find Windows executable 'cyberspring-windows-amd64.exe' or 'cyberspring.exe'." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Source binary: $BinSource" -ForegroundColor Green
Write-Host "[*] Target installation folder: $InstallDir" -ForegroundColor Green

# 1. Create Directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# 2. Copy Executable and Icon
Copy-Item -Path $BinSource -Destination "$InstallDir\cyberspring.exe" -Force
if (Test-Path "$ScriptDir\assets\icon.ico") {
    Copy-Item -Path "$ScriptDir\assets\icon.ico" -Destination "$InstallDir\icon.ico" -Force
}

# 3. Add to User PATH if not already present
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Adding CyberSpring to User PATH..." -ForegroundColor Cyan
    $NewPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[+] User PATH updated." -ForegroundColor Green
}

# 4. Create Desktop & Start Menu Shortcuts via WScript.Shell
$WshShell = New-Object -ComObject WScript.Shell

# Desktop Shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = $WshShell.CreateShortcut("$DesktopPath\CyberSpring.lnk")
$DesktopShortcut.TargetPath = "$InstallDir\cyberspring.exe"
$DesktopShortcut.Arguments = "-gui"
$DesktopShortcut.WorkingDirectory = "$InstallDir"
$DesktopShortcut.Description = "CyberSpring SOC Controlling Center & SAST Scanner"
if (Test-Path "$InstallDir\icon.ico") {
    $DesktopShortcut.IconLocation = "$InstallDir\icon.ico, 0"
}
$DesktopShortcut.Save()
Write-Host "[+] Desktop shortcut created at $DesktopPath\CyberSpring.lnk" -ForegroundColor Green

# Start Menu Shortcut
$StartMenuPath = [Environment]::GetFolderPath("Programs")
$StartShortcut = $WshShell.CreateShortcut("$StartMenuPath\CyberSpring.lnk")
$StartShortcut.TargetPath = "$InstallDir\cyberspring.exe"
$StartShortcut.Arguments = "-gui"
$StartShortcut.WorkingDirectory = "$InstallDir"
$StartShortcut.Description = "CyberSpring SOC Controlling Center & SAST Scanner"
if (Test-Path "$InstallDir\icon.ico") {
    $StartShortcut.IconLocation = "$InstallDir\icon.ico, 0"
}
$StartShortcut.Save()
Write-Host "[+] Start Menu shortcut created at $StartMenuPath\CyberSpring.lnk" -ForegroundColor Green

Write-Host ""
Write-Host "[SUCCESS] CyberSpring has been installed successfully!" -ForegroundColor Green
Write-Host "----------------------------------------------------------"
Write-Host "You can now run 'cyberspring' in any PowerShell or Command Prompt,"
Write-Host "or double-click the CyberSpring shortcut on your Desktop."
Write-Host "----------------------------------------------------------"
