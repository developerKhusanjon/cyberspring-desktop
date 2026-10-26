# ==============================================================================
# 🚀 CyberSpring — Start / Up Server Script for Windows (PowerShell)
# ==============================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir
& ".\run.ps1"
