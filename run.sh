#!/usr/bin/env bash
# ==============================================================================
# 🌿 CyberSpring — One-Click Desktop Launcher for macOS and Linux
# ==============================================================================
set -e
cd "$(dirname "$0")"

echo -e "\033[1;36m========================================================\033[0m"
echo -e "\033[1;32m  🌿 CyberSpring SOC Controlling Center & SAST Scanner\033[0m"
echo -e "\033[1;37m  Native Desktop Engine (macOS & Linux)\033[0m"
echo -e "\033[1;36m========================================================\033[0m"

# Build binary if not already built or if source files are newer
if [ ! -f ./cyberspring ]; then
    echo -e "\033[33m🔨 Building CyberSpring native standalone binary...\033[0m"
    go build -ldflags="-s -w" -o cyberspring cmd/cyberspring/main.go
    echo -e "\033[32m✅ Build complete.\033[0m"
fi

# Launch in GUI mode (auto-opens default web browser)
PORT=${CYBERSPRING_PORT:-8787}
echo -e "\033[32m🚀 Starting CyberSpring Desktop Hub on http://127.0.0.1:${PORT} ...\033[0m"
exec ./cyberspring -gui -port "${PORT}"
