#!/usr/bin/env bash
# ==============================================================================
# 🚀 CyberSpring — Start / Up Server Script (macOS & Linux)
# ==============================================================================
set -e
cd "$(dirname "$0")"

PORT=${CYBERSPRING_PORT:-8787}

# 1. Check if server is already running on port
if lsof -ti tcp:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    echo -e "\033[1;33m⚠️ CyberSpring is already running on port ${PORT}.\033[0m"
    echo -e "\033[1;36m🌐 UI Dashboard: http://127.0.0.1:${PORT}\033[0m"
    exit 0
fi

# 2. Build binary if missing
if [ ! -f ./cyberspring ]; then
    echo -e "\033[33m🔨 Building CyberSpring native standalone binary...\033[0m"
    go build -ldflags="-s -w" -o cyberspring cmd/cyberspring/main.go
    echo -e "\033[32m✅ Build complete.\033[0m"
fi

# 3. Check for background / daemon flag
if [ "$1" = "-d" ] || [ "$1" = "--daemon" ] || [ "$1" = "background" ]; then
    echo -e "\033[1;32m🚀 Starting CyberSpring in background daemon mode...\033[0m"
    nohup ./cyberspring -gui -port "${PORT}" > cyberspring.log 2>&1 &
    PID=$!
    sleep 0.8
    echo -e "\033[1;32m✅ CyberSpring started in background (PID: ${PID}).\033[0m"
    echo -e "\033[1;36m🌐 UI Dashboard: http://127.0.0.1:${PORT}\033[0m"
    echo -e "\033[2mLogs: tail -f cyberspring.log\033[0m"
    echo -e "\033[2mTo stop: ./down.sh or make down\033[0m"
else
    echo -e "\033[1;32m🚀 Starting CyberSpring Desktop Hub on http://127.0.0.1:${PORT} ...\033[0m"
    echo -e "\033[2mPress Ctrl+C to terminate or run ./down.sh from another terminal.\033[0m"
    exec ./cyberspring -gui -port "${PORT}"
fi
