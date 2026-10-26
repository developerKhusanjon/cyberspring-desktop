#!/usr/bin/env bash
# ==============================================================================
# 🛑 CyberSpring — Stop / Down Server Script (macOS & Linux)
# ==============================================================================
set -e
cd "$(dirname "$0")"

PORT=${CYBERSPRING_PORT:-8787}
echo -e "\033[1;33m🛑 Bringing down CyberSpring server (Port ${PORT})...\033[0m"

# Find process listening on port 8787
PIDS=$(lsof -ti tcp:${PORT} -sTCP:LISTEN 2>/dev/null || true)

if [ -n "$PIDS" ]; then
    kill -15 $PIDS 2>/dev/null || kill -9 $PIDS 2>/dev/null
    sleep 0.5
    echo -e "\033[1;32m✅ CyberSpring server stopped successfully (PID: $PIDS).\033[0m"
else
    # Fallback to kill by process name if port wasn't caught
    PKILLED=0
    pkill -f "cyberspring -gui" 2>/dev/null && PKILLED=1 || true
    if [ "$PKILLED" -eq 1 ]; then
        echo -e "\033[1;32m✅ CyberSpring process terminated.\033[0m"
    else
        echo -e "\033[36mℹ️ CyberSpring server is already down (port ${PORT} is free).\033[0m"
    fi
fi
