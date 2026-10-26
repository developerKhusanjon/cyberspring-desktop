#!/usr/bin/env bash
# ==============================================================================
# 🗑️ CyberSpring Uninstaller for macOS and Linux
# ==============================================================================
set -e

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

echo -e "${CYAN}🗑️  Uninstalling CyberSpring...${RESET}"

# Stop any running instances first
if [ -x "./down.sh" ]; then
    ./down.sh >/dev/null 2>&1 || true
fi

OS_TYPE="$(uname -s)"

# Remove CLI binaries
for bin_path in "/usr/local/bin/cyberspring" "$HOME/.local/bin/cyberspring"; do
    if [ -f "$bin_path" ]; then
        if [ -w "$bin_path" ]; then
            rm -f "$bin_path"
        elif command -v sudo >/dev/null 2>&1; then
            sudo rm -f "$bin_path"
        fi
        echo -e "${GREEN}Removed $bin_path${RESET}"
    fi
done

# macOS specific cleanup
if [ "$OS_TYPE" = "Darwin" ]; then
    if [ -d "/Applications/CyberSpring.app" ]; then
        rm -rf "/Applications/CyberSpring.app" 2>/dev/null || sudo rm -rf "/Applications/CyberSpring.app" 2>/dev/null || true
        echo -e "${GREEN}Removed /Applications/CyberSpring.app${RESET}"
    fi
fi

# Linux specific cleanup
if [ "$OS_TYPE" = "Linux" ]; then
    DESKTOP_FILE="$HOME/.local/share/applications/cyberspring.desktop"
    ICON_FILE="$HOME/.local/share/icons/hicolor/512x512/apps/cyberspring.png"

    if [ -f "$DESKTOP_FILE" ]; then
        rm -f "$DESKTOP_FILE"
        echo -e "${GREEN}Removed $DESKTOP_FILE${RESET}"
    fi
    if [ -f "$ICON_FILE" ]; then
        rm -f "$ICON_FILE"
        echo -e "${GREEN}Removed $ICON_FILE${RESET}"
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
    fi
fi

echo -e "${GREEN}✅ CyberSpring has been uninstalled successfully.${RESET}"
