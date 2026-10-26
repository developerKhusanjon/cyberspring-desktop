#!/usr/bin/env bash
# ==============================================================================
# 🌸 CyberSpring Universal Installer for macOS and Linux
# ==============================================================================
# Automatically detects OS and Architecture, installs the standalone executable,
# registers desktop shortcuts/applications, and configures CLI PATH access.
# Zero external runtime dependencies required.
# ==============================================================================

set -e

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${CYAN}"
echo "   ______      __               _____             _            "
echo "  / ____/_  __/ /_  ___  _____ / ___/____  _____ (_)___  ____ _"
echo " / /   / / / / __ \/ _ \/ ___/ \__ \/ __ \/ ___// / __ \/ __ \`/"
echo "/ /___/ /_/ / /_/ /  __/ /    ___/ / /_/ / /   / / / / / /_/ / "
echo "\____/\__, /_.___/\___/_/    /____/ .___/_/   /_/_/ /_/\__, /  "
echo "     /____/                      /_/                  /____/   "
echo -e "${RESET}"
echo -e "${BOLD}🌸 CyberSpring Standalone Installer (macOS & Linux)${RESET}\n"

# 1. Detect OS
OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

case "$ARCH_TYPE" in
    x86_64|amd64)
        TARGET_ARCH="amd64"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}❌ Unsupported architecture: $ARCH_TYPE${RESET}"
        exit 1
        ;;
esac

echo -e "🖥️  Detected OS:   ${BOLD}${OS_TYPE}${RESET}"
echo -e "⚙️  Architecture:  ${BOLD}${TARGET_ARCH}${RESET} (${ARCH_TYPE})"

# 2. Locate Source Binary
SOURCE_BIN=""
if [ "$OS_TYPE" = "Darwin" ]; then
    CANDIDATES=(
        "$SCRIPT_DIR/bin/cyberspring-darwin-${TARGET_ARCH}"
        "$SCRIPT_DIR/cyberspring-darwin-${TARGET_ARCH}"
        "$SCRIPT_DIR/cyberspring"
        "$SCRIPT_DIR/bin/cyberspring"
    )
elif [ "$OS_TYPE" = "Linux" ]; then
    CANDIDATES=(
        "$SCRIPT_DIR/bin/cyberspring-linux-${TARGET_ARCH}"
        "$SCRIPT_DIR/cyberspring-linux-${TARGET_ARCH}"
        "$SCRIPT_DIR/cyberspring"
        "$SCRIPT_DIR/bin/cyberspring"
    )
else
    echo -e "${RED}❌ For Windows, please run 'install.bat' or 'install.ps1'.${RESET}"
    exit 1
fi

for cand in "${CANDIDATES[@]}"; do
    if [ -f "$cand" ]; then
        SOURCE_BIN="$cand"
        break
    fi
done

if [ -z "$SOURCE_BIN" ]; then
    echo -e "${YELLOW}⚠️ Prebuilt binary not found. Attempting to compile from source...${RESET}"
    if command -v go >/dev/null 2>&1; then
        (cd "$SCRIPT_DIR" && go build -ldflags="-s -w" -o cyberspring ./cmd/cyberspring)
        SOURCE_BIN="$SCRIPT_DIR/cyberspring"
    else
        echo -e "${RED}❌ Prebuilt binary missing and 'go' compiler is not installed.${RESET}"
        echo -e "Please ensure bin/ directory contains prebuilt binaries."
        exit 1
    fi
fi

echo -e "📦 Selected source binary: ${CYAN}${SOURCE_BIN}${RESET}"

# 3. Determine CLI Install Destination
if [ -w "/usr/local/bin" ] || [ "$EUID" -eq 0 ]; then
    CLI_DIR="/usr/local/bin"
    NEED_SUDO=false
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    CLI_DIR="/usr/local/bin"
    NEED_SUDO=true
else
    CLI_DIR="$HOME/.local/bin"
    NEED_SUDO=false
    mkdir -p "$CLI_DIR"
fi

# 4. macOS Installation Flow
if [ "$OS_TYPE" = "Darwin" ]; then
    echo -e "\n${BLUE}🍏 Installing for macOS...${RESET}"
    
    # 4a. Install CyberSpring.app bundle
    APP_BUNDLE="$SCRIPT_DIR/bin/CyberSpring.app"
    if [ ! -d "$APP_BUNDLE" ]; then
        if [ -x "$SCRIPT_DIR/scripts/build-macos-app.sh" ]; then
            echo "Building macOS application bundle..."
            "$SCRIPT_DIR/scripts/build-macos-app.sh"
        fi
    fi

    if [ -d "$APP_BUNDLE" ]; then
        echo "📂 Copying CyberSpring.app to /Applications/..."
        rm -rf "/Applications/CyberSpring.app" 2>/dev/null || sudo rm -rf "/Applications/CyberSpring.app" 2>/dev/null || true
        cp -R "$APP_BUNDLE" "/Applications/" 2>/dev/null || sudo cp -R "$APP_BUNDLE" "/Applications/"
        echo -e "${GREEN}✅ Installed /Applications/CyberSpring.app${RESET}"
    fi

    # 4b. Install CLI tool
    echo "⚡ Installing CLI tool to $CLI_DIR/cyberspring..."
    if [ "$NEED_SUDO" = true ]; then
        sudo cp "$SOURCE_BIN" "$CLI_DIR/cyberspring"
        sudo chmod 755 "$CLI_DIR/cyberspring"
    else
        cp "$SOURCE_BIN" "$CLI_DIR/cyberspring"
        chmod 755 "$CLI_DIR/cyberspring"
    fi
    echo -e "${GREEN}✅ Installed CLI binary to $CLI_DIR/cyberspring${RESET}"

# 5. Linux Installation Flow
elif [ "$OS_TYPE" = "Linux" ]; then
    echo -e "\n${BLUE}🐧 Installing for Linux...${RESET}"

    # 5a. Install CLI binary
    echo "⚡ Installing CLI binary to $CLI_DIR/cyberspring..."
    if [ "$NEED_SUDO" = true ]; then
        sudo cp "$SOURCE_BIN" "$CLI_DIR/cyberspring"
        sudo chmod 755 "$CLI_DIR/cyberspring"
    else
        cp "$SOURCE_BIN" "$CLI_DIR/cyberspring"
        chmod 755 "$CLI_DIR/cyberspring"
    fi
    echo -e "${GREEN}✅ Installed CLI binary to $CLI_DIR/cyberspring${RESET}"

    # 5b. Install Icons & Desktop Entry
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
    mkdir -p "$DESKTOP_DIR" "$ICON_DIR"

    if [ -f "$SCRIPT_DIR/assets/icon.png" ]; then
        cp "$SCRIPT_DIR/assets/icon.png" "$ICON_DIR/cyberspring.png"
        echo -e "${GREEN}✅ Installed desktop icon to $ICON_DIR/cyberspring.png${RESET}"
    fi

    if [ -f "$SCRIPT_DIR/assets/cyberspring.desktop" ]; then
        # Replace Exec with full path if in ~/.local/bin
        DESKTOP_FILE="$DESKTOP_DIR/cyberspring.desktop"
        sed "s|Exec=cyberspring -gui|Exec=$CLI_DIR/cyberspring -gui|g" "$SCRIPT_DIR/assets/cyberspring.desktop" > "$DESKTOP_FILE"
        chmod 644 "$DESKTOP_FILE"
        echo -e "${GREEN}✅ Installed desktop launcher to $DESKTOP_FILE${RESET}"
        
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
        fi
    fi
fi

# 6. Check PATH
if [[ ":$PATH:" != *":$CLI_DIR:"* ]]; then
    echo -e "\n${YELLOW}ℹ️  Notice: $CLI_DIR is not currently in your \$PATH.${RESET}"
    echo -e "Add it to your shell config (~/.bashrc or ~/.zshrc):"
    echo -e "   ${BOLD}export PATH=\"\$PATH:$CLI_DIR\"${RESET}"
fi

# 7. Verification
echo -e "\n${GREEN}🎉 CyberSpring installation completed successfully!${RESET}"
echo -e "----------------------------------------------------------------"
echo -e "• Run in terminal:         ${CYAN}cyberspring${RESET} (or $CLI_DIR/cyberspring)"
echo -e "• Run instant SAST scan:   ${CYAN}cyberspring -scan /path/to/codebase${RESET}"
echo -e "• Stop running server:     ${CYAN}cyberspring down${RESET} (or ./down.sh)"
if [ "$OS_TYPE" = "Darwin" ]; then
    echo -e "• Launch from GUI:         ${CYAN}Open CyberSpring in Finder / Applications${RESET}"
elif [ "$OS_TYPE" = "Linux" ]; then
    echo -e "• Launch from GUI:         ${CYAN}Find CyberSpring in Application Menu${RESET}"
fi
echo -e "----------------------------------------------------------------\n"
