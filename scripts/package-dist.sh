#!/usr/bin/env bash
# ==============================================================================
# 📦 CyberSpring Release Package Generator
# ==============================================================================
# Packages standalone, zero-dependency release archives for Windows, macOS,
# and Linux into the dist/ directory.
# ==============================================================================

set -e
cd "$(dirname "$0")/.."

VERSION="v1.0.0"
DIST_DIR="dist"
BUILD_DIR="dist/build"

echo -e "\033[1;36m🔨 Packaging CyberSpring ${VERSION} Standalone Distributions...\033[0m"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR"

# Ensure all cross-platform binaries exist
make cross-compile

# 1. macOS ARM64 (Apple Silicon)
echo -e "\n\033[1;34m🍏 Packaging macOS ARM64...\033[0m"
PKG_MAC_ARM="$BUILD_DIR/cyberspring-${VERSION}-macos-arm64"
mkdir -p "$PKG_MAC_ARM" "$PKG_MAC_ARM/assets" "$PKG_MAC_ARM/bin"
cp bin/cyberspring-darwin-arm64 "$PKG_MAC_ARM/bin/cyberspring"
cp bin/cyberspring-darwin-arm64 "$PKG_MAC_ARM/cyberspring"
cp -R bin/CyberSpring.app "$PKG_MAC_ARM/"
cp assets/icon.icns assets/icon.png "$PKG_MAC_ARM/assets/" 2>/dev/null || true
cp install.sh uninstall.sh up.sh down.sh README.md "$PKG_MAC_ARM/"
chmod +x "$PKG_MAC_ARM/"*.sh "$PKG_MAC_ARM/cyberspring"
tar -czf "$DIST_DIR/cyberspring-${VERSION}-macos-arm64.tar.gz" -C "$BUILD_DIR" "cyberspring-${VERSION}-macos-arm64"
echo -e "\033[1;32m✅ Created $DIST_DIR/cyberspring-${VERSION}-macos-arm64.tar.gz\033[0m"

# 2. macOS AMD64 (Intel)
echo -e "\n\033[1;34m🍏 Packaging macOS AMD64 (Intel)...\033[0m"
PKG_MAC_INTEL="$BUILD_DIR/cyberspring-${VERSION}-macos-amd64"
mkdir -p "$PKG_MAC_INTEL" "$PKG_MAC_INTEL/assets" "$PKG_MAC_INTEL/bin"
cp bin/cyberspring-darwin-amd64 "$PKG_MAC_INTEL/bin/cyberspring"
cp bin/cyberspring-darwin-amd64 "$PKG_MAC_INTEL/cyberspring"
# Create intel app bundle
cp -R bin/CyberSpring.app "$PKG_MAC_INTEL/"
cp bin/cyberspring-darwin-amd64 "$PKG_MAC_INTEL/CyberSpring.app/Contents/MacOS/cyberspring"
cp assets/icon.icns assets/icon.png "$PKG_MAC_INTEL/assets/" 2>/dev/null || true
cp install.sh uninstall.sh up.sh down.sh README.md "$PKG_MAC_INTEL/"
chmod +x "$PKG_MAC_INTEL/"*.sh "$PKG_MAC_INTEL/cyberspring"
tar -czf "$DIST_DIR/cyberspring-${VERSION}-macos-amd64.tar.gz" -C "$BUILD_DIR" "cyberspring-${VERSION}-macos-amd64"
echo -e "\033[1;32m✅ Created $DIST_DIR/cyberspring-${VERSION}-macos-amd64.tar.gz\033[0m"

# 3. Linux AMD64 (x86_64)
echo -e "\n\033[1;34m🐧 Packaging Linux AMD64...\033[0m"
PKG_LINUX_AMD64="$BUILD_DIR/cyberspring-${VERSION}-linux-amd64"
mkdir -p "$PKG_LINUX_AMD64" "$PKG_LINUX_AMD64/assets" "$PKG_LINUX_AMD64/bin"
cp bin/cyberspring-linux-amd64 "$PKG_LINUX_AMD64/bin/cyberspring"
cp bin/cyberspring-linux-amd64 "$PKG_LINUX_AMD64/cyberspring"
cp assets/cyberspring.desktop assets/icon.png assets/icon.svg "$PKG_LINUX_AMD64/assets/"
cp install.sh uninstall.sh up.sh down.sh README.md "$PKG_LINUX_AMD64/"
chmod +x "$PKG_LINUX_AMD64/"*.sh "$PKG_LINUX_AMD64/cyberspring"
tar -czf "$DIST_DIR/cyberspring-${VERSION}-linux-amd64.tar.gz" -C "$BUILD_DIR" "cyberspring-${VERSION}-linux-amd64"
echo -e "\033[1;32m✅ Created $DIST_DIR/cyberspring-${VERSION}-linux-amd64.tar.gz\033[0m"

# 4. Linux ARM64 (aarch64)
echo -e "\n\033[1;34m🐧 Packaging Linux ARM64...\033[0m"
PKG_LINUX_ARM64="$BUILD_DIR/cyberspring-${VERSION}-linux-arm64"
mkdir -p "$PKG_LINUX_ARM64" "$PKG_LINUX_ARM64/assets" "$PKG_LINUX_ARM64/bin"
cp bin/cyberspring-linux-arm64 "$PKG_LINUX_ARM64/bin/cyberspring"
cp bin/cyberspring-linux-arm64 "$PKG_LINUX_ARM64/cyberspring"
cp assets/cyberspring.desktop assets/icon.png assets/icon.svg "$PKG_LINUX_ARM64/assets/"
cp install.sh uninstall.sh up.sh down.sh README.md "$PKG_LINUX_ARM64/"
chmod +x "$PKG_LINUX_ARM64/"*.sh "$PKG_LINUX_ARM64/cyberspring"
tar -czf "$DIST_DIR/cyberspring-${VERSION}-linux-arm64.tar.gz" -C "$BUILD_DIR" "cyberspring-${VERSION}-linux-arm64"
echo -e "\033[1;32m✅ Created $DIST_DIR/cyberspring-${VERSION}-linux-arm64.tar.gz\033[0m"

# 5. Windows AMD64
echo -e "\n\033[1;34m🪟 Packaging Windows AMD64...\033[0m"
PKG_WIN="$BUILD_DIR/cyberspring-${VERSION}-windows-amd64"
mkdir -p "$PKG_WIN" "$PKG_WIN/assets" "$PKG_WIN/bin"
cp bin/cyberspring-windows-amd64.exe "$PKG_WIN/bin/cyberspring.exe"
cp bin/cyberspring-windows-amd64.exe "$PKG_WIN/cyberspring.exe"
cp assets/icon.ico assets/icon.png "$PKG_WIN/assets/" 2>/dev/null || true
cp install.bat install.ps1 uninstall.bat uninstall.ps1 run.bat run.ps1 up.bat down.bat README.md "$PKG_WIN/"
(cd "$BUILD_DIR" && zip -r -q "../../$DIST_DIR/cyberspring-${VERSION}-windows-amd64.zip" "cyberspring-${VERSION}-windows-amd64")
echo -e "\033[1;32m✅ Created $DIST_DIR/cyberspring-${VERSION}-windows-amd64.zip\033[0m"

# Cleanup intermediate staging directory
rm -rf "$BUILD_DIR"

echo -e "\n\033[1;32m🎉 All standalone distribution packages generated in dist/:\033[0m"
ls -lh "$DIST_DIR"
