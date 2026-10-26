#!/usr/bin/env bash
# ==============================================================================
# 🍎 CyberSpring — macOS Application Bundle (.app) Builder
# ==============================================================================
set -e
cd "$(dirname "$0")/.."

APP_DIR="bin/CyberSpring.app"
echo -e "\033[1;36m🔨 Packaging CyberSpring.app for macOS...\033[0m"

# Ensure binary is built
if [ ! -f bin/cyberspring-darwin-arm64 ] && [ ! -f cyberspring ]; then
    make build
fi

SRC_BIN="cyberspring"
if [ -f bin/cyberspring-darwin-arm64 ]; then
    SRC_BIN="bin/cyberspring-darwin-arm64"
fi

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# 1. Copy Executable
cp "$SRC_BIN" "$APP_DIR/Contents/MacOS/cyberspring"
chmod +x "$APP_DIR/Contents/MacOS/cyberspring"

# 2. Copy App Icon
if [ -f assets/icon.icns ]; then
    cp assets/icon.icns "$APP_DIR/Contents/Resources/AppIcon.icns"
elif [ -f assets/icon.png ]; then
    cp assets/icon.png "$APP_DIR/Contents/Resources/AppIcon.png"
fi

# 3. Create Info.plist
cat <<EOF > "$APP_DIR/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>cyberspring</string>
    <key>CFBundleIdentifier</key>
    <string>com.cyberspring.soc</string>
    <key>CFBundleName</key>
    <string>CyberSpring</string>
    <key>CFBundleDisplayName</key>
    <string>CyberSpring</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
EOF

echo -e "\033[1;32m✅ Successfully created $APP_DIR\033[0m"
echo -e "\033[2mTo install into /Applications: cp -R $APP_DIR /Applications/\033[0m"
