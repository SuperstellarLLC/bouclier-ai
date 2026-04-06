#!/bin/bash
set -euo pipefail

# Builds the Bouclier.ai.app bundle with all binaries and the embedded System Extension.
#
# Usage:
#   ./scripts/build-app.sh                    # Debug build
#   ./scripts/build-app.sh --release          # Release build
#   ./scripts/build-app.sh --release --sign   # Release + code sign

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

CONFIG="debug"
SIGN=false
VERSION="${VERSION:-0.2.0}"

for arg in "$@"; do
  case "$arg" in
    --release) CONFIG="release" ;;
    --sign) SIGN=true ;;
  esac
done

echo "Building Bouclier.ai ($CONFIG)..."

# Build all targets
swift build -c "$CONFIG"

BUILD_DIR=".build/$CONFIG"
OUTPUT_DIR="$PROJECT_DIR/build"
APP="$OUTPUT_DIR/Bouclier.ai.app"

rm -rf "$APP"

# ── Main App Bundle ─────────────────────────────
CONTENTS="$APP/Contents"
mkdir -p "$CONTENTS/MacOS"
mkdir -p "$CONTENTS/Resources"
mkdir -p "$CONTENTS/Library/SystemExtensions"

# Binaries
cp "$BUILD_DIR/Bouclier.ai" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-mcp-wrapper" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-env" "$CONTENTS/MacOS/"

# Resources (patterns.json bundle)
if [ -d "$BUILD_DIR/Bouclier.ai_Bouclier.ai.bundle" ]; then
  cp -r "$BUILD_DIR/Bouclier.ai_Bouclier.ai.bundle" "$CONTENTS/Resources/"
fi

# App icon
if [ -f "$PROJECT_DIR/icon/Bouclier.ai.icns" ]; then
  cp "$PROJECT_DIR/icon/Bouclier.ai.icns" "$CONTENTS/Resources/AppIcon.icns"
fi

# Sparkle framework
mkdir -p "$CONTENTS/Frameworks"
SPARKLE_PATH=$(find "$PROJECT_DIR/.build/artifacts" -name "Sparkle.framework" -type d | head -1)
if [ -n "$SPARKLE_PATH" ]; then
  cp -R "$SPARKLE_PATH" "$CONTENTS/Frameworks/"
  echo "Bundled Sparkle.framework"
fi

# Fix rpath so the binary can find Sparkle.framework at runtime
install_name_tool -add_rpath @executable_path/../Frameworks "$CONTENTS/MacOS/Bouclier.ai" 2>/dev/null || true

# Info.plist
cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Bouclier.ai</string>
    <key>CFBundleDisplayName</key><string>Bouclier.ai</string>
    <key>CFBundleIdentifier</key><string>com.bouclier.app</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>Bouclier.ai</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHumanReadableCopyright</key><string>Copyright 2026 Bouclier.ai</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>NSSystemExtensionUsageDescription</key>
    <string>Bouclier.ai needs a system extension to intercept AI API traffic for prompt injection scanning.</string>
    <key>SUPublicEDKey</key>
    <string>QNMtWO7H9Z9Hv1J9bAsunleicPvJVP2bMJQezjV3vmM=</string>
    <key>SUFeedURL</key>
    <string>https://bouclier.ai/appcast.xml</string>
    <key>SUEnableAutomaticChecks</key>
    <true/>
</dict>
</plist>
EOF

# ── System Extension Bundle ─────────────────────
SYSEXT="$CONTENTS/Library/SystemExtensions/com.bouclier.app.extension.systemextension"
SYSEXT_CONTENTS="$SYSEXT/Contents"
mkdir -p "$SYSEXT_CONTENTS/MacOS"

cp "$BUILD_DIR/Bouclier.aiExtension" "$SYSEXT_CONTENTS/MacOS/"

cat > "$SYSEXT_CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Bouclier.aiExtension</string>
    <key>CFBundleDisplayName</key><string>Bouclier.ai Network Extension</string>
    <key>CFBundleIdentifier</key><string>com.bouclier.app.extension</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>Bouclier.aiExtension</string>
    <key>CFBundlePackageType</key><string>SYSX</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NetworkExtension</key>
    <dict>
        <key>NEProviderClasses</key>
        <dict>
            <key>com.apple.networkextension.transparent-proxy</key>
            <string>Bouclier.aiExtension.TransparentProxyProvider</string>
        </dict>
    </dict>
    <key>NSSystemExtensionUsageDescription</key>
    <string>Bouclier.ai intercepts AI API traffic to scan for prompt injections.</string>
</dict>
</plist>
EOF

# ── Embed Provisioning Profiles ─────────────────
APP_PROFILE="$PROJECT_DIR/profiles/Bouclier.ai.provisionprofile"
EXT_PROFILE="$PROJECT_DIR/profiles/Bouclier.ai_Network_Extension.provisionprofile"

if [ -f "$APP_PROFILE" ]; then
  cp "$APP_PROFILE" "$CONTENTS/embedded.provisionprofile"
  echo "Embedded app provisioning profile"
fi

if [ -f "$EXT_PROFILE" ]; then
  cp "$EXT_PROFILE" "$SYSEXT_CONTENTS/embedded.provisionprofile"
  echo "Embedded extension provisioning profile"
fi

# ── Code Signing ────────────────────────────────
if [ "$SIGN" = true ]; then
  IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"

  # Sign Sparkle framework first (innermost)
  if [ -d "$CONTENTS/Frameworks/Sparkle.framework" ]; then
    echo "Signing Sparkle framework..."
    codesign --force --options runtime \
      --sign "$IDENTITY" \
      "$CONTENTS/Frameworks/Sparkle.framework"
  fi

  echo "Signing System Extension..."
  codesign --force --options runtime \
    --sign "$IDENTITY" \
    --entitlements "$PROJECT_DIR/Bouclier.aiExtension.entitlements" \
    "$SYSEXT"

  echo "Signing main app..."
  codesign --force --options runtime \
    --sign "$IDENTITY" \
    --entitlements "$PROJECT_DIR/Bouclier.ai.entitlements" \
    "$APP"

  echo "Verifying signatures..."
  codesign --verify --deep --strict "$APP"
fi

echo ""
echo "Built: $APP"
echo ""
echo "To run in development (requires SIP adjustment for unsigned extensions):"
echo "  systemextensionsctl developer on"
echo "  open $APP"
echo ""
