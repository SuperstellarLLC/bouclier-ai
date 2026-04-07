#!/bin/bash
set -euo pipefail

# Builds the Bouclier-ai.app bundle with all binaries and the embedded System Extension.
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
APP="$OUTPUT_DIR/Bouclier-ai.app"

rm -rf "$APP"

# ── Main App Bundle ─────────────────────────────
CONTENTS="$APP/Contents"
mkdir -p "$CONTENTS/MacOS"
mkdir -p "$CONTENTS/Resources"
mkdir -p "$CONTENTS/Library/SystemExtensions"

# Binaries
cp "$BUILD_DIR/Bouclier" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-ai-mcp-wrapper" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-ai-env" "$CONTENTS/MacOS/"

# Resources (patterns.json bundle)
if [ -d "$BUILD_DIR/Bouclier_Bouclier.bundle" ]; then
  cp -r "$BUILD_DIR/Bouclier_Bouclier.bundle" "$CONTENTS/Resources/"
fi

# App icon
if [ -f "$PROJECT_DIR/icon/Bouclier.icns" ]; then
  cp "$PROJECT_DIR/icon/Bouclier.icns" "$CONTENTS/Resources/AppIcon.icns"
fi

# Sparkle framework
mkdir -p "$CONTENTS/Frameworks"
SPARKLE_PATH=$(find "$PROJECT_DIR/.build/artifacts" -name "Sparkle.framework" -type d | head -1)
if [ -n "$SPARKLE_PATH" ]; then
  cp -R "$SPARKLE_PATH" "$CONTENTS/Frameworks/"
  echo "Bundled Sparkle.framework"
fi

# Fix rpath so the binary can find Sparkle.framework at runtime
install_name_tool -add_rpath @executable_path/../Frameworks "$CONTENTS/MacOS/Bouclier" 2>/dev/null || true

# Info.plist
cat > "$CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Bouclier.ai</string>
    <key>CFBundleDisplayName</key><string>Bouclier.ai</string>
    <key>CFBundleIdentifier</key><string>ai.bouclier.app</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>Bouclier</string>
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
    <string>https://www.bouclier.ai/appcast.xml</string>
    <key>SUEnableAutomaticChecks</key>
    <true/>
</dict>
</plist>
EOF

# ── System Extension Bundle ─────────────────────
SYSEXT="$CONTENTS/Library/SystemExtensions/ai.bouclier.app.extension.systemextension"
SYSEXT_CONTENTS="$SYSEXT/Contents"
mkdir -p "$SYSEXT_CONTENTS/MacOS"

cp "$BUILD_DIR/BouclierExtension" "$SYSEXT_CONTENTS/MacOS/"

cat > "$SYSEXT_CONTENTS/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>BouclierExtension</string>
    <key>CFBundleDisplayName</key><string>Bouclier.ai Network Extension</string>
    <key>CFBundleIdentifier</key><string>ai.bouclier.app.extension</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>BouclierExtension</string>
    <key>CFBundlePackageType</key><string>SYSX</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NetworkExtension</key>
    <dict>
        <key>NEProviderClasses</key>
        <dict>
            <key>com.apple.networkextension.transparent-proxy</key>
            <string>BouclierExtension.TransparentProxyProvider</string>
        </dict>
    </dict>
    <key>NSSystemExtensionUsageDescription</key>
    <string>Bouclier.ai intercepts AI API traffic to scan for prompt injections.</string>
</dict>
</plist>
EOF

# ── Embed Provisioning Profiles ─────────────────
APP_PROFILE="$PROJECT_DIR/profiles/Bouclierai.provisionprofile"
EXT_PROFILE="$PROJECT_DIR/profiles/Bouclierai_Network_Extension.provisionprofile"

if [ -f "$APP_PROFILE" ]; then
  cp "$APP_PROFILE" "$CONTENTS/embedded.provisionprofile"
  echo "Embedded app provisioning profile"
fi

if [ -f "$EXT_PROFILE" ]; then
  cp "$EXT_PROFILE" "$SYSEXT_CONTENTS/embedded.provisionprofile"
  echo "Embedded extension provisioning profile"
fi

# ── Code Signing ────────────────────────────────
# Sign inside-out: deepest nested binaries first, main app last.
# Every binary needs --options runtime (hardened runtime) and --timestamp
# for notarization to pass.
if [ "$SIGN" = true ]; then
  IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"
  CODESIGN="codesign --force --options runtime --timestamp --sign"

  # 1. Sparkle nested binaries (innermost first)
  SPARKLE="$CONTENTS/Frameworks/Sparkle.framework/Versions/B"
  if [ -d "$SPARKLE" ]; then
    echo "Signing Sparkle XPC services..."
    $CODESIGN "$IDENTITY" "$SPARKLE/XPCServices/Downloader.xpc"
    $CODESIGN "$IDENTITY" "$SPARKLE/XPCServices/Installer.xpc"

    echo "Signing Sparkle Updater.app..."
    $CODESIGN "$IDENTITY" "$SPARKLE/Updater.app"

    echo "Signing Sparkle Autoupdate..."
    $CODESIGN "$IDENTITY" "$SPARKLE/Autoupdate"

    echo "Signing Sparkle.framework..."
    $CODESIGN "$IDENTITY" "$CONTENTS/Frameworks/Sparkle.framework"
  fi

  # 2. Helper executables
  echo "Signing helper binaries..."
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-ai-mcp-wrapper"
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-ai-env"

  # 3. System Extension
  echo "Signing System Extension..."
  $CODESIGN "$IDENTITY" \
    --entitlements "$PROJECT_DIR/BouclierExtension.entitlements" \
    "$SYSEXT"

  # 4. Main app (outermost — must be last)
  echo "Signing main app..."
  $CODESIGN "$IDENTITY" \
    --entitlements "$PROJECT_DIR/Bouclier.entitlements" \
    "$APP"

  echo "Verifying signatures..."
  codesign --verify --deep --strict "$APP"
fi

# ── Hide .app extension in Finder ──────────────────
# SetFile -a E marks the extension as hidden so Finder shows
# "Bouclier-ai" instead of "Bouclier-ai.app".
if command -v SetFile &>/dev/null; then
  SetFile -a E "$APP"
fi

# ── Refresh Icon Cache ─────────────────────────────
# macOS aggressively caches app icons. Without this, a previously-seen
# app will keep showing the generic icon even after the .icns is fixed.
touch "$APP"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
if [ -x "$LSREGISTER" ]; then
  "$LSREGISTER" -f "$APP" 2>/dev/null || true
fi

echo ""
echo "Built: $APP"
echo ""
echo "To run in development (requires SIP adjustment for unsigned extensions):"
echo "  systemextensionsctl developer on"
echo "  open $APP"
echo ""
