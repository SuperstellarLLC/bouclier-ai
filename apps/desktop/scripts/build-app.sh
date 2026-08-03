#!/bin/bash
set -euo pipefail

# Builds the Bouclier-ai.app bundle with all binaries.
#
# Usage:
#   ./scripts/build-app.sh                    # Debug build
#   ./scripts/build-app.sh --release          # Release build
#   ./scripts/build-app.sh --release --sign   # Release + code sign

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"
cd "$PROJECT_DIR"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

CONFIG="debug"
SIGN=false

for arg in "$@"; do
  case "$arg" in
    --release) CONFIG="release" ;;
    --sign) SIGN=true ;;
  esac
done

# VERSION is usually set by release.sh; when build-app.sh is invoked
# directly (debug builds), default to the current released version so
# the plist stays coherent with the rest of the repo. No prompt — this
# script runs in tight dev loops and shouldn't block on input.
if [ -z "${VERSION:-}" ]; then
  VERSION=$(current_app_version "$SITE_DIR/src/lib/constants.ts")
  VERSION="${VERSION:-0.0.0}"
fi

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

# Binaries
cp "$BUILD_DIR/Bouclier" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-ai-mcp-wrapper" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-ai-env" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-ai-secrets-mcp" "$CONTENTS/MacOS/"
cp "$BUILD_DIR/bouclier-cli" "$CONTENTS/MacOS/"

# Resources (patterns.json bundle)
if [ -d "$BUILD_DIR/Bouclier_Bouclier.bundle" ]; then
  cp -r "$BUILD_DIR/Bouclier_Bouclier.bundle" "$CONTENTS/Resources/"
fi

# Compile PromptGuard2.mlpackage → PromptGuard2.mlmodelc so CoreML can
# load it at runtime. SPM's .copy("Resources") ships the raw .mlpackage;
# Xcode auto-compiles but swift-build does not, and CoreML refuses to
# load a raw .mlpackage ("Compile the model with Xcode or
# MLModel.compileModel(at:)"). Doing it here (once at build) avoids the
# ~1-2s runtime compile on first launch — and the .mlpackage was
# silently unusable for every build from v0.2.6 through v0.2.9.
#
# The model is produced by ensure-model.sh (run from release.sh) before
# `swift build`; when it's absent (a normal dev build without HF access)
# this no-ops and MLClassifier degrades to regex-only, which is fine.
ML_DIR="$CONTENTS/Resources/Bouclier_Bouclier.bundle/Resources"
if [ -d "$ML_DIR/PromptGuard2.mlpackage" ]; then
  if command -v xcrun &>/dev/null && xcrun --find coremlcompiler &>/dev/null; then
    echo "Compiling PromptGuard2.mlpackage → .mlmodelc ..."
    xcrun coremlcompiler compile "$ML_DIR/PromptGuard2.mlpackage" "$ML_DIR/"
    # Drop the raw source to save ~60MB of duplicated weights in the DMG
    rm -rf "$ML_DIR/PromptGuard2.mlpackage"
    echo "  ✓ Compiled and dropped raw .mlpackage"
  else
    echo "  ⚠ xcrun coremlcompiler unavailable — shipping raw .mlpackage; app will compile at first launch"
  fi
fi

# App icon
if [ -f "$PROJECT_DIR/icon/Bouclier.icns" ]; then
  cp "$PROJECT_DIR/icon/Bouclier.icns" "$CONTENTS/Resources/AppIcon.icns"
fi

# Third-party notices and licenses required by bundled model materials
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"
if [ -f "$REPO_ROOT/NOTICE.txt" ]; then
  cp "$REPO_ROOT/NOTICE.txt" "$CONTENTS/Resources/NOTICE.txt"
fi
if [ -f "$REPO_ROOT/LICENSES/Llama-4-Community-License.txt" ]; then
  mkdir -p "$CONTENTS/Resources/LICENSES"
  cp "$REPO_ROOT/LICENSES/Llama-4-Community-License.txt" \
    "$CONTENTS/Resources/LICENSES/Llama-4-Community-License.txt"
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
    <key>CFBundleName</key><string>Bouclier-ai</string>
    <key>CFBundleDisplayName</key><string>Bouclier-ai</string>
    <key>CFBundleIdentifier</key><string>ai.bouclier.app</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleExecutable</key><string>Bouclier</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHumanReadableCopyright</key><string>Copyright 2026 Bouclier.ai</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>SUPublicEDKey</key>
    <string>QNMtWO7H9Z9Hv1J9bAsunleicPvJVP2bMJQezjV3vmM=</string>
    <key>SUFeedURL</key>
    <string>https://www.bouclier.ai/appcast.xml</string>
    <key>SUEnableAutomaticChecks</key>
    <true/>
</dict>
</plist>
EOF

# ── Embed Provisioning Profile ──────────────────
APP_PROFILE="$PROJECT_DIR/profiles/Bouclierai.provisionprofile"

if [ -f "$APP_PROFILE" ]; then
  cp "$APP_PROFILE" "$CONTENTS/embedded.provisionprofile"
  echo "Embedded app provisioning profile"
else
  echo "ERROR: App provisioning profile not found at $APP_PROFILE"
  echo "Download from: https://developer.apple.com/account/resources/profiles/list"
  exit 1
fi

# ── Hide .app extension in Finder ──────────────────
# Must happen BEFORE signing — SetFile adds resource fork metadata
# that would break the signature if applied after.
if command -v SetFile &>/dev/null; then
  SetFile -a E "$APP"
fi
# Clean any extended attributes that interfere with codesign
xattr -cr "$APP"

# ── Code Signing ────────────────────────────────
# Sign inside-out: deepest nested binaries first, main app last.
# Every binary needs --options runtime (hardened runtime) and --timestamp
# for notarization to pass.
if [ "$SIGN" = true ]; then
  IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"
  CODESIGN="codesign --force --options runtime --timestamp --sign"
  # Preserve-metadata variant for Sparkle components. They ship
  # pre-signed by the Sparkle project with whatever entitlements that
  # release needs; a plain `--force` re-sign wipes them. Harmless for
  # our non-sandboxed case today (Sparkle ships empty entitlements for
  # this path), defensive if a future Sparkle version starts relying on
  # something specific.
  CODESIGN_PRESERVE="codesign --force --preserve-metadata=entitlements --options runtime --timestamp --sign"

  # 1. Sparkle nested binaries (innermost first)
  SPARKLE="$CONTENTS/Frameworks/Sparkle.framework/Versions/B"
  if [ -d "$SPARKLE" ]; then
    echo "Signing Sparkle XPC services (preserving entitlements)..."
    $CODESIGN_PRESERVE "$IDENTITY" "$SPARKLE/XPCServices/Downloader.xpc"
    $CODESIGN_PRESERVE "$IDENTITY" "$SPARKLE/XPCServices/Installer.xpc"

    echo "Signing Sparkle Updater.app (preserving entitlements)..."
    $CODESIGN_PRESERVE "$IDENTITY" "$SPARKLE/Updater.app"

    echo "Signing Sparkle Autoupdate (preserving entitlements)..."
    $CODESIGN_PRESERVE "$IDENTITY" "$SPARKLE/Autoupdate"

    echo "Signing Sparkle.framework..."
    $CODESIGN "$IDENTITY" "$CONTENTS/Frameworks/Sparkle.framework"
  fi

  # 2. Helper executables
  echo "Signing helper binaries..."
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-ai-mcp-wrapper"
  # The `bouclier` CLI (built as bouclier-cli — see Package.swift) reads
  # status + drives the approval IPC, but never touches the Keychain (no
  # secret-value path), so it needs no special entitlement — least privilege.
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-cli"
  # env + secrets-mcp share the app's Keychain access group so the agent
  # can use stored secrets without a per-access prompt (see
  # BouclierHelpers.entitlements).
  $CODESIGN "$IDENTITY" \
    --entitlements "$PROJECT_DIR/BouclierHelpers.entitlements" \
    "$CONTENTS/MacOS/bouclier-ai-env"
  $CODESIGN "$IDENTITY" \
    --entitlements "$PROJECT_DIR/BouclierHelpers.entitlements" \
    "$CONTENTS/MacOS/bouclier-ai-secrets-mcp"

  # 3. Main app (outermost — must be last)
  echo "Signing main app..."
  $CODESIGN "$IDENTITY" \
    --entitlements "$PROJECT_DIR/Bouclier.entitlements" \
    "$APP"

  echo "Verifying signatures..."
  codesign --verify --deep --strict "$APP"
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
echo "To run in development:"
echo "  open $APP"
echo ""
