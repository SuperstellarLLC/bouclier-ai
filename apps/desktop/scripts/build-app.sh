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

# PromptGuard assets are generated and gitignored, so a local file's mere
# presence is not release provenance. Verify the exact reviewed file set before
# SwiftPM can copy it. Unsigned CI/dev packages may omit the gated model and use
# the product's documented regex-only fallback; signed releases may not.
PROMPTGUARD_PACKAGE="$PROJECT_DIR/Sources/Bouclier/Resources/PromptGuard2.mlpackage"
PROMPTGUARD_TOKENIZER="$PROJECT_DIR/Sources/Bouclier/Resources/PromptGuardTokenizer"
PROMPTGUARD_VERIFIER="$SCRIPT_DIR/verify-promptguard-artifacts.py"
INCLUDE_PROMPTGUARD=false
if [ -e "$PROMPTGUARD_PACKAGE" ] || [ -L "$PROMPTGUARD_PACKAGE" ] \
  || [ -e "$PROMPTGUARD_TOKENIZER" ] || [ -L "$PROMPTGUARD_TOKENIZER" ]; then
  python3 "$PROMPTGUARD_VERIFIER"
  INCLUDE_PROMPTGUARD=true
elif [ "$SIGN" = true ]; then
  echo "ERROR: signed builds require the reviewed PromptGuard model and tokenizer." >&2
  echo "       Run $SCRIPT_DIR/ensure-model.sh first." >&2
  exit 1
fi

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
cp "$BUILD_DIR/bouclier-cli" "$CONTENTS/MacOS/"

# SwiftPM resources. This bundle is load-bearing: it contains the complete
# detector set and classifier/tokenizer assets. Shipping without it silently
# reduces the product to the emergency fallback patterns (and can make the
# generated Bundle.module accessor fatal on another Mac), so absence is a
# release error rather than an optional dev convenience.
RESOURCE_BUNDLE="$BUILD_DIR/Bouclier_Bouclier.bundle"
SOURCE_PATTERNS="$PROJECT_DIR/Sources/Bouclier/Resources/patterns.json"
BUILT_PATTERNS="$RESOURCE_BUNDLE/Resources/patterns.json"
if [ ! -f "$SOURCE_PATTERNS" ] || [ ! -f "$BUILT_PATTERNS" ]; then
  echo "ERROR: SwiftPM resource bundle or patterns.json is missing at $RESOURCE_BUNDLE" >&2
  exit 1
fi
if ! cmp -s "$SOURCE_PATTERNS" "$BUILT_PATTERNS"; then
  echo "ERROR: SwiftPM resource bundle contains a stale patterns.json" >&2
  exit 1
fi
if [ "$INCLUDE_PROMPTGUARD" = true ]; then
  python3 "$PROMPTGUARD_VERIFIER" --resources-dir "$RESOURCE_BUNDLE/Resources"
fi

PACKAGED_RESOURCE_BUNDLE="$CONTENTS/Resources/Bouclier_Bouclier.bundle"
mkdir -p "$PACKAGED_RESOURCE_BUNDLE"
# Hugging Face's local-dir transport metadata can remain in historical source
# trees. It is not a runtime input and must never enter the application bundle.
rsync -a --exclude='.cache' "$RESOURCE_BUNDLE/" "$PACKAGED_RESOURCE_BUNDLE/"

# SwiftPM can retain a stale copied resource after a source-side model is
# removed. Do not let an unsigned fallback build accidentally package it.
if [ "$INCLUDE_PROMPTGUARD" = false ]; then
  rm -rf "$PACKAGED_RESOURCE_BUNDLE/Resources/PromptGuard2.mlpackage"
  rm -rf "$PACKAGED_RESOURCE_BUNDLE/Resources/PromptGuard2.mlmodelc"
  rm -rf "$PACKAGED_RESOURCE_BUNDLE/Resources/PromptGuardTokenizer"
else
  python3 "$PROMPTGUARD_VERIFIER" --resources-dir "$PACKAGED_RESOURCE_BUNDLE/Resources"
fi

PACKAGED_PATTERNS="$PACKAGED_RESOURCE_BUNDLE/Resources/patterns.json"
if [ ! -f "$PACKAGED_PATTERNS" ] || ! cmp -s "$SOURCE_PATTERNS" "$PACKAGED_PATTERNS"; then
  echo "ERROR: packaged detector resources could not be verified" >&2
  exit 1
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
ML_DIR="$PACKAGED_RESOURCE_BUNDLE/Resources"
PROMPTGUARD_PACKAGING="absent"
if [ -d "$ML_DIR/PromptGuard2.mlpackage" ]; then
  if command -v xcrun &>/dev/null && xcrun --find coremlcompiler &>/dev/null; then
    echo "Compiling PromptGuard2.mlpackage → .mlmodelc ..."
    xcrun coremlcompiler compile "$ML_DIR/PromptGuard2.mlpackage" "$ML_DIR/"
    # Drop the raw source to save ~60MB of duplicated weights in the DMG
    rm -rf "$ML_DIR/PromptGuard2.mlpackage"
    PROMPTGUARD_PACKAGING="compiled"
    echo "  ✓ Compiled and dropped raw .mlpackage"
  else
    PROMPTGUARD_PACKAGING="raw"
    echo "  ⚠ xcrun coremlcompiler unavailable — shipping raw .mlpackage; app will compile at first launch"
  fi
fi
if [ "$INCLUDE_PROMPTGUARD" = true ] && [ "$PROMPTGUARD_PACKAGING" = "absent" ]; then
  echo "ERROR: verified PromptGuard source disappeared during packaging" >&2
  exit 1
fi

PACKAGED_CACHE=$(find "$APP" -type d -name .cache -print -quit)
if [ -n "$PACKAGED_CACHE" ]; then
  echo "ERROR: cache metadata was packaged at $PACKAGED_CACHE" >&2
  exit 1
fi

# App icon
if [ -f "$PROJECT_DIR/icon/Bouclier.icns" ]; then
  cp "$PROJECT_DIR/icon/Bouclier.icns" "$CONTENTS/Resources/AppIcon.icns"
fi

# Project license plus the complete, committed runtime attribution set. The
# standalone verifier checks every copied byte against its reviewed checksum,
# so adding, removing, or changing a dependency license is a deliberate
# release change rather than a best-effort copy.
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"
for compliance_source in \
  "$REPO_ROOT/LICENSE" \
  "$REPO_ROOT/NOTICE.txt" \
  "$REPO_ROOT/LICENSES/THIRD-PARTY-NOTICES.txt"; do
  if [ ! -f "$compliance_source" ] || [ -L "$compliance_source" ]; then
    echo "ERROR: required compliance file is missing or symlinked: $compliance_source" >&2
    exit 1
  fi
done
LICENSE_SYMLINK=$(find "$REPO_ROOT/LICENSES" -type l -print -quit)
if [ -n "$LICENSE_SYMLINK" ]; then
  echo "ERROR: compliance assets must not contain symlinks: $LICENSE_SYMLINK" >&2
  exit 1
fi
cp "$REPO_ROOT/LICENSE" "$CONTENTS/Resources/LICENSE.txt"
cp "$REPO_ROOT/NOTICE.txt" "$CONTENTS/Resources/NOTICE.txt"
mkdir -p "$CONTENTS/Resources/LICENSES"
cp -R "$REPO_ROOT/LICENSES/." "$CONTENTS/Resources/LICENSES/"

# Sparkle framework
mkdir -p "$CONTENTS/Frameworks"
SPARKLE_PATH=$(find "$PROJECT_DIR/.build/artifacts" -name "Sparkle.framework" -type d -print -quit)
if [ -z "$SPARKLE_PATH" ]; then
  echo "ERROR: Sparkle.framework is missing from SwiftPM build artifacts" >&2
  exit 1
fi
cp -R "$SPARKLE_PATH" "$CONTENTS/Frameworks/"
echo "Bundled Sparkle.framework"

# Fix rpath so the binary can find Sparkle.framework at runtime
install_name_tool -add_rpath @executable_path/../Frameworks "$CONTENTS/MacOS/Bouclier" 2>/dev/null || true

# `swift build` can embed an Xcode-toolchain rpath from the build machine.
# Remove every non-system absolute/unknown rpath before distribution; required
# libraries must resolve either from macOS or from within this app bundle.
for executable in \
  "$CONTENTS/MacOS/Bouclier" \
  "$CONTENTS/MacOS/bouclier-ai-mcp-wrapper" \
  "$CONTENTS/MacOS/bouclier-cli"; do
  while IFS= read -r rpath; do
    case "$rpath" in
      /System/Library/*|/usr/lib/*|@loader_path*|@executable_path*) ;;
      *)
        echo "Removing non-portable rpath from $(basename "$executable"): $rpath"
        install_name_tool -delete_rpath "$rpath" "$executable"
        ;;
    esac
  done < <(
    otool -l "$executable" | awk '
      $1 == "cmd" && $2 == "LC_RPATH" { want_path = 1; next }
      want_path && $1 == "path" { print $2; want_path = 0 }
    '
  )
done

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
    <key>LSMinimumSystemVersion</key><string>15.0</string>
    <key>NSHumanReadableCopyright</key><string>Copyright 2026 Superstellar LLC</string>
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

if [ "$SIGN" = true ] && [ -f "$APP_PROFILE" ]; then
  cp "$APP_PROFILE" "$CONTENTS/embedded.provisionprofile"
  echo "Embedded app provisioning profile"
elif [ "$SIGN" = true ]; then
  echo "ERROR: App provisioning profile not found at $APP_PROFILE"
  echo "Download from: https://developer.apple.com/account/resources/profiles/list"
  exit 1
else
  echo "Unsigned build: provisioning profile not required"
fi

VERIFY_APP_ARGS=("$APP")
if [ "$INCLUDE_PROMPTGUARD" = true ]; then
  VERIFY_APP_ARGS+=(--require-promptguard)
  if [ "$PROMPTGUARD_PACKAGING" = "raw" ]; then
    VERIFY_APP_ARGS+=(--allow-raw-promptguard)
  fi
fi
python3 "$SCRIPT_DIR/verify-app-bundle.py" "${VERIFY_APP_ARGS[@]}"

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
  # The read-only MCP status server and the `bouclier` CLI (built as
  # bouclier-cli — see Package.swift) both read the local status snapshot.
  # Neither touches the Keychain, so they need no special entitlement —
  # least privilege.
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-ai-mcp-wrapper"
  $CODESIGN "$IDENTITY" "$CONTENTS/MacOS/bouclier-cli"

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
