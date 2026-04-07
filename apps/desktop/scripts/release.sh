#!/bin/bash
set -euo pipefail

# Full release pipeline: build → sign → DMG → notarize → Sparkle → upload → deploy.
#
# Usage:
#   APPLE_ID=you@example.com \
#   DOWNLOAD_BASE_URL=https://xyz.public.blob.vercel-storage.com \
#     ./scripts/release.sh
#
# Prompts for version and app-specific password at runtime.
#
# Prerequisites:
#   - Developer ID identity in Keychain
#   - Sparkle EdDSA key in Keychain
#   - Provisioning profiles in profiles/
#   - App-specific password (appleid.apple.com → App-Specific Passwords)
#   - vercel CLI authenticated

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"

APPLE_ID="${APPLE_ID:?APPLE_ID env var required}"
TEAM_ID="${TEAM_ID:-U86PR842AK}"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL:?DOWNLOAD_BASE_URL env var required}"

read -rp "Version (e.g. 0.2.0): " VERSION
if [ -z "$VERSION" ]; then echo "Version is required."; exit 1; fi

echo -n "App-specific password: "
read -rs APP_PASSWORD
echo ""
if [ -z "$APP_PASSWORD" ]; then echo "Password is required."; exit 1; fi

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
APP="$PROJECT_DIR/build/Bouclier-ai.app"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai v${VERSION} — Release Pipeline"
echo "═══════════════════════════════════════════════"
echo ""

# ── Step 0: Bump version in source files ────────
echo "▸ Bumping version to ${VERSION}..."
sed -i '' "s/APP_VERSION = \".*\"/APP_VERSION = \"${VERSION}\"/" "$REPO_ROOT/apps/site/src/lib/constants.ts"
sed -i '' "s/<key>CFBundleShortVersionString<\/key>.*/<key>CFBundleShortVersionString<\/key>/" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/BouclierExtension/GeneratedInfo.plist"
echo "  ✓ Version bumped in constants.ts + plists"
echo ""

# ── Step 1: Build + Sign ────────────────────────
echo "▸ Step 1/6: Building and signing..."
VERSION="$VERSION" "$SCRIPT_DIR/build-app.sh" --release --sign
echo "  ✓ App built and signed at $APP"
echo ""

# ── Step 2: Create DMG with Applications shortcut ──
echo "▸ Step 2/6: Creating DMG..."
rm -f "$DMG"

# Stage a temp folder with the app + Applications symlink
DMG_STAGE="$PROJECT_DIR/build/dmg-stage"
rm -rf "$DMG_STAGE"
mkdir -p "$DMG_STAGE"
cp -R "$APP" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"

hdiutil create -volname "Bouclier.ai" -srcfolder "$DMG_STAGE" \
  -ov -format UDZO "$DMG" -quiet

rm -rf "$DMG_STAGE"
echo "  ✓ DMG created at $DMG (with Applications shortcut)"
echo ""

# ── Step 3: Notarize ────────────────────────────
echo "▸ Step 3/6: Submitting for notarization..."
xcrun notarytool submit "$DMG" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APP_PASSWORD" \
  --wait
echo ""

echo "  Stapling..."
xcrun stapler staple "$DMG"
echo "  ✓ Notarized and stapled"
echo ""

# ── Step 4: Sparkle sign + appcast ──────────────
echo "▸ Step 4/6: Signing for Sparkle and generating appcast..."
VERSION="$VERSION" DOWNLOAD_BASE_URL="$DOWNLOAD_BASE_URL" "$SCRIPT_DIR/publish-update.sh"
echo ""

# ── Step 5: Upload DMG ──────────────────────────
echo "▸ Step 5/6: Uploading DMG to Vercel Blob..."
if command -v vercel &>/dev/null; then
  vercel blob upload "$DMG" --no-confirm 2>/dev/null || {
    echo "  ⚠ vercel blob upload failed — upload manually:"
    echo "    vercel blob upload $DMG"
  }
else
  echo "  ⚠ vercel CLI not found — upload manually:"
  echo "    vercel blob upload $DMG"
fi
echo ""

# ── Step 6: Deploy site ─────────────────────────
echo "▸ Step 6/6: Deploying site..."
if command -v vercel &>/dev/null; then
  cd "$SITE_DIR"
  vercel --prod --yes 2>/dev/null || {
    echo "  ⚠ vercel deploy failed — deploy manually:"
    echo "    cd $SITE_DIR && vercel --prod"
  }
else
  echo "  ⚠ vercel CLI not found — deploy manually:"
  echo "    cd $SITE_DIR && vercel --prod"
fi
echo ""

echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai v${VERSION} released!"
echo "═══════════════════════════════════════════════"
echo ""
echo "  DMG:     $DMG"
echo "  Appcast: $SITE_DIR/public/appcast.xml"
echo "  Site:    https://www.bouclier.ai"
echo ""
