#!/bin/bash
set -euo pipefail

# Full release pipeline: build → sign → DMG → notarize → Sparkle → upload → deploy.
#
# Usage:
#   VERSION=0.2.0 \
#   APPLE_ID=you@example.com \
#   TEAM_ID=U86PR842AK \
#   DOWNLOAD_BASE_URL=https://xyz.public.blob.vercel-storage.com \
#     ./scripts/release.sh
#
# Prerequisites:
#   - Developer ID identity in Keychain
#   - Sparkle EdDSA key in Keychain
#   - Provisioning profiles in profiles/
#   - notarytool credentials (--apple-id + --team-id, or keychain profile)
#   - vercel CLI authenticated

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"

VERSION="${VERSION:?VERSION env var required (e.g. 0.2.0)}"
APPLE_ID="${APPLE_ID:?APPLE_ID env var required (Apple Developer email)}"
TEAM_ID="${TEAM_ID:-U86PR842AK}"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL:?DOWNLOAD_BASE_URL env var required}"

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
APP="$PROJECT_DIR/build/Bouclier.ai.app"

echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai v${VERSION} — Release Pipeline"
echo "═══════════════════════════════════════════════"
echo ""

# ── Step 1: Build + Sign ────────────────────────
echo "▸ Step 1/6: Building and signing..."
VERSION="$VERSION" "$SCRIPT_DIR/build-app.sh" --release --sign
echo "  ✓ App built and signed at $APP"
echo ""

# ── Step 2: Create DMG ──────────────────────────
echo "▸ Step 2/6: Creating DMG..."
rm -f "$DMG"
hdiutil create -volname "Bouclier.ai" -srcfolder "$APP" \
  -ov -format UDZO "$DMG" -quiet
echo "  ✓ DMG created at $DMG"
echo ""

# ── Step 3: Notarize ────────────────────────────
echo "▸ Step 3/6: Submitting for notarization..."
xcrun notarytool submit "$DMG" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
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
echo "  Site:    https://bouclier.ai"
echo ""
