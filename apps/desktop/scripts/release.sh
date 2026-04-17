#!/bin/bash
set -euo pipefail

# Full release pipeline: build → sign → DMG → notarize → Sparkle → upload → deploy.
#
# Usage:
#   ./scripts/release.sh
#
# The script prompts for everything it needs. Any value set in the
# environment beforehand is used without prompting (handy for CI or
# repeated invocations).
#
# Prerequisites:
#   - Developer ID identity in Keychain
#   - Sparkle EdDSA key in Keychain
#   - Provisioning profiles in profiles/
#   - App-specific password (appleid.apple.com → App-Specific Passwords)
#   - vercel CLI authenticated
#   - HuggingFace access to meta-llama/Llama-Prompt-Guard-2-86M
#     (first release only; subsequent builds reuse the cached .mlpackage)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai — Release Pipeline"
echo "═══════════════════════════════════════════════"
echo ""

# Suggest the next patch version as default — users just press enter to
# accept a standard bump, and only type for major/minor jumps.
CURRENT_VERSION=$(current_app_version "$SITE_DIR/src/lib/constants.ts")
NEXT_VERSION=$(bump_patch "$CURRENT_VERSION")
if [ -n "$CURRENT_VERSION" ]; then
  echo "  Current released version: $CURRENT_VERSION"
fi
prompt_with_default VERSION "Version" "${NEXT_VERSION:-0.2.8}"
prompt_required APPLE_ID "Apple ID" "you@example.com"
prompt_with_default TEAM_ID "Apple Team ID" "U86PR842AK"
prompt_required DOWNLOAD_BASE_URL "Vercel Blob public URL" "https://xyz.public.blob.vercel-storage.com"
prompt_secret APP_PASSWORD "App-specific password"
prompt_secret BLOB_READ_WRITE_TOKEN "Vercel Blob read-write token (from Storage > your store > .env.local)"
export BLOB_READ_WRITE_TOKEN

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
APP="$PROJECT_DIR/build/Bouclier-ai.app"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"

echo ""
echo "── Starting release for v${VERSION} ──"
echo ""

# ── Step 0: Bump version in source files ────────
echo "▸ Bumping version to ${VERSION}..."
sed -i '' "s/APP_VERSION = \".*\"/APP_VERSION = \"${VERSION}\"/" "$REPO_ROOT/apps/site/src/lib/constants.ts"
sed -i '' "s/<key>CFBundleShortVersionString<\/key>.*/<key>CFBundleShortVersionString<\/key>/" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/BouclierExtension/GeneratedInfo.plist"
echo "  ✓ Version bumped in constants.ts + plists"
echo ""

# ── Step 1: Ensure CoreML model is built ────────
# The .mlpackage is gitignored (too large for GitHub) but must exist on
# disk for swift build to bundle it into the app. ensure-model.sh is a
# no-op when the model is already present, so this is free on reruns.
echo "▸ Step 1/7: Ensuring CoreML model is present..."
"$SCRIPT_DIR/ensure-model.sh"
echo ""

# ── Step 2: Build + Sign ────────────────────────
echo "▸ Step 2/7: Building and signing..."
VERSION="$VERSION" "$SCRIPT_DIR/build-app.sh" --release --sign
echo "  ✓ App built and signed at $APP"
echo ""

# ── Step 2: Notarize the .app ───────────────────
# We notarize the app as a zip first, then staple the ticket onto the
# .app before packaging the DMG. This way the app inside the DMG has
# the notarization ticket embedded and Gatekeeper won't block it.
echo "▸ Step 3/7: Notarizing app..."
APP_ZIP="$PROJECT_DIR/build/Bouclier-ai-notarize.zip"
ditto -c -k --keepParent "$APP" "$APP_ZIP"

xcrun notarytool submit "$APP_ZIP" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APP_PASSWORD" \
  --wait
echo ""

echo "  Stapling app..."
xcrun stapler staple "$APP"
rm -f "$APP_ZIP"
echo "  ✓ App notarized and stapled"
echo ""

# ── Step 3: Create DMG with Applications shortcut ──
echo "▸ Step 4/7: Creating DMG..."
rm -f "$DMG"

DMG_STAGE="$PROJECT_DIR/build/dmg-stage"
rm -rf "$DMG_STAGE"
mkdir -p "$DMG_STAGE"
cp -R "$APP" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"

hdiutil create -volname "Bouclier-ai" -srcfolder "$DMG_STAGE" \
  -ov -format UDZO "$DMG" -quiet

rm -rf "$DMG_STAGE"
echo "  ✓ DMG created at $DMG (with stapled app + Applications shortcut)"
echo "  ✓ Notarized and stapled"
echo ""

# ── Step 4: Sparkle sign + appcast ──────────────
echo "▸ Step 5/7: Signing for Sparkle and generating appcast..."
VERSION="$VERSION" DOWNLOAD_BASE_URL="$DOWNLOAD_BASE_URL" "$SCRIPT_DIR/publish-update.sh"
echo ""

# ── Step 5: Upload DMG ──────────────────────────
# Correct subcommand is `vercel blob put` — `upload` was silently
# failing because of the 2>/dev/null muzzle below it. Token is passed
# as env var so the CLI can find the target store without folder
# linking; --allow-overwrite lets reruns of the same version replace.
echo "▸ Step 6/7: Uploading DMG to Vercel Blob..."
if ! command -v vercel &>/dev/null; then
  echo "  ⚠ vercel CLI not found — upload manually:"
  echo "    vercel blob put $DMG --pathname Bouclier-ai-v${VERSION}-macOS.dmg --allow-overwrite"
  echo ""
elif vercel blob put "$DMG" \
       --pathname "Bouclier-ai-v${VERSION}-macOS.dmg" \
       --allow-overwrite; then
  echo "  ✓ Uploaded"
else
  echo ""
  echo "  ⚠ Upload failed. Run manually from any blob-linked folder:"
  echo "    vercel blob put $DMG --pathname Bouclier-ai-v${VERSION}-macOS.dmg --allow-overwrite"
fi
echo ""

# ── Step 6: Deploy site ─────────────────────────
echo "▸ Step 7/7: Deploying site..."
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
