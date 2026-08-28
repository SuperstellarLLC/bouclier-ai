#!/bin/bash
set -euo pipefail

# Release pipeline: build → sign → notarize → DMG → Sparkle → upload.
# Site deploy happens via Vercel's git integration on the commit+push
# that follows the release, so there's no explicit deploy step here.
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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai — Release Pipeline"
echo "═══════════════════════════════════════════════"
echo ""

# A signed/notarized artifact must be reproducible from the commit that will be
# tagged. Starting dirty can put uncommitted runtime code in the DMG while the
# handoff commit contains only version metadata. Require product changes and
# the versioned CHANGELOG section to be reviewed and committed first.
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]; then
  echo "ERROR: release requires a clean worktree and index." >&2
  echo "Commit the complete product change (including its versioned CHANGELOG section), then rerun." >&2
  exit 1
fi

# Suggest the next patch version as default — users just press enter to
# accept a standard bump, and only type for major/minor jumps.
CURRENT_VERSION=$(current_app_version "$SITE_DIR/src/lib/constants.ts")
NEXT_VERSION=$(bump_patch "$CURRENT_VERSION")
RELEASED_VERSION=$(latest_released_version "$SITE_DIR/public/appcast.xml")
# Offer the prepped-but-uncut version when constants.ts is already ahead of the
# appcast (a release was prepped but never cut); otherwise the next patch. This
# stops the prompt defaulting to N+1 — and the maintainer retyping the real
# number — on every prepped release.
DEFAULT_VERSION=$(default_release_version "$CURRENT_VERSION" "$RELEASED_VERSION" "$NEXT_VERSION")
if [ -n "$RELEASED_VERSION" ]; then
  echo "  Last released version: $RELEASED_VERSION"
fi
# The release script is maintainer-driven (single host with the signing
# keys). Defaults come from env so the public repo doesn't hard-code
# the maintainer's Apple ID. Set $BOUCLIER_APPLE_ID and
# $BOUCLIER_APPLE_TEAM_ID in your shell or a .env to skip the prompt.
prompt_with_default VERSION "Version" "${DEFAULT_VERSION:-0.2.8}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: version must be a numeric semantic version (for example 0.9.11)." >&2
  exit 1
fi
if ! grep -Fq "## [$VERSION]" "$REPO_ROOT/CHANGELOG.md"; then
  echo "ERROR: CHANGELOG.md has no committed '## [$VERSION]' release section." >&2
  echo "Convert Unreleased to the dated version section, commit it, and rerun." >&2
  exit 1
fi
prompt_with_default APPLE_ID "Apple ID" "${BOUCLIER_APPLE_ID:-}"
prompt_with_default TEAM_ID "Apple Team ID" "${BOUCLIER_APPLE_TEAM_ID:-}"
prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"
prompt_secret APP_PASSWORD "App-specific password"
prompt_secret BLOB_READ_WRITE_TOKEN "Vercel Blob read-write token (from Storage > your store > .env.local)"
export BLOB_READ_WRITE_TOKEN

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
APP="$PROJECT_DIR/build/Bouclier-ai.app"

verify_release_diff() {
  local changed unexpected=""
  while IFS= read -r changed; do
    case "$changed" in
      apps/site/src/lib/constants.ts|\
      apps/desktop/Sources/Bouclier/Resources/Info.plist|\
      apps/desktop/project.yml|\
      apps/site/public/appcast.xml) ;;
      "") ;;
      *) unexpected="${unexpected}${changed}"$'\n' ;;
    esac
  done < <(git -C "$REPO_ROOT" diff --name-only)
  if [ -n "$unexpected" ]; then
    echo "ERROR: the release process changed files outside the audited metadata/appcast set:" >&2
    printf '%s' "$unexpected" >&2
    echo "Aborting so the signed artifact cannot drift from its eventual tag." >&2
    exit 1
  fi
}

echo ""
echo "── Starting release for v${VERSION} ──"
echo ""

# ── Step 0: Bump version in source files ────────
echo "▸ Bumping version to ${VERSION}..."
sed -i '' "s/APP_VERSION = \".*\"/APP_VERSION = \"${VERSION}\"/" "$REPO_ROOT/apps/site/src/lib/constants.ts"
sed -i '' "s/MARKETING_VERSION: \".*\"/MARKETING_VERSION: \"${VERSION}\"/" "$PROJECT_DIR/project.yml"
sed -i '' "s/<key>CFBundleShortVersionString<\/key>.*/<key>CFBundleShortVersionString<\/key>/" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
echo "  ✓ Version bumped in constants.ts + project.yml + Info.plist"
verify_release_diff
echo ""

# ── Step 1: Ensure the on-device model is built ──
# Prompt Guard 2 (86M) is gitignored (288MB, gated HuggingFace model) but
# reproducible via ensure-model.sh. It must be in Resources BEFORE the
# swift build so SPM's .copy("Resources") bundles it. First run downloads
# ~350MB + converts (~5 min); subsequent runs are instant. Requires a
# one-time `huggingface-cli login` with access to the gated model.
echo "▸ Step 1/6: Ensuring on-device model (Prompt Guard 2)..."
"$SCRIPT_DIR/ensure-model.sh"
echo ""

# ── Step 2: Build + Sign ────────────────────────
echo "▸ Step 2/6: Building and signing..."
VERSION="$VERSION" "$SCRIPT_DIR/build-app.sh" --release --sign
verify_release_diff
echo "  ✓ App built and signed at $APP"
echo ""

# ── Step 3: Notarize the .app ───────────────────
# We notarize the app as a zip first, then staple the ticket onto the
# .app before packaging the DMG. This way the app inside the DMG has
# the notarization ticket embedded and Gatekeeper won't block it.
echo "▸ Step 3/6: Notarizing app..."
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

# ── Step 4: Create DMG with Applications shortcut ──
echo "▸ Step 4/6: Creating DMG..."
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

# ── Step 5: Sparkle sign + appcast ──────────────
echo "▸ Step 5/6: Signing for Sparkle and generating appcast..."
VERSION="$VERSION" DOWNLOAD_BASE_URL="$DOWNLOAD_BASE_URL" "$SCRIPT_DIR/publish-update.sh"
verify_release_diff
echo ""

# ── Step 6: Upload DMG ──────────────────────────
# Correct subcommand is `vercel blob put` — `upload` was silently
# failing because of the 2>/dev/null muzzle below it. Token is passed
# as env var so the CLI can find the target store without folder
# linking; --allow-overwrite lets reruns of the same version replace.
#
# The upload --pathname MUST mirror whatever path component is in
# DOWNLOAD_BASE_URL, otherwise the appcast/site point at /download/...
# while the DMG lands at /... and Sparkle auto-update 404s silently.
# Extract the path portion of DOWNLOAD_BASE_URL and prepend it.
DOWNLOAD_PATH=$(echo "$DOWNLOAD_BASE_URL" | sed -E 's|^https?://[^/]+||; s|^/||; s|/$||')
UPLOAD_PATHNAME="${DOWNLOAD_PATH:+${DOWNLOAD_PATH}/}Bouclier-ai-v${VERSION}-macOS.dmg"

echo "▸ Step 6/6: Uploading DMG to Vercel Blob..."
echo "  Target pathname: $UPLOAD_PATHNAME"
# `--access public` is required by Vercel CLI >= ~48 (older releases
# defaulted to public); without it `vercel blob put` exits with
# "Missing required --access flag" and the upload is skipped silently.
if ! command -v vercel &>/dev/null; then
  echo "  ERROR: vercel CLI not found. The release is not publishable until the DMG upload succeeds."
  echo "  Install/authenticate the CLI, then run:"
  echo "    vercel blob put $DMG --pathname $UPLOAD_PATHNAME --access public --allow-overwrite"
  echo ""
  exit 1
elif vercel blob put "$DMG" \
       --pathname "$UPLOAD_PATHNAME" \
       --access public \
       --allow-overwrite; then
  echo "  ✓ Uploaded"
else
  echo ""
  echo "  ERROR: DMG upload failed. The appcast must not be deployed with a missing artifact."
  echo "  Retry from any blob-linked folder:"
  echo "    vercel blob put $DMG --pathname $UPLOAD_PATHNAME --access public --allow-overwrite"
  exit 1
fi
echo ""

echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai v${VERSION} built and uploaded"
echo "═══════════════════════════════════════════════"
echo ""
echo "  DMG:     $DMG"
echo "  Appcast: $SITE_DIR/public/appcast.xml"
echo ""
echo "  Commit and push to deploy the site (Vercel picks up the appcast +"
echo "  version bump on push to main):"
echo ""
echo "    git add apps/site/src/lib/constants.ts \\"
echo "            apps/desktop/Sources/Bouclier/Resources/Info.plist \\"
echo "            apps/desktop/project.yml \\"
echo "            apps/site/public/appcast.xml"
echo "    git commit -m \"chore: v${VERSION} release\""
echo "    git push origin HEAD"
echo "    # Verify the commit on the remote, then trigger the tag verifier/draft release:"
echo "    git tag v${VERSION}"
echo "    git push origin v${VERSION}"
echo ""
