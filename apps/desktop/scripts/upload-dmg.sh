#!/bin/bash
set -euo pipefail

# Upload an already-built DMG to Vercel Blob — the last step of release.sh,
# split out so you can re-run it on its own without rebuilding/renotarizing
# (e.g. when the upload failed but the DMG is already signed + stapled).
#
# Prompts for the Blob read-write token with HIDDEN input, so it never
# lands in your shell history or in a command argument. Any value already
# set in the environment is used without prompting (handy for CI).
#
# Usage:
#   ./scripts/upload-dmg.sh              # prompts for version + token
#   VERSION=0.9.0 ./scripts/upload-dmg.sh
#
# The Blob token lives in: Vercel → Storage → your Blob store → tokens.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"
BUILD_DIR="$PROJECT_DIR/build"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

echo ""
echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai — Upload DMG to Vercel Blob"
echo "═══════════════════════════════════════════════"
echo ""

# Default to the newest DMG sitting in build/, else the version in source.
DEFAULT_VERSION="$(latest_built_version "$BUILD_DIR")"
[ -n "$DEFAULT_VERSION" ] || DEFAULT_VERSION="$(current_app_version "$REPO_ROOT/apps/site/src/lib/constants.ts")"
prompt_with_default VERSION "Version to upload" "${DEFAULT_VERSION:-0.9.0}"

prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"

DMG="$BUILD_DIR/Bouclier-ai-v${VERSION}-macOS.dmg"
if [ ! -f "$DMG" ]; then
  echo "✗ No DMG at $DMG" >&2
  echo "  Build one first with ./scripts/release.sh (VERSION=$VERSION)." >&2
  exit 1
fi

# Hidden prompt — the whole point of this script.
prompt_secret BLOB_READ_WRITE_TOKEN "Vercel Blob read-write token"
export BLOB_READ_WRITE_TOKEN

if ! command -v vercel &>/dev/null; then
  echo "✗ vercel CLI not found (npm i -g vercel)." >&2
  exit 1
fi

# The upload --pathname MUST mirror the path component of DOWNLOAD_BASE_URL,
# or the site/appcast point at /download/... while the DMG lands at /... and
# the download (and Sparkle auto-update) 404 silently.
DOWNLOAD_PATH=$(echo "$DOWNLOAD_BASE_URL" | sed -E 's|^https?://[^/]+||; s|^/||; s|/$||')
UPLOAD_PATHNAME="${DOWNLOAD_PATH:+${DOWNLOAD_PATH}/}Bouclier-ai-v${VERSION}-macOS.dmg"

echo ""
echo "▸ Uploading $(basename "$DMG") → $UPLOAD_PATHNAME"
# --access public: required by newer Vercel CLI (older versions defaulted
# to public). --allow-overwrite: lets a re-run replace the same version.
vercel blob put "$DMG" \
  --pathname "$UPLOAD_PATHNAME" \
  --access public \
  --allow-overwrite

# Verify the object is actually reachable at the URL the site will use.
PUBLIC_URL="${DOWNLOAD_BASE_URL%/}/Bouclier-ai-v${VERSION}-macOS.dmg"
echo ""
echo "▸ Verifying $PUBLIC_URL"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -I "$PUBLIC_URL" || echo "000")
if [ "$CODE" = "200" ]; then
  echo "  ✓ Live (HTTP 200)"
else
  echo "  ⚠ Got HTTP $CODE — the object may not be at the expected path."
  echo "    Check that DOWNLOAD_BASE_URL matches your store and that the"
  echo "    token belongs to that store."
  exit 1
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  v${VERSION} DMG uploaded"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Next: merge to main — Vercel deploys bouclier.ai (site + appcast),"
echo "  the Download button resolves, and Sparkle updates existing users."
echo ""
