#!/bin/bash
set -euo pipefail

# Upload an already-built, signed, notarized DMG to Vercel Blob.
#
# This is an artifact-only recovery utility. It deliberately does not change
# version metadata or the Sparkle appcast: release.sh owns that transaction and
# rolls it back after any failure. A successful standalone upload is therefore
# not permission to merge/tag a release; rerun release.sh to finish safely.
#
# Prompts for the Blob read-write token with HIDDEN input, so it never
# lands in your shell history or in a command argument. Any value already
# set in the environment is used without prompting (handy for CI).
#
# Usage:
#   ./scripts/upload-dmg.sh              # prompts for version + token
#   VERSION=0.9.11 ./scripts/upload-dmg.sh
#
# The Blob token lives in: Vercel → Storage → your Blob store → tokens.

# Remove a caller-provided token from the exported environment before even the
# path-discovery commands run. It is restored only for the Vercel subprocess.
PRESET_BLOB_TOKEN="${BLOB_READ_WRITE_TOKEN:-}"
export -n PRESET_BLOB_TOKEN
unset BLOB_READ_WRITE_TOKEN
unset HF_TOKEN
unset HUGGING_FACE_HUB_TOKEN
unset APP_PASSWORD

upload_exit_handler() {
  local status=$?
  trap - EXIT INT TERM
  unset BLOB_READ_WRITE_TOKEN
  unset PRESET_BLOB_TOKEN
  exit "$status"
}
trap upload_exit_handler EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"
BUILD_DIR="$PROJECT_DIR/build"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

for required_command in git vercel curl stat hdiutil codesign xcrun spctl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "ERROR: required upload command is unavailable: $required_command" >&2
    exit 1
  fi
done
if ! xcrun --find stapler >/dev/null 2>&1; then
  echo "ERROR: required Xcode release tool is unavailable: stapler" >&2
  exit 1
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Bouclier.ai — Upload DMG to Vercel Blob"
echo "═══════════════════════════════════════════════"
echo ""

# Default to the newest DMG sitting in build/, else the version in source.
DEFAULT_VERSION="$(latest_built_version "$BUILD_DIR")"
[ -n "$DEFAULT_VERSION" ] || DEFAULT_VERSION="$(current_app_version "$REPO_ROOT/apps/site/src/lib/constants.ts")"
prompt_with_default VERSION "Version to upload" "${DEFAULT_VERSION:-0.9.0}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: version must be a numeric semantic version (for example 0.9.11)." >&2
  exit 1
fi

RELEASED_VERSION=$(latest_released_version "$REPO_ROOT/apps/site/public/appcast.xml")
if [ -f "$REPO_ROOT/apps/site/public/appcast.xml" ] && [ -z "$RELEASED_VERSION" ]; then
  echo "ERROR: the existing appcast has no parseable released version." >&2
  exit 1
fi
if [ -n "$RELEASED_VERSION" ] && ! semver_greater_than "$VERSION" "$RELEASED_VERSION"; then
  echo "ERROR: refusing to overwrite published v${RELEASED_VERSION} with v${VERSION}." >&2
  echo "Only an unpublished, newer release artifact may use this recovery utility." >&2
  exit 1
fi
if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/tags/v${VERSION}"; then
  echo "ERROR: tag v${VERSION} already exists locally; its artifact is immutable." >&2
  exit 1
fi
remote_tag_status=0
git -C "$REPO_ROOT" ls-remote --exit-code --tags origin \
  "refs/tags/v${VERSION}" >/dev/null 2>&1 || remote_tag_status=$?
case "$remote_tag_status" in
  0)
    echo "ERROR: tag v${VERSION} already exists on origin; its artifact is immutable." >&2
    exit 1
    ;;
  2) ;;
  *)
    echo "ERROR: could not verify whether tag v${VERSION} exists on origin." >&2
    echo "Refusing to upload without a trustworthy remote-tag check." >&2
    exit 1
    ;;
esac

prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL%/}"
if ! valid_download_base_url "$DOWNLOAD_BASE_URL"; then
  echo "ERROR: Vercel Blob public URL must be a safe HTTPS base URL." >&2
  exit 1
fi

DMG="$BUILD_DIR/Bouclier-ai-v${VERSION}-macOS.dmg"
if [ ! -f "$DMG" ] || [ -L "$DMG" ]; then
  echo "✗ No DMG at $DMG" >&2
  echo "  Build one first with ./scripts/release.sh (VERSION=$VERSION)." >&2
  exit 1
fi

# Never let a stale, unsigned, or merely app-notarized image replace a public
# artifact. The final outer DMG itself must carry a valid signature and ticket.
echo "▸ Verifying signed and notarized DMG..."
hdiutil imageinfo "$DMG" >/dev/null
codesign --verify --strict --verbose=2 "$DMG"
xcrun stapler validate -v "$DMG"
spctl --assess --type open --context context:primary-signature -vv "$DMG"
echo "  ✓ Distribution checks passed"

if [ -n "$PRESET_BLOB_TOKEN" ]; then
  BLOB_READ_WRITE_TOKEN="$PRESET_BLOB_TOKEN"
fi
unset PRESET_BLOB_TOKEN
prompt_secret BLOB_READ_WRITE_TOKEN "Vercel Blob read-write token"

# The upload --pathname MUST mirror the path component of DOWNLOAD_BASE_URL,
# or the site/appcast point at /download/... while the DMG lands at /... and
# the download (and Sparkle auto-update) 404 silently.
DOWNLOAD_PATH=$(echo "$DOWNLOAD_BASE_URL" | sed -E 's|^https?://[^/]+||; s|^/||; s|/$||')
UPLOAD_PATHNAME="${DOWNLOAD_PATH:+${DOWNLOAD_PATH}/}Bouclier-ai-v${VERSION}-macOS.dmg"

echo ""
echo "▸ Uploading $(basename "$DMG") → $UPLOAD_PATHNAME"
# --access public: required by newer Vercel CLI (older versions defaulted
# to public). --allow-overwrite: lets a re-run replace the same version.
if BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put "$DMG" \
    --pathname "$UPLOAD_PATHNAME" \
    --access public \
    --allow-overwrite; then
  unset BLOB_READ_WRITE_TOKEN
else
  upload_status=$?
  unset BLOB_READ_WRITE_TOKEN
  exit "$upload_status"
fi

# Verify the exact-size object is reachable at the URL the appcast will use.
PUBLIC_URL="${DOWNLOAD_BASE_URL%/}/Bouclier-ai-v${VERSION}-macOS.dmg"
echo ""
echo "▸ Verifying $PUBLIC_URL"
verify_public_file "$PUBLIC_URL" "$DMG"

echo ""
echo "═══════════════════════════════════════════════"
echo "  v${VERSION} DMG uploaded"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Artifact-only recovery complete. No source version or appcast metadata"
echo "  was changed. Rerun ./scripts/release.sh to complete the coordinated"
echo "  release; do not merge or tag based only on this upload."
echo ""
