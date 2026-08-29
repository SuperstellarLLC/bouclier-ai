#!/bin/bash
set -euo pipefail

# Capture network credentials before path discovery or any other subprocess can
# inherit them. Unexported copies are restored only for their one intended
# command: Hugging Face credentials for model preparation, Blob for Vercel.
PRESET_BLOB_TOKEN="${BLOB_READ_WRITE_TOKEN:-}"
PRESET_HF_TOKEN="${HF_TOKEN:-}"
PRESET_HUGGING_FACE_HUB_TOKEN="${HUGGING_FACE_HUB_TOKEN:-}"
export -n PRESET_BLOB_TOKEN
export -n PRESET_HF_TOKEN
export -n PRESET_HUGGING_FACE_HUB_TOKEN
unset BLOB_READ_WRITE_TOKEN
unset HF_TOKEN
unset HUGGING_FACE_HUB_TOKEN
unset APP_PASSWORD

# Release pipeline: build/sign app → create/sign DMG → notarize/staple
# DMG → Sparkle signature/appcast → verified upload.
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
#   - notarytool credentials in a Keychain profile (recommended setup below)
#   - vercel CLI authenticated
#
# One-time notarization setup (the command securely prompts for the
# app-specific password; never provide the password as a command argument):
#   xcrun notarytool store-credentials "bouclier-ai" \
#     --apple-id "you@example.com" --team-id "YOURTEAMID"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"
# shellcheck source=_release_transaction.sh
source "$SCRIPT_DIR/_release_transaction.sh"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: required release command is unavailable: $command_name" >&2
    return 1
  fi
}

refresh_origin_main() {
  if ! git -C "$REPO_ROOT" fetch --quiet --no-tags origin main; then
    echo "ERROR: could not refresh origin/main." >&2
    return 1
  fi
  if ! git -C "$REPO_ROOT" rev-parse 'FETCH_HEAD^{commit}'; then
    echo "ERROR: fetched origin/main did not resolve to a commit." >&2
    return 1
  fi
}

# Check non-secret prerequisites before model conversion, compilation, or
# signing. Missing upload tooling should never be discovered only after a
# notarized artifact has already been produced.
for release_command in git swift xcrun hdiutil codesign spctl curl stat openssl xmllint vercel; do
  require_command "$release_command"
done
if [ ! -x /usr/libexec/PlistBuddy ]; then
  echo "ERROR: /usr/libexec/PlistBuddy is required for version verification." >&2
  exit 1
fi
for xcode_tool in notarytool stapler; do
  if ! xcrun --find "$xcode_tool" >/dev/null 2>&1; then
    echo "ERROR: required Xcode release tool is unavailable: $xcode_tool" >&2
    exit 1
  fi
done

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

# The signed artifact and the eventual deployment/tag must start from the exact
# public main commit. A feature branch, unpushed commit, stale clone, or detached
# HEAD can otherwise produce bytes that never match what origin/main deploys.
RELEASE_BRANCH=$(git -C "$REPO_ROOT" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
if [ "$RELEASE_BRANCH" != "main" ]; then
  echo "ERROR: releases must be run from the checked-out main branch, not '${RELEASE_BRANCH:-detached HEAD}'." >&2
  exit 1
fi
if ! ORIGIN_MAIN_COMMIT=$(refresh_origin_main); then
  echo "Refusing to release without a trustworthy origin/main baseline." >&2
  exit 1
fi
if ! RELEASE_BASE_COMMIT=$(git -C "$REPO_ROOT" rev-parse 'HEAD^{commit}'); then
  echo "ERROR: could not resolve the local release commit." >&2
  exit 1
fi
if [ "$RELEASE_BASE_COMMIT" != "$ORIGIN_MAIN_COMMIT" ]; then
  echo "ERROR: local main must exactly match origin/main before release." >&2
  echo "       local=$RELEASE_BASE_COMMIT origin=$ORIGIN_MAIN_COMMIT" >&2
  exit 1
fi

# Suggest the next patch version as default — users just press enter to
# accept a standard bump, and only type for major/minor jumps.
CURRENT_VERSION=$(current_app_version "$SITE_DIR/src/lib/constants.ts")
NEXT_VERSION=$(bump_patch "$CURRENT_VERSION")
RELEASED_VERSION=$(latest_released_version "$SITE_DIR/public/appcast.xml")
if [ -f "$SITE_DIR/public/appcast.xml" ] && [ -z "$RELEASED_VERSION" ]; then
  echo "ERROR: the existing appcast has no parseable released version." >&2
  exit 1
fi
# Offer the prepped-but-uncut version when constants.ts is already ahead of the
# appcast (a release was prepped but never cut); otherwise the next patch. This
# stops the prompt defaulting to N+1 — and the maintainer retyping the real
# number — on every prepped release.
DEFAULT_VERSION=$(default_release_version "$CURRENT_VERSION" "$RELEASED_VERSION" "$NEXT_VERSION")
if [ -n "$RELEASED_VERSION" ]; then
  echo "  Last released version: $RELEASED_VERSION"
fi
prompt_with_default VERSION "Version" "${DEFAULT_VERSION:-0.2.8}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: version must be a numeric semantic version (for example 0.9.11)." >&2
  exit 1
fi
if [ -n "$RELEASED_VERSION" ] && ! semver_greater_than "$VERSION" "$RELEASED_VERSION"; then
  echo "ERROR: v${VERSION} is not newer than published v${RELEASED_VERSION}." >&2
  echo "Published version paths are immutable; choose a newer version." >&2
  exit 1
fi
if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/tags/v${VERSION}"; then
  echo "ERROR: tag v${VERSION} already exists locally; released versions cannot be rebuilt in place." >&2
  exit 1
fi
if ! grep -Fq "## [$VERSION]" "$REPO_ROOT/CHANGELOG.md"; then
  echo "ERROR: CHANGELOG.md has no committed '## [$VERSION]' release section." >&2
  echo "Convert Unreleased to the dated version section, commit it, and rerun." >&2
  exit 1
fi
prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL%/}"
if ! valid_download_base_url "$DOWNLOAD_BASE_URL"; then
  echo "ERROR: Vercel Blob public URL must be an HTTPS base URL without query, fragment, whitespace, or XML metacharacters." >&2
  exit 1
fi

# A local-only tag lookup is insufficient in a stale clone. Fail closed when
# origin cannot be checked so an existing remote release can never be replaced
# merely because its appcast deployment lagged behind. Network credentials
# captured above remain unexported during this request.
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
    echo "Refusing to release without a trustworthy remote-tag check." >&2
    exit 1
    ;;
esac

# Prepare every network-fetched build input before notarization or upload
# credentials are collected/accessed. Prompt Guard 2 is gitignored (288MB,
# gated HuggingFace model) but reproducible via the hash-locked conversion
# environment in ensure-model.sh. A valid existing artifact makes this a fast
# checksum-only preflight.
echo ""
echo "▸ Preflight: Ensuring on-device model (Prompt Guard 2)..."
run_model_preflight() {
  if [ -n "$PRESET_HF_TOKEN" ] && [ -n "$PRESET_HUGGING_FACE_HUB_TOKEN" ]; then
    HF_TOKEN="$PRESET_HF_TOKEN" \
      HUGGING_FACE_HUB_TOKEN="$PRESET_HUGGING_FACE_HUB_TOKEN" \
      "$SCRIPT_DIR/ensure-model.sh"
  elif [ -n "$PRESET_HF_TOKEN" ]; then
    HF_TOKEN="$PRESET_HF_TOKEN" "$SCRIPT_DIR/ensure-model.sh"
  elif [ -n "$PRESET_HUGGING_FACE_HUB_TOKEN" ]; then
    HUGGING_FACE_HUB_TOKEN="$PRESET_HUGGING_FACE_HUB_TOKEN" \
      "$SCRIPT_DIR/ensure-model.sh"
  else
    "$SCRIPT_DIR/ensure-model.sh"
  fi
}
model_preflight_status=0
run_model_preflight || model_preflight_status=$?
unset PRESET_HF_TOKEN
unset PRESET_HUGGING_FACE_HUB_TOKEN
# Hugging Face credentials are needed only by model preparation. Remove them
# before Swift dependencies, signing tools, notarization, Vercel, or curl run.
unset HF_TOKEN
unset HUGGING_FACE_HUB_TOKEN
if [ "$model_preflight_status" -ne 0 ]; then
  exit "$model_preflight_status"
fi
echo ""

# Keychain is the normal notarization path. Enter "interactive" only as a
# migration fallback; notarytool itself will securely prompt for the
# app-specific password, so the secret still never appears in argv.
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-${BOUCLIER_NOTARYTOOL_PROFILE:-}}"
prompt_with_default NOTARYTOOL_PROFILE \
  "notarytool Keychain profile (or 'interactive')" \
  "bouclier-ai"
if [ "$NOTARYTOOL_PROFILE" = "interactive" ]; then
  APPLE_ID="${APPLE_ID:-${BOUCLIER_APPLE_ID:-}}"
  TEAM_ID="${TEAM_ID:-${BOUCLIER_APPLE_TEAM_ID:-}}"
  prompt_required APPLE_ID "Apple ID"
  prompt_required TEAM_ID "Apple Team ID"
fi

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
APP="$PROJECT_DIR/build/Bouclier-ai.app"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application}"

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

verify_source_versions() {
  local site_version project_version desktop_version
  site_version=$(sed -nE 's/^export const APP_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)";$/\1/p' \
    "$REPO_ROOT/apps/site/src/lib/constants.ts")
  project_version=$(sed -nE 's/^        MARKETING_VERSION: "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' \
    "$PROJECT_DIR/project.yml")
  desktop_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist" 2>/dev/null || true)

  if [ "$site_version" != "$VERSION" ] \
    || [ "$project_version" != "$VERSION" ] \
    || [ "$desktop_version" != "$VERSION" ]; then
    echo "ERROR: release version rewrite did not update every audited source." >&2
    echo "       site=${site_version:-missing} project=${project_version:-missing} desktop=${desktop_version:-missing} expected=$VERSION" >&2
    return 1
  fi
}

submit_for_notarization() {
  local artifact="$1"
  if [ "$NOTARYTOOL_PROFILE" = "interactive" ]; then
    echo "  Using notarytool's secure password prompt (migration fallback)."
    if xcrun notarytool submit "$artifact" \
      --apple-id "$APPLE_ID" \
      --team-id "$TEAM_ID" \
      --wait; then
      return 0
    fi
    echo "ERROR: interactive notarization failed." >&2
    return 1
  fi

  if xcrun notarytool submit "$artifact" \
    --keychain-profile "$NOTARYTOOL_PROFILE" \
    --wait; then
    return 0
  fi

  cat >&2 << EOF

ERROR: notarization failed with Keychain profile '$NOTARYTOOL_PROFILE'.
Create or refresh it with this command, which securely prompts for the
app-specific password instead of placing it in command arguments:

  xcrun notarytool store-credentials "$NOTARYTOOL_PROFILE" \\
    --apple-id "you@example.com" --team-id "YOURTEAMID"

Then rerun the release. As a one-time fallback, set
BOUCLIER_NOTARYTOOL_PROFILE=interactive; notarytool will prompt securely.
EOF
  return 1
}

# All tracked edits made by this script are transactional. A build,
# notarization, signing, or upload failure restores their exact pre-release
# bytes so the clean-tree gate does not block a safe rerun. Build artifacts are
# intentionally retained for diagnosis; only a successful upload commits the
# metadata transaction.
RELEASE_METADATA_FILES=(
  "$REPO_ROOT/apps/site/src/lib/constants.ts"
  "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
  "$PROJECT_DIR/project.yml"
  "$SITE_DIR/public/appcast.xml"
)
release_transaction_begin "${RELEASE_METADATA_FILES[@]}"

release_exit_handler() {
  local status=$?
  local final_status
  trap - EXIT INT TERM
  unset BLOB_READ_WRITE_TOKEN
  unset PRESET_BLOB_TOKEN
  unset HF_TOKEN
  unset HUGGING_FACE_HUB_TOKEN
  unset PRESET_HF_TOKEN
  unset PRESET_HUGGING_FACE_HUB_TOKEN
  release_transaction_finish "$status"
  final_status=$?
  exit "$final_status"
}
trap release_exit_handler EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo ""
echo "── Starting release for v${VERSION} ──"
echo ""

# ── Step 0: Bump version in source files ────────
echo "▸ Bumping version to ${VERSION}..."
sed -i '' "s/APP_VERSION = \".*\"/APP_VERSION = \"${VERSION}\"/" "$REPO_ROOT/apps/site/src/lib/constants.ts"
sed -i '' "s/MARKETING_VERSION: \".*\"/MARKETING_VERSION: \"${VERSION}\"/" "$PROJECT_DIR/project.yml"
sed -i '' "s/<key>CFBundleShortVersionString<\/key>.*/<key>CFBundleShortVersionString<\/key>/" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
sed -i '' "/<key>CFBundleShortVersionString<\/key>/{n;s|<string>.*</string>|<string>${VERSION}</string>|;}" "$PROJECT_DIR/Sources/Bouclier/Resources/Info.plist"
verify_source_versions
echo "  ✓ Version bumped in constants.ts + project.yml + Info.plist"
verify_release_diff
echo ""

# ── Step 1: Build + Sign ────────────────────────
echo "▸ Step 1/5: Building and signing..."
VERSION="$VERSION" SIGNING_IDENTITY="$SIGNING_IDENTITY" \
  "$SCRIPT_DIR/build-app.sh" --release --sign
verify_release_diff
BUILT_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
  "$APP/Contents/Info.plist" 2>/dev/null || true)
if [ "$BUILT_VERSION" != "$VERSION" ]; then
  echo "ERROR: signed app version is ${BUILT_VERSION:-missing}; expected $VERSION." >&2
  exit 1
fi
echo "  ✓ App built and signed at $APP"
echo ""

# Step 2: Create and sign the outer DMG.
# The outer container is the artifact users actually download and must be
# signed and finalized before its byte-level Sparkle signature is generated.
echo "▸ Step 2/5: Creating and signing DMG..."
rm -f "$DMG"

DMG_STAGE="$PROJECT_DIR/build/dmg-stage"
rm -rf "$DMG_STAGE"
mkdir -p "$DMG_STAGE"
cp -R "$APP" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"

hdiutil create -volname "Bouclier-ai" -srcfolder "$DMG_STAGE" \
  -ov -format UDZO "$DMG" -quiet

rm -rf "$DMG_STAGE"
codesign --force --timestamp --sign "$SIGNING_IDENTITY" "$DMG"
codesign --verify --strict --verbose=2 "$DMG"
echo "  ✓ Signed DMG created at $DMG"
echo ""

# The DMG is the outermost file users download. Its ticket covers the signed
# contents and remains available to Gatekeeper when the Mac is offline, so it
# must be finalized before the byte-level Sparkle signature.
echo "▸ Step 3/5: Notarizing and validating DMG..."
submit_for_notarization "$DMG"
xcrun stapler staple -v "$DMG"
xcrun stapler validate -v "$DMG"
codesign --verify --strict --verbose=2 "$DMG"
spctl --assess --type open --context context:primary-signature -vv "$DMG"
echo "  ✓ DMG signed, notarized, stapled, and accepted by Gatekeeper"
echo ""

# ── Step 4: Sparkle sign + appcast ──────────────
echo "▸ Step 4/5: Signing for Sparkle and generating appcast..."
VERSION="$VERSION" DOWNLOAD_BASE_URL="$DOWNLOAD_BASE_URL" RELEASE_PIPELINE=1 \
  "$SCRIPT_DIR/publish-update.sh"
verify_release_diff
echo ""

# ── Step 5: Upload DMG ──────────────────────────
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

if [ -n "$PRESET_BLOB_TOKEN" ]; then
  BLOB_READ_WRITE_TOKEN="$PRESET_BLOB_TOKEN"
fi
unset PRESET_BLOB_TOKEN
prompt_secret BLOB_READ_WRITE_TOKEN \
  "Vercel Blob read-write token (from Storage > your store > .env.local)"

# Notarization can take long enough for main to advance. Refresh immediately
# before the irreversible upload and require both local HEAD and origin/main to
# remain the exact commit from which the signed artifact was built. The Blob
# token is a non-exported shell variable and is not inherited by these commands.
if ! LATEST_ORIGIN_MAIN_COMMIT=$(refresh_origin_main); then
  echo "Refusing to upload without rechecking origin/main." >&2
  exit 1
fi
if ! CURRENT_RELEASE_HEAD=$(git -C "$REPO_ROOT" rev-parse 'HEAD^{commit}'); then
  echo "ERROR: could not re-resolve the local release commit." >&2
  exit 1
fi
if [ "$CURRENT_RELEASE_HEAD" != "$RELEASE_BASE_COMMIT" ] \
  || [ "$LATEST_ORIGIN_MAIN_COMMIT" != "$RELEASE_BASE_COMMIT" ]; then
  echo "ERROR: main changed while the release was being built; refusing to upload." >&2
  echo "       base=$RELEASE_BASE_COMMIT local=$CURRENT_RELEASE_HEAD origin=$LATEST_ORIGIN_MAIN_COMMIT" >&2
  exit 1
fi

echo "▸ Step 5/5: Uploading DMG to Vercel Blob..."
echo "  Target pathname: $UPLOAD_PATHNAME"
# `--access public` is required by Vercel CLI >= ~48 (older releases
# defaulted to public); without it `vercel blob put` exits with
# "Missing required --access flag" and the upload is skipped silently.
if BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put "$DMG" \
       --pathname "$UPLOAD_PATHNAME" \
       --access public \
       --allow-overwrite; then
  unset BLOB_READ_WRITE_TOKEN
  echo "  ✓ Uploaded"
else
  upload_status=$?
  unset BLOB_READ_WRITE_TOKEN
  echo ""
  echo "  ERROR: DMG upload failed. The appcast must not be deployed with a missing artifact."
  echo "  Fix the Vercel CLI/store configuration and rerun this release; the token"
  echo "  will be requested with hidden input and tracked metadata will be restored."
  exit "$upload_status"
fi
echo ""

# Do not retain/deploy the appcast until the exact final-size object is publicly
# reachable at its enclosure URL. The Blob credential has already been removed
# before this unauthenticated verification request.
PUBLIC_URL="${DOWNLOAD_BASE_URL}/Bouclier-ai-v${VERSION}-macOS.dmg"
echo "▸ Verifying public artifact..."
verify_public_file "$PUBLIC_URL" "$DMG"
echo ""

# The signed artifact is now verifiably reachable at the appcast URL.
# Keep the version/appcast edits for the maintainer's release commit.
release_transaction_commit

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
echo "    git push origin main"
echo "    # Verify the commit on the remote, then trigger the tag verifier/draft release:"
echo "    git tag v${VERSION}"
echo "    git push origin v${VERSION}"
echo ""
