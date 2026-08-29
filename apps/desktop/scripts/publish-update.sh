#!/bin/bash
set -euo pipefail

# This utility only needs the Sparkle signing key in Keychain. Prevent unrelated
# caller credentials from reaching codesign, Xcode tools, sign_update, or XML
# validation when it is invoked directly rather than through release.sh.
unset BLOB_READ_WRITE_TOKEN
unset HF_TOKEN
unset HUGGING_FACE_HUB_TOKEN
unset APP_PASSWORD

# Publishes a Sparkle update for Bouclier.ai.
#
# Prerequisites:
#   1. build/Bouclier-ai-v$VERSION-macOS.dmg exists (signed + notarized + stapled)
#   2. Sparkle EdDSA key is in login Keychain
#   3. CHANGELOG.md has a `## [$VERSION]` section with the release notes
#
# Usage:
#   ./scripts/publish-update.sh
#
# Prompts interactively for version and Vercel Blob URL. Env vars
# (VERSION, DOWNLOAD_BASE_URL) are honored when set — release.sh passes
# them through so this stays a no-prompt pass in the pipeline.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"
REPO_ROOT="$(dirname "$(dirname "$PROJECT_DIR")")"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"

# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

# Extract the markdown section for a given version from CHANGELOG.md.
# Looks for a heading matching `## [<version>]` and prints every line
# until the next `## [` heading. Empty output = section not found.
extract_changelog_section() {
  local version="$1" file="$2"
  awk -v ver="$version" '
    $0 ~ ("^## \\[" ver "\\]") { found = 1; next }
    found && /^## \[/ { exit }
    found { print }
  ' "$file"
}

# Convert a minimal Keep-a-Changelog markdown subset to the HTML subset
# Sparkle renders in its update dialog: `### Heading` → <h4>, `- item`
# → <li> grouped in <ul>, two-space-indented continuation lines append
# to the previous <li>, blank lines split blocks.
#
# Inline markdown is reduced to safe HTML: `**bold**` → <strong>, and
# `` `code` `` → <code>. Without this, Sparkle's dialog renders the
# literal asterisks and backticks — which looks unfinished.
markdown_to_sparkle_html() {
  awk '
    function inline_md(s,    out) {
      out = s
      # **bold** → <strong>...</strong>. Repeat until no pairs remain.
      while (match(out, /\*\*[^*]+\*\*/)) {
        out = substr(out, 1, RSTART - 1) "<strong>" \
              substr(out, RSTART + 2, RLENGTH - 4) "</strong>" \
              substr(out, RSTART + RLENGTH)
      }
      # `code` → <code>...</code>. Same idea.
      while (match(out, /`[^`]+`/)) {
        out = substr(out, 1, RSTART - 1) "<code>" \
              substr(out, RSTART + 1, RLENGTH - 2) "</code>" \
              substr(out, RSTART + RLENGTH)
      }
      return out
    }
    function flush_item() {
      if (buf != "") { print "<li>" inline_md(buf) "</li>"; buf = "" }
    }
    function flush_list() {
      flush_item()
      if (in_list) { print "</ul>"; in_list = 0 }
    }
    BEGIN { in_list = 0; buf = "" }
    /^[[:space:]]*$/ { flush_list(); next }
    /^### / {
      flush_list()
      sub(/^### /, "")
      print "<h4>" inline_md($0) "</h4>"
      next
    }
    /^- / {
      flush_item()
      if (!in_list) { print "<ul>"; in_list = 1 }
      sub(/^- /, "")
      buf = $0
      next
    }
    /^  / {
      sub(/^ +/, " ")
      if (in_list && buf != "") { buf = buf $0 } else { print "<p>" inline_md($0) "</p>" }
      next
    }
    { flush_list(); print "<p>" inline_md($0) "</p>" }
    END { flush_list() }
  '
}

# Default to the version of the most recently built DMG — this script
# regenerates the appcast for an artifact that already exists on disk,
# not for a hypothetical next release.
BUILT_VERSION=$(latest_built_version "$PROJECT_DIR/build")
if [ -n "$BUILT_VERSION" ]; then
  echo "  Latest build on disk: $BUILT_VERSION"
fi
prompt_with_default VERSION "Version" "${BUILT_VERSION:-0.0.0}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: version must be a numeric semantic version (for example 0.9.11)." >&2
  exit 1
fi
prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL%/}"
if ! valid_download_base_url "$DOWNLOAD_BASE_URL"; then
  echo "ERROR: Vercel Blob public URL must be a safe HTTPS base URL." >&2
  exit 1
fi

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
SIGN_UPDATE="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/bin/sign_update"
APPCAST_OUT="$SITE_DIR/public/appcast.xml"

for required_command in codesign xcrun spctl stat openssl xmllint; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "ERROR: required appcast command is unavailable: $required_command" >&2
    exit 1
  fi
done
if ! xcrun --find stapler >/dev/null 2>&1; then
  echo "ERROR: required Xcode release tool is unavailable: stapler" >&2
  exit 1
fi

if [ ! -f "$DMG" ] || [ -L "$DMG" ]; then
  echo "ERROR: DMG not found at $DMG"
  echo "Run: VERSION=$VERSION ./scripts/build-app.sh --release --sign"
  exit 1
fi

# A standalone appcast invocation must not bless an unsigned or merely
# app-notarized container. release.sh already performed these checks, but
# repeating them is cheap and keeps this public utility safe on its own.
codesign --verify --strict --verbose=2 "$DMG"
xcrun stapler validate -v "$DMG"
spctl --assess --type open --context context:primary-signature -vv "$DMG"

if [ ! -x "$SIGN_UPDATE" ]; then
  echo "ERROR: sign_update not found. Run 'swift build' first to fetch Sparkle artifacts."
  exit 1
fi

# Pull release notes from CHANGELOG.md. No section = refuse to publish:
# a silent fallback is how we ended up with the stale-notes-forever bug.
if [ ! -f "$CHANGELOG" ]; then
  echo "ERROR: CHANGELOG.md missing at $CHANGELOG" >&2
  exit 1
fi
CHANGELOG_MD=$(extract_changelog_section "$VERSION" "$CHANGELOG")
if [ -z "$CHANGELOG_MD" ]; then
  cat >&2 << EOF
ERROR: No changelog section found for v${VERSION} in $CHANGELOG.
       Add a '## [${VERSION}] — YYYY-MM-DD' section with ### Added /
       ### Fixed / ### Changed groups before releasing.
EOF
  exit 1
fi
CHANGELOG_HTML=$(echo "$CHANGELOG_MD" | markdown_to_sparkle_html)

echo "Signing DMG for Sparkle..."
SIGNATURE=$("$SIGN_UPDATE" "$DMG")
echo "$SIGNATURE"

# Parse the sparkle:edSignature and length from sign_update output
# (BSD grep on macOS — no -P flag)
ED_SIG=$(echo "$SIGNATURE" | sed -n 's/.*sparkle:edSignature="\([^"]*\)".*/\1/p')
LENGTH=$(echo "$SIGNATURE" | sed -n 's/.*length="\([^"]*\)".*/\1/p')
DMG_SIZE=$(portable_file_size "$DMG")

APPCAST_TMP=""
SIGNATURE_BYTES=""
cleanup_publish_update() {
  if [ -n "$APPCAST_TMP" ]; then
    rm -f "$APPCAST_TMP"
  fi
  if [ -n "$SIGNATURE_BYTES" ]; then
    rm -f "$SIGNATURE_BYTES"
  fi
}
trap cleanup_publish_update EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Sparkle uses a 64-byte Ed25519 signature encoded as canonical base64. Treat
# parser drift or partial sign_update output as a hard release failure rather
# than publishing an enclosure that every installed client will reject.
SIGNATURE_BYTES=$(mktemp /tmp/bouclier-sparkle-signature.XXXXXX)
if ! [[ "$ED_SIG" =~ ^[A-Za-z0-9+/]{86}==$ ]] \
  || ! printf '%s' "$ED_SIG" | openssl base64 -d -A > "$SIGNATURE_BYTES"; then
  echo "ERROR: sign_update did not return a canonical Ed25519 signature." >&2
  exit 1
fi
DECODED_SIGNATURE_SIZE=$(portable_file_size "$SIGNATURE_BYTES")
CANONICAL_SIGNATURE=$(openssl base64 -A -in "$SIGNATURE_BYTES")
if [ "$DECODED_SIGNATURE_SIZE" != "64" ] || [ "$CANONICAL_SIGNATURE" != "$ED_SIG" ]; then
  echo "ERROR: Sparkle signature is not canonical base64 for exactly 64 bytes." >&2
  exit 1
fi
rm -f "$SIGNATURE_BYTES"
SIGNATURE_BYTES=""

if ! [[ "$LENGTH" =~ ^[1-9][0-9]*$ ]] || [ "$LENGTH" != "$DMG_SIZE" ]; then
  echo "ERROR: sign_update length '${LENGTH:-missing}' does not match the ${DMG_SIZE}-byte DMG." >&2
  exit 1
fi

DATE=$(date -R 2>/dev/null || date -u +"%a, %d %b %Y %H:%M:%S %z")

DMG_URL="${DOWNLOAD_BASE_URL}/Bouclier-ai-v${VERSION}-macOS.dmg"

echo ""
echo "Generating appcast.xml..."

APPCAST_TMP=$(mktemp "${APPCAST_OUT}.tmp.XXXXXX")
cat > "$APPCAST_TMP" << EOF
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Bouclier.ai Updates</title>
    <link>https://www.bouclier.ai/appcast.xml</link>
    <description>Updates for Bouclier.ai — prompt injection firewall for macOS</description>
    <language>en</language>
    <item>
      <title>Version ${VERSION}</title>
      <pubDate>${DATE}</pubDate>
      <sparkle:version>${VERSION}</sparkle:version>
      <sparkle:shortVersionString>${VERSION}</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>15.0</sparkle:minimumSystemVersion>
      <description><![CDATA[
<h2>Bouclier.ai v${VERSION}</h2>
${CHANGELOG_HTML}
]]></description>
      <enclosure
        url="${DMG_URL}"
        sparkle:edSignature="${ED_SIG}"
        length="${LENGTH}"
        type="application/octet-stream"
      />
    </item>
  </channel>
</rss>
EOF

chmod 644 "$APPCAST_TMP"
if ! xmllint --noout "$APPCAST_TMP"; then
  echo "ERROR: generated appcast is not well-formed XML; existing appcast was preserved." >&2
  exit 1
fi
mv "$APPCAST_TMP" "$APPCAST_OUT"
APPCAST_TMP=""

echo "Wrote: $APPCAST_OUT"
echo ""
if [ "${RELEASE_PIPELINE:-}" != "1" ]; then
  echo "Standalone appcast generation does not complete a release."
  echo "Use ./scripts/release.sh for the coordinated metadata, upload, and verification transaction."
fi
