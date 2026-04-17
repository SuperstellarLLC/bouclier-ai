#!/bin/bash
set -euo pipefail

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
markdown_to_sparkle_html() {
  awk '
    function flush_item() {
      if (buf != "") { print "<li>" buf "</li>"; buf = "" }
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
      print "<h4>" $0 "</h4>"
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
      if (in_list && buf != "") { buf = buf $0 } else { print "<p>" $0 "</p>" }
      next
    }
    { flush_list(); print "<p>" $0 "</p>" }
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
prompt_with_default DOWNLOAD_BASE_URL "Vercel Blob public URL" \
  "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download"

DMG="$PROJECT_DIR/build/Bouclier-ai-v${VERSION}-macOS.dmg"
SIGN_UPDATE="$PROJECT_DIR/.build/artifacts/sparkle/Sparkle/bin/sign_update"
APPCAST_OUT="$SITE_DIR/public/appcast.xml"

if [ ! -f "$DMG" ]; then
  echo "ERROR: DMG not found at $DMG"
  echo "Run: VERSION=$VERSION ./scripts/build-app.sh --release --sign"
  exit 1
fi

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
DMG_SIZE=$(stat -f%z "$DMG" 2>/dev/null || stat --format=%s "$DMG")

# Use LENGTH from sign_update if available, fall back to file size
LENGTH="${LENGTH:-$DMG_SIZE}"

DATE=$(date -R 2>/dev/null || date -u +"%a, %d %b %Y %H:%M:%S %z")

DMG_URL="${DOWNLOAD_BASE_URL}/Bouclier-ai-v${VERSION}-macOS.dmg"

echo ""
echo "Generating appcast.xml..."

cat > "$APPCAST_OUT" << EOF
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

echo "Wrote: $APPCAST_OUT"
echo ""
echo "Next steps:"
echo "  1. Upload the DMG:  vercel blob put build/Bouclier-ai-v${VERSION}-macOS.dmg \\"
echo "                       --pathname Bouclier-ai-v${VERSION}-macOS.dmg --allow-overwrite"
echo "     (requires BLOB_READ_WRITE_TOKEN env var or folder linked to a Blob project)"
echo "  2. Deploy the site: cd $SITE_DIR && vercel --prod"
echo "  3. Existing users will get the update automatically via Sparkle."
