#!/bin/bash
set -euo pipefail

# Publishes a Sparkle update for Bouclier.ai.
#
# Prerequisites:
#   1. build/Bouclier-ai-v$VERSION-macOS.dmg exists (signed + notarized + stapled)
#   2. Sparkle EdDSA key is in login Keychain
#   3. DOWNLOAD_BASE_URL env var is set (e.g. the Vercel Blob public URL)
#
# Usage:
#   VERSION=0.2.0 DOWNLOAD_BASE_URL=https://xyz.public.blob.vercel-storage.com ./scripts/publish-update.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SITE_DIR="$(dirname "$(dirname "$PROJECT_DIR")")/apps/site"

VERSION="${VERSION:?VERSION env var required (e.g. 0.2.0)}"
DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL:?DOWNLOAD_BASE_URL env var required}"

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

echo "Signing DMG for Sparkle..."
SIGNATURE=$("$SIGN_UPDATE" "$DMG")
echo "$SIGNATURE"

# Parse the sparkle:edSignature and length from sign_update output
ED_SIG=$(echo "$SIGNATURE" | grep -oP 'sparkle:edSignature="\K[^"]+')
LENGTH=$(echo "$SIGNATURE" | grep -oP 'length="\K[^"]+')
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
    <link>https://bouclier.ai/appcast.xml</link>
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
        <ul>
          <li>161 detection patterns across 21 attack categories (was 35 / 11)</li>
          <li>Streaming SSE response scanning (OpenAI, Anthropic, Gemini, Mistral)</li>
          <li>8 false-positive dampeners for academic, tutorial, and translation contexts</li>
          <li>HTTP pipeline hardening: body-size cap, CRLF rejection, Content-Type gating</li>
          <li>Structured metrics with latency histograms and per-category hit counts</li>
          <li>Export Diagnostics bundle for enterprise support handoff</li>
          <li>MDM feature flags (sseInspection, uriScanning, telemetryEnabled)</li>
          <li>Input validation on all MDM config: ports, hostnames, webhook URLs</li>
          <li>STRIDE threat model published</li>
        </ul>
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
echo "  1. Upload the DMG:  vercel blob upload build/Bouclier-ai-v${VERSION}-macOS.dmg"
echo "  2. Deploy the site: cd $SITE_DIR && vercel --prod"
echo "  3. Existing users will get the update automatically via Sparkle."
