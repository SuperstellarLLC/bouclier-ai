#!/bin/bash
# Tests for the release-pipeline version helpers in _prompts.sh.
#   bash apps/desktop/scripts/prompts_test.sh
#
# Deliberately NOT `set -e`: we run every assertion and report all failures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_prompts.sh
source "$SCRIPT_DIR/_prompts.sh"

fail=0
assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    printf '  ok    %s\n' "$desc"
  else
    printf 'FAIL    %s\n          expected: %q\n          actual:   %q\n' "$desc" "$expected" "$actual"
    fail=1
  fi
}

assert_status() {
  local desc="$1" expected="$2"
  shift 2
  "$@" >/dev/null 2>&1
  local actual=$?
  assert_eq "$desc" "$expected" "$actual"
}

# --- default_release_version ---
assert_eq "prepped-but-uncut -> prepped version" "0.9.8" "$(default_release_version 0.9.8 0.9.7 0.9.9)"
assert_eq "already released -> next patch"        "0.9.9" "$(default_release_version 0.9.8 0.9.8 0.9.9)"
assert_eq "no constants version -> next patch"    "0.9.9" "$(default_release_version '' 0.9.7 0.9.9)"
assert_eq "no released info -> prepped version"   "0.9.8" "$(default_release_version 0.9.8 '' 0.9.9)"

# --- latest_released_version ---
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/single.xml" <<'XML'
<item><sparkle:shortVersionString>0.9.7</sparkle:shortVersionString></item>
XML
assert_eq "appcast single item" "0.9.7" "$(latest_released_version "$tmp/single.xml")"

cat > "$tmp/multi.xml" <<'XML'
<item><sparkle:shortVersionString>0.9.5</sparkle:shortVersionString></item>
<item><sparkle:shortVersionString>0.9.7</sparkle:shortVersionString></item>
<item><sparkle:shortVersionString>0.9.6</sparkle:shortVersionString></item>
XML
assert_eq "appcast picks highest of many" "0.9.7" "$(latest_released_version "$tmp/multi.xml")"

cat > "$tmp/attr.xml" <<'XML'
<enclosure url="https://x/Bouclier-ai-v0.9.7-macOS.dmg" sparkle:shortVersionString="0.9.7" sparkle:version="7"/>
XML
assert_eq "appcast attribute form" "0.9.7" "$(latest_released_version "$tmp/attr.xml")"

assert_eq "missing appcast -> empty" "" "$(latest_released_version "$tmp/does-not-exist.xml")"

# --- integration: the exact footgun this fixes ---
# constants prepped to 0.9.8 while the appcast still reads 0.9.7 must default to
# 0.9.8, never bump_patch(0.9.8) = 0.9.9.
released="$(latest_released_version "$tmp/single.xml")" # 0.9.7
assert_eq "footgun: prepped 0.9.8 over released 0.9.7 -> 0.9.8" "0.9.8" \
  "$(default_release_version 0.9.8 "$released" "$(bump_patch 0.9.8)")"

# --- immutable release versions ---
assert_status "patch version is newer" 0 semver_greater_than 0.9.11 0.9.10
assert_status "minor version is newer" 0 semver_greater_than 0.10.0 0.9.99
assert_status "major version is newer" 0 semver_greater_than 1.0.0 0.99.99
assert_status "same version is rejected" 1 semver_greater_than 0.9.10 0.9.10
assert_status "older version is rejected" 1 semver_greater_than 0.9.9 0.9.10
assert_status "malformed candidate is rejected" 1 semver_greater_than 0.9 0.9.10

# --- appcast/download URL safety ---
assert_status "HTTPS Blob path accepted" 0 valid_download_base_url \
  https://example.public.blob.vercel-storage.com/download
assert_status "HTTPS URL with port accepted" 0 valid_download_base_url \
  https://localhost:8443/releases/v1
assert_status "HTTPS origin accepted" 0 valid_download_base_url https://downloads.example.com
assert_status "HTTP URL rejected" 1 valid_download_base_url http://example.com/download
assert_status "query string rejected" 1 valid_download_base_url \
  'https://example.com/download?token=secret'
assert_status "XML metacharacters rejected" 1 valid_download_base_url \
  'https://example.com/download&bad'

# --- public object verification ---
# Stub curl as a shell function so this test exercises the real macOS awk
# header parser without network access or sleeping on the mismatch case.
curl() {
  local header_file=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "--dump-header" ]; then
      shift
      header_file="$1"
    fi
    shift
  done
  printf 'HTTP/2 200\r\ncontent-length: %s\r\n\r\n' "${STUB_CONTENT_LENGTH:-4}" > "$header_file"
  printf '200'
}
sleep() { :; }
printf 'test' > "$tmp/artifact.dmg"
assert_status "public object size accepted" 0 verify_public_file \
  https://downloads.example.com/artifact.dmg "$tmp/artifact.dmg"
STUB_CONTENT_LENGTH=3
assert_status "public object size mismatch rejected" 1 verify_public_file \
  https://downloads.example.com/artifact.dmg "$tmp/artifact.dmg"
unset STUB_CONTENT_LENGTH
unset -f curl sleep

if [ "$fail" -ne 0 ]; then
  echo "prompts_test: FAILED"
  exit 1
fi
echo "prompts_test: all assertions passed."
