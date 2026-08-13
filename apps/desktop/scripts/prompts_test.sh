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

if [ "$fail" -ne 0 ]; then
  echo "prompts_test: FAILED"
  exit 1
fi
echo "prompts_test: all assertions passed."
