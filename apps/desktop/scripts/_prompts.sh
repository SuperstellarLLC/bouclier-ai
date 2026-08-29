# Shared interactive-prompt helpers for release-pipeline scripts.
# Source this file — do not execute it directly.
#
#   source "$SCRIPT_DIR/_prompts.sh"
#
# Every helper is a no-op when the target variable is already set in the
# environment, so callers (release.sh → build-app.sh → publish-update.sh)
# pass values forward without re-prompting.

prompt_required() {
  # $1 = var name, $2 = label, $3 = optional example
  local varname="$1" label="$2" example="${3:-}"
  if [ -z "${!varname:-}" ]; then
    if [ -n "$example" ]; then
      read -rp "$label (e.g. $example): " value
    else
      read -rp "$label: " value
    fi
    printf -v "$varname" '%s' "$value"
  fi
  if [ -z "${!varname:-}" ]; then
    echo "$label is required." >&2
    exit 1
  fi
}

prompt_with_default() {
  # $1 = var name, $2 = label, $3 = default
  local varname="$1" label="$2" default="$3"
  if [ -z "${!varname:-}" ]; then
    read -rp "$label [$default]: " value
    printf -v "$varname" '%s' "${value:-$default}"
  fi
}

prompt_secret() {
  # $1 = var name, $2 = label
  local varname="$1" label="$2"
  if [ -z "${!varname:-}" ]; then
    echo -n "$label: "
    read -rs value
    echo ""
    printf -v "$varname" '%s' "$value"
  fi
  if [ -z "${!varname:-}" ]; then
    echo "$label is required." >&2
    exit 1
  fi
}

# Read APP_VERSION from apps/site/src/lib/constants.ts. Empty string if
# unreadable — callers should pick a static fallback in that case.
current_app_version() {
  local constants_file="$1"
  [ -f "$constants_file" ] || { echo ""; return; }
  awk -F'"' '/APP_VERSION =/ {print $2; exit}' "$constants_file"
}

# Bump the patch component of a semver string ("0.2.6" → "0.2.7"). Empty
# input → empty output so callers can chain this with `current_app_version`
# and fall through to a hardcoded default if the read failed.
bump_patch() {
  local v="$1"
  [ -n "$v" ] || { echo ""; return; }
  echo "$v" | awk -F. '{printf "%d.%d.%d\n", $1, $2, $3+1}'
}

# Highest-version DMG present in the build directory, returned as a bare
# semver ("0.2.7"). Used by publish-update.sh to default to whatever was
# last built — the appcast regenerates for the artifact sitting on disk,
# not for a hypothetical next release.
latest_built_version() {
  local build_dir="$1"
  [ -d "$build_dir" ] || { echo ""; return; }
  ls -1 "$build_dir" 2>/dev/null \
    | grep -E '^Bouclier-ai-v[0-9]+\.[0-9]+\.[0-9]+-macOS\.dmg$' \
    | sed -E 's/^Bouclier-ai-v(.+)-macOS\.dmg$/\1/' \
    | sort -V \
    | tail -1
}

# Highest version published in the signed Sparkle appcast — the last version
# actually *released* to users (distinct from `latest_built_version`, which
# only reflects a DMG sitting on disk). Bare semver ("0.9.7"), empty if
# unreadable. Handles multiple <item>s and both the element and attribute
# short-version forms. Always exits 0 (safe under `set -euo pipefail`).
latest_released_version() {
  local appcast_file="$1"
  [ -f "$appcast_file" ] || { echo ""; return 0; }
  { grep 'shortVersionString' "$appcast_file" 2>/dev/null \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' \
      | sort -V \
      | tail -1; } || true
}

# The version to offer at the release prompt. When the prepped version in
# constants.ts ($current, == CHANGELOG top, drift-enforced) is already ahead of
# the last *released* version ($released), a release has been prepped but not
# yet cut — offer that prepped version rather than $next (the next patch), so
# the maintainer doesn't have to retype the real number on every prepped
# release. Once the prepped version has shipped (current == released), fall
# through to the next patch.
default_release_version() {
  local current="$1" released="$2" next="$3"
  if [ -n "$current" ] && [ "$current" != "$released" ]; then
    printf '%s\n' "$current"
  else
    printf '%s\n' "$next"
  fi
}

# True only when $1 is a numeric x.y.z version strictly newer than $2. Release
# artifacts use stable versioned URLs, so equality is intentionally rejected:
# a published version must be immutable even when a local rebuild exists.
semver_greater_than() {
  local candidate="$1" released="$2"
  [[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  [[ "$released" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  awk -v candidate="$candidate" -v released="$released" '
    BEGIN {
      split(candidate, proposed, ".")
      split(released, previous, ".")
      for (part = 1; part <= 3; part++) {
        if ((proposed[part] + 0) > (previous[part] + 0)) exit 0
        if ((proposed[part] + 0) < (previous[part] + 0)) exit 1
      }
      exit 1
    }
  '
}

# Release URLs are embedded unescaped in an XML attribute and are also used to
# derive a Blob pathname. Restrict them to HTTPS plus an intentionally small,
# XML-safe URL alphabet instead of trying to repair arbitrary input later.
valid_download_base_url() {
  local url="$1"
  [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~%+@=-]+)*$ ]]
}

portable_file_size() {
  local path="$1"
  stat -f%z "$path" 2>/dev/null || stat --format=%s "$path"
}

# Confirm that the public object referenced by the appcast exists and has the
# complete local byte length. Blob/CDN propagation can be briefly eventual, so
# retry a few times before failing the surrounding metadata transaction.
verify_public_file() {
  local url="$1" path="$2"
  local expected_size attempt headers status content_length
  expected_size=$(portable_file_size "$path") || return 1

  attempt=1
  status=""
  content_length=""
  while [ "$attempt" -le 5 ]; do
    headers=$(mktemp /tmp/bouclier-public-head.XXXXXX) || return 1
    status=$(curl --silent --show-error --location --head \
      --dump-header "$headers" \
      --output /dev/null \
      --write-out '%{http_code}' \
      "$url") || status=""
    content_length=$(awk '
      /^HTTP\// { content_length_value = "" }
      tolower($1) == "content-length:" {
        gsub(/\r/, "", $2)
        content_length_value = $2
      }
      END { print content_length_value }
    ' "$headers")
    rm -f "$headers"

    if [ "$status" = "200" ] && [ "$content_length" = "$expected_size" ]; then
      echo "  ✓ Public object verified (HTTP 200, ${expected_size} bytes)"
      return 0
    fi
    if [ "$attempt" -lt 5 ]; then
      sleep 2
    fi
    attempt=$((attempt + 1))
  done

  echo "ERROR: public artifact verification failed for $url" >&2
  echo "       expected HTTP 200 and ${expected_size} bytes; got HTTP ${status:-none} and ${content_length:-no Content-Length}." >&2
  return 1
}
