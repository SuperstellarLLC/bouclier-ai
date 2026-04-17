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
