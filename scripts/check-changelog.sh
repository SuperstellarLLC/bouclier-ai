#!/bin/bash
set -euo pipefail

# Guardrail: if a commit bumps APP_VERSION in apps/site/src/lib/constants.ts
# (or the Info.plist build-version string), refuse to commit unless
# CHANGELOG.md has a matching '## [<version>]' section.
#
# Run from .husky/pre-commit. Reads from the staged tree (not the working
# tree), so it stays correct even when only some files are staged.
#
# Bypass for exceptional commits with `git commit --no-verify`.

CONSTANTS="apps/site/src/lib/constants.ts"
INFO_PLIST="apps/desktop/Sources/Bouclier/Resources/Info.plist"
EXT_PLIST="apps/desktop/Sources/BouclierExtension/GeneratedInfo.plist"
CHANGELOG="CHANGELOG.md"

staged_files=$(git diff --cached --name-only)

# Only run when a version-bearing file is in the commit.
if ! echo "$staged_files" | grep -qE "^($CONSTANTS|$INFO_PLIST|$EXT_PLIST)$"; then
  exit 0
fi

# Pull the staged version from constants.ts (the canonical source). Fall
# back to the working tree when the file itself wasn't staged — Info.plist
# changes can land alone.
if echo "$staged_files" | grep -qxF "$CONSTANTS"; then
  VERSION=$(git show ":$CONSTANTS" | awk -F'"' '/APP_VERSION =/ {print $2; exit}')
else
  VERSION=$(awk -F'"' '/APP_VERSION =/ {print $2; exit}' "$CONSTANTS")
fi

if [ -z "${VERSION:-}" ]; then
  echo "❌ Could not determine APP_VERSION from $CONSTANTS" >&2
  exit 1
fi

# Check the CHANGELOG in whichever state it will be after this commit:
# staged content wins, falling back to what's already committed.
if echo "$staged_files" | grep -qxF "$CHANGELOG"; then
  changelog_contents=$(git show ":$CHANGELOG")
else
  changelog_contents=$(cat "$CHANGELOG" 2>/dev/null || true)
fi

# Fixed-string match — the dots in a semver otherwise act as regex
# wildcards and let "0.2.99" pass when only "## [0.2.9]" exists.
if ! echo "$changelog_contents" | grep -qF "## [${VERSION}]"; then
  cat >&2 << EOF
❌ CHANGELOG.md is missing a section for v${VERSION}.

   $CONSTANTS (or an Info.plist) has been bumped to ${VERSION}, but
   CHANGELOG.md has no '## [${VERSION}] — YYYY-MM-DD' section. Add it
   with '### Added' / '### Fixed' / '### Changed' groups before
   committing — the Sparkle appcast draws its release notes from there.

   Bypass for exceptional commits:  git commit --no-verify
EOF
  exit 1
fi

echo "✓ CHANGELOG.md entry for v${VERSION} present."
