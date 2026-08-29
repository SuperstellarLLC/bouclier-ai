#!/bin/bash
set -euo pipefail

# Ensures the CoreML PromptGuard 2 model is built, verified, and on disk.
# Idempotent: a no-op when the complete reviewed artifact is already present.
# Used by release.sh so
# fresh clones (or any machine missing the gitignored model) can produce
# a shippable build with one command.
#
# The .mlpackage is too large for git (288MB; exceeds GitHub's 100MB
# per-file limit) but reproducible from Meta's HuggingFace checkpoint
# via convert-promptguard.py. First run takes ~5 min + ~350MB download.
#
# Usage:
#   ./scripts/ensure-model.sh           # builds if missing
#   ./scripts/ensure-model.sh --force   # rebuilds even if present
#
# Prerequisites:
#   - Python 3.11 or 3.12 available as `python3.11` / `python3.12`
#   - HuggingFace account with access to meta-llama/Llama-Prompt-Guard-2-86M
#     (gated model — request access + `huggingface-cli login` one-time)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv-ml"
MLPACKAGE="$PROJECT_DIR/Sources/Bouclier/Resources/PromptGuard2.mlpackage"
TOKENIZER="$PROJECT_DIR/Sources/Bouclier/Resources/PromptGuardTokenizer"
REQUIREMENTS_LOCK="$SCRIPT_DIR/requirements-promptguard.lock"
ARTIFACT_VERIFIER="$SCRIPT_DIR/verify-promptguard-artifacts.py"

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
  esac
done

# ── Interpreter ──────────────────────────────────
# The pinned conversion toolchain supports Python 3.11–3.12 only. Check the
# actual version rather than trusting a generic `python3` executable name.
BASEPY=""
for cand in python3.12 python3.11 python3; do
  if command -v "$cand" >/dev/null 2>&1 \
    && "$cand" -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] <= (3, 12) else 1)' 2>/dev/null; then
    BASEPY="$cand"
    break
  fi
done
if [ -z "$BASEPY" ]; then
  echo "ERROR: PromptGuard conversion requires Python 3.11 or 3.12." >&2
  echo "       Install one of those versions and expose python3.12 or python3.11 on PATH." >&2
  exit 1
fi

# ── Verify or build ────────────────────────────────
# Presence alone is not sufficient: both artifacts are gitignored and could
# otherwise be stale, locally modified, or generated from another revision.
if [ "$FORCE" = false ] && { \
  [ -e "$MLPACKAGE" ] || [ -L "$MLPACKAGE" ] \
    || [ -e "$TOKENIZER" ] || [ -L "$TOKENIZER" ]; \
}; then
  if "$BASEPY" -I "$ARTIFACT_VERIFIER"; then
    size_mb=$(du -sm "$MLPACKAGE" | cut -f1)
    echo "  ✓ CoreML model already present and verified (${size_mb}MB)"
    echo "    Pass --force to rebuild from the pinned source revision"
    exit 0
  fi
  echo "ERROR: existing PromptGuard artifacts are incomplete or unreviewed." >&2
  echo "       Investigate the mismatch; use --force only to reproduce the pinned artifact." >&2
  exit 1
fi

echo "  Building CoreML model at $MLPACKAGE"
echo "  (first run ~5 min + ~350MB download; subsequent runs are instant)"

# ── Venv ────────────────────────────────────────
PY="$VENV/bin/python3"

# A conversion is rare and security-sensitive. Never reuse the ignored venv:
# an otherwise valid existing environment can contain unlisted packages,
# sitecustomize.py, or executable .pth files that run before pip gets a chance
# to verify the lock. A reviewed artifact already exited above, so rebuilding
# this environment costs nothing on the normal release path.
if [ -e "$VENV" ] || [ -L "$VENV" ]; then
  echo "  Removing the previous untrusted conversion environment."
  rm -rf "$VENV"
fi
echo "  Creating a fresh isolated Python venv at .venv-ml/ ($("$BASEPY" --version 2>&1))..."
"$BASEPY" -I -m venv "$VENV"
# Some base pythons produce a venv without pip; ensurepip backfills it.
"$PY" -I -m ensurepip --upgrade >/dev/null 2>&1 || true

if ! "$PY" -I -m pip --isolated --version >/dev/null 2>&1; then
  echo "ERROR: could not get a working pip inside $VENV." >&2
  echo "       Your base python ($BASEPY) may lack ensurepip. Try: $BASEPY -m ensurepip" >&2
  exit 1
fi

# ── Deps ────────────────────────────────────────
# The complete conversion closure is exact-pinned and hash-locked to the
# reviewed Apple-silicon wheels for both supported Python versions. Refuse
# source distributions, unlisted artifacts, implicit dependencies, and a
# previously installed unverified environment. The final artifact verifier is
# the second line of defence: even reviewed dependencies cannot silently
# produce different release bytes.
echo "  Installing hash-verified PromptGuard conversion dependencies..."
"$PY" -I -m pip --isolated install \
  --quiet \
  --force-reinstall \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  --requirement "$REQUIREMENTS_LOCK"
"$PY" -I -m pip --isolated check

# ── HuggingFace auth ────────────────────────────
# PromptGuard 2 is a gated model. We can't interactively log the user in
# from inside a release pipeline, so fail fast with actionable guidance.
# Check auth via the library (token is shared across CLIs via
# ~/.cache/huggingface/token or the HF_TOKEN env var).
if ! "$PY" -I -c "from huggingface_hub import whoami; whoami()" >/dev/null 2>&1; then
  cat >&2 << EOF

ERROR: Not authenticated with HuggingFace.
       Meta Prompt Guard 2 is a gated model — you need access first.

  1. Request access:   https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
  2. Generate a token: https://huggingface.co/settings/tokens   (type: Read)
  3. Log in:           "$VENV/bin/huggingface-cli" login
       (or: export HF_TOKEN=hf_your_token_here)

Then rerun this script.
EOF
  exit 1
fi

# ── Convert ─────────────────────────────────────
"$PY" -I "$SCRIPT_DIR/convert-promptguard.py"

# ── Verify ──────────────────────────────────────
"$PY" -I "$ARTIFACT_VERIFIER"

size_mb=$(du -sm "$MLPACKAGE" | cut -f1)
echo "  ✓ CoreML model built and verified (${size_mb}MB)"
