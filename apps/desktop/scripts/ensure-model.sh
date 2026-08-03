#!/bin/bash
set -euo pipefail

# Ensures the CoreML PromptGuard 2 model is built and on disk. Idempotent:
# a no-op when the .mlpackage is already present. Used by release.sh so
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
#   - Python 3.11+ available as `python3`
#   - HuggingFace account with access to meta-llama/Llama-Prompt-Guard-2-86M
#     (gated model — request access + `huggingface-cli login` one-time)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/.venv-ml"
MLPACKAGE="$PROJECT_DIR/Sources/Bouclier/Resources/PromptGuard2.mlpackage"

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
  esac
done

# ── Skip if already built ───────────────────────
if [ "$FORCE" = false ] && [ -f "$MLPACKAGE/Manifest.json" ]; then
  size_mb=$(du -sm "$MLPACKAGE" | cut -f1)
  echo "  ✓ CoreML model already present (${size_mb}MB) — skipping build"
  echo "    Pass --force to rebuild"
  exit 0
fi

echo "  Building CoreML model at $MLPACKAGE"
echo "  (first run ~5 min + ~350MB download; subsequent runs are instant)"

# ── Venv ────────────────────────────────────────
# Pick a CoreML-compatible base interpreter. coremltools and torch wheels
# lag new Python releases, so whatever `python3` happens to be (e.g. a
# brand-new 3.14 with no wheels) is the wrong default — prefer 3.12/3.11.
BASEPY=""
for cand in python3.12 python3.11 python3.13 python3.10 python3; do
  if command -v "$cand" >/dev/null 2>&1; then BASEPY="$cand"; break; fi
done
if [ -z "$BASEPY" ]; then
  echo "ERROR: no python3 interpreter found on PATH." >&2
  exit 1
fi

PY="$VENV/bin/python3"

# (Re)create the venv if it's missing, broken (no working pip — a stale
# .venv-ml can lack pip entirely, which failed with "pip: command not
# found"), or built on a Python too new for the ML wheels (3.13+).
needs_venv=false
if [ ! -x "$PY" ] || ! "$PY" -m pip --version >/dev/null 2>&1; then
  needs_venv=true
elif [ "$("$PY" -c 'import sys; print(1 if sys.version_info[:2] <= (3,12) else 0)' 2>/dev/null || echo 0)" != "1" ]; then
  echo "  Existing .venv-ml uses a Python too new for CoreML wheels — rebuilding."
  needs_venv=true
fi

if [ "$needs_venv" = true ]; then
  echo "  Creating Python venv at .venv-ml/ ($("$BASEPY" --version 2>&1))..."
  rm -rf "$VENV"
  "$BASEPY" -m venv "$VENV"
  # Some base pythons produce a venv without pip; ensurepip backfills it.
  "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi

if ! "$PY" -m pip --version >/dev/null 2>&1; then
  echo "ERROR: could not get a working pip inside $VENV." >&2
  echo "       Your base python ($BASEPY) may lack ensurepip. Try: $BASEPY -m ensurepip" >&2
  exit 1
fi

# ── Deps ────────────────────────────────────────
# Call pip via the venv's python (`-m pip`) rather than a bare `pip`, so
# this never depends on `pip` being on PATH or on `activate` having run.
if ! "$PY" -c "import torch, transformers, coremltools, huggingface_hub" 2>/dev/null; then
  echo "  Installing Python dependencies..."
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet \
    "torch<2.8" \
    transformers \
    coremltools \
    sentencepiece \
    protobuf \
    huggingface-hub
fi

# ── HuggingFace auth ────────────────────────────
# PromptGuard 2 is a gated model. We can't interactively log the user in
# from inside a release pipeline, so fail fast with actionable guidance.
# Check auth via the library (token is shared across CLIs via
# ~/.cache/huggingface/token or the HF_TOKEN env var).
if ! "$PY" -c "from huggingface_hub import whoami; whoami()" >/dev/null 2>&1; then
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
"$PY" "$SCRIPT_DIR/convert-promptguard.py"

# ── Verify ──────────────────────────────────────
if [ ! -f "$MLPACKAGE/Manifest.json" ]; then
  echo "ERROR: convert-promptguard.py finished but $MLPACKAGE/Manifest.json is missing" >&2
  exit 1
fi

size_mb=$(du -sm "$MLPACKAGE" | cut -f1)
echo "  ✓ CoreML model built (${size_mb}MB)"
