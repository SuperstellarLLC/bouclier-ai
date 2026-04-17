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
if [ ! -d "$VENV" ]; then
  echo "  Creating Python venv at .venv-ml/..."
  python3 -m venv "$VENV"
fi

# shellcheck source=/dev/null
source "$VENV/bin/activate"

# ── Deps ────────────────────────────────────────
# Check once per import chain — avoids reinstalling on every rebuild.
if ! python3 -c "import torch, transformers, coremltools, huggingface_hub" 2>/dev/null; then
  echo "  Installing Python dependencies..."
  pip install --quiet --upgrade pip
  pip install --quiet \
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
if ! huggingface-cli whoami >/dev/null 2>&1; then
  cat >&2 << 'EOF'

ERROR: Not authenticated with HuggingFace.
       Meta Prompt Guard 2 is a gated model — you need access first.

  1. Request access:   https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
  2. Generate a token: https://huggingface.co/settings/tokens   (type: Read)
  3. Log in:           huggingface-cli login

Then rerun this script.
EOF
  exit 1
fi

# ── Convert ─────────────────────────────────────
python3 "$SCRIPT_DIR/convert-promptguard.py"

# ── Verify ──────────────────────────────────────
if [ ! -f "$MLPACKAGE/Manifest.json" ]; then
  echo "ERROR: convert-promptguard.py finished but $MLPACKAGE/Manifest.json is missing" >&2
  exit 1
fi

size_mb=$(du -sm "$MLPACKAGE" | cut -f1)
echo "  ✓ CoreML model built (${size_mb}MB)"
