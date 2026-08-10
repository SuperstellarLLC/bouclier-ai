#!/bin/bash
# Syncs the shared patterns JSON into the Swift app's resources.
# Run this after building the @bouclier-ai/patterns package.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$(dirname "$SCRIPT_DIR")"
PATTERNS_JSON="$DESKTOP_DIR/../../packages/patterns/dist/patterns.json"
RESOURCES_DIR="$DESKTOP_DIR/Sources/Bouclier/Resources"

mkdir -p "$RESOURCES_DIR"

if [ -f "$PATTERNS_JSON" ]; then
    cp "$PATTERNS_JSON" "$RESOURCES_DIR/patterns.json"
    echo "Synced patterns.json → $RESOURCES_DIR/patterns.json"
else
    echo "Warning: patterns.json not found. Run 'pnpm --filter @bouclier-ai/patterns build' first."
    exit 1
fi
