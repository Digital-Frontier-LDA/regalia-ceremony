#!/usr/bin/env bash
# build.sh — build the ceremony emulator image with the correct build context.
# The context is qubes so the image can bake requirements.txt + scripts.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CTX="$(cd "$HERE/.." && pwd)"
TAG="${1:-ceremony-emu}"
exec docker build -t "$TAG" -f "$HERE/Dockerfile" "$CTX"
