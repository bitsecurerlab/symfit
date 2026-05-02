#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build/symfit}"

exec python3 "$SCRIPT_DIR/symfit_system_smoke.py" \
  --build-dir "$BUILD_DIR" \
  "$@"
