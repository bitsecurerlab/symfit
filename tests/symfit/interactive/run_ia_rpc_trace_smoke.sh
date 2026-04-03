#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"
SYMFIT="${SYMFIT:-$BUILD_DIR/symfit-symsan/x86_64-linux-user/symfit-x86_64}"
FGTEST="${FGTEST:-$BUILD_DIR/symsan/bin/fgtest}"
RUNNER="${RUNNER:-direct}"
TARGET="${TARGET:-/bin/sleep}"
SOCKET_PATH="${SOCKET_PATH:-$PROJECT_ROOT/mcp-workdir/ia-trace-smoke.sock}"

if [[ ! -x "$SYMFIT" ]]; then
  echo "symfit binary not found or not executable: $SYMFIT" >&2
  exit 1
fi

if [[ "$RUNNER" == "fgtest" && ! -x "$FGTEST" ]]; then
  echo "fgtest not found or not executable: $FGTEST" >&2
  exit 1
fi

mkdir -p "$(dirname "$SOCKET_PATH")"

exec "$SCRIPT_DIR/ia_rpc_trace_smoke.py" \
  --runner "$RUNNER" \
  --symfit "$SYMFIT" \
  --fgtest "$FGTEST" \
  --target "$TARGET" \
  --socket "$SOCKET_PATH" \
  "$@"
