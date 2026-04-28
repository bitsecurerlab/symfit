#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"
SYMFIT="${SYMFIT:-$BUILD_DIR/symfit/x86_64-linux-user/symfit-x86_64}"
FGTEST="${FGTEST:-$BUILD_DIR/symsan/bin/fgtest}"
RUNNER="${RUNNER:-direct}"
SOCKET_PATH="${SOCKET_PATH:-/tmp/symfit-ia-client.sock}"

if [[ "${1:-}" == "--spawn" && ! -x "$SYMFIT" ]]; then
  echo "symfit binary not found or not executable: $SYMFIT" >&2
  exit 1
fi

if [[ "${1:-}" == "--spawn" && "$RUNNER" == "fgtest" && ! -x "$FGTEST" ]]; then
  echo "fgtest not found or not executable: $FGTEST" >&2
  exit 1
fi

exec "$SCRIPT_DIR/ia_rpc_client.py" \
  --socket "$SOCKET_PATH" \
  --runner "$RUNNER" \
  --symfit "$SYMFIT" \
  --fgtest "$FGTEST" \
  "$@"
