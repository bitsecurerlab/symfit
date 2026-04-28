#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

export PYTHONPATH="$REPO_ROOT/src"

exec "$REPO_ROOT/.venv/bin/python" -m dynamiq.mcp_server
