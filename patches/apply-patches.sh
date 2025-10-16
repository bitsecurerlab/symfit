#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Applying Compatibility Patches ==="
echo "Root directory: $ROOT_DIR"

# Apply SymCC patch (qsym submodule)
echo ""
echo "[1/2] Applying SymCC LLVM 14 compatibility patch..."
cd "$ROOT_DIR/external/symcc/runtime/qsym_backend/qsym"

if git apply --check "$ROOT_DIR/patches/symcc-llvm14-compat.patch" 2>/dev/null; then
    git apply "$ROOT_DIR/patches/symcc-llvm14-compat.patch"
    echo "✓ SymCC patch applied successfully"
elif git diff --quiet; then
    echo "⚠ SymCC: No changes to apply (patch may already be applied)"
else
    echo "⚠ SymCC: Patch conflicts or already applied"
fi

# Apply Symsan patch
echo ""
echo "[2/2] Applying Symsan Ubuntu 22.04 compatibility patch..."
cd "$ROOT_DIR/external/symsan"

if git apply --check "$ROOT_DIR/patches/symsan-ubuntu22-compat.patch" 2>/dev/null; then
    git apply "$ROOT_DIR/patches/symsan-ubuntu22-compat.patch"
    echo "✓ Symsan patch applied successfully"
elif git diff --quiet; then
    echo "⚠ Symsan: No changes to apply (patch may already be applied)"
else
    echo "⚠ Symsan: Patch conflicts or already applied"
fi

cd "$ROOT_DIR"
echo ""
echo "=== Patch Application Complete ==="
echo "You can now run: ./build.sh"
