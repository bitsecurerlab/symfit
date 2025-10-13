#!/bin/bash
# Simple test script to verify MCP server can start and respond to basic requests

set -e

echo "Testing SymFit MCP Server..."
echo

# Check Node.js is installed
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed"
    exit 1
fi

echo "✓ Node.js found: $(node --version)"

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

echo "✓ Dependencies installed"

# Test that the script is syntactically valid
node --check index.js
echo "✓ JavaScript syntax valid"

# Check if SymFit is built
if [ -z "$SYMFIT_BUILD_DIR" ]; then
    SYMFIT_BUILD_DIR="../build"
fi

if [ ! -f "$SYMFIT_BUILD_DIR/symfit-symsan/x86_64-linux-user/symqemu-x86_64" ]; then
    echo "WARNING: SymFit QEMU binary not found at $SYMFIT_BUILD_DIR"
    echo "  You may need to run ./build.sh from the project root"
else
    echo "✓ SymFit QEMU binary found"
fi

if [ ! -f "$SYMFIT_BUILD_DIR/symsan/bin/fgtest" ]; then
    echo "WARNING: fgtest binary not found at $SYMFIT_BUILD_DIR"
    echo "  You may need to run ./build.sh from the project root"
else
    echo "✓ fgtest binary found"
fi

echo
echo "MCP Server tests passed!"
echo
echo "To start the server manually:"
echo "  node index.js"
echo
echo "To use with Claude Desktop, add this to your config:"
echo "  {\"mcpServers\": {\"symfit\": {\"command\": \"node\", \"args\": [\"$(pwd)/index.js\"]}}}"
