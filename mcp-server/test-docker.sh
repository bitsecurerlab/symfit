#!/bin/bash
# Test script to verify Docker-based MCP server functionality

set -e

echo "Testing SymFit MCP Server (Docker Mode)..."
echo

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

echo "✓ Docker found: $(docker --version)"

# Check if SymFit image exists
if ! docker images | grep -q "bitsecurerlab/symfit"; then
    echo "WARNING: SymFit Docker image not found"
    echo "  Pulling image..."
    docker pull ghcr.io/bitsecurerlab/symfit:latest
fi

echo "✓ SymFit Docker image found"

# Check test binary exists
TEST_BINARY="/home/heng/git/symfit/tests/symfit/test"
if [ ! -f "$TEST_BINARY" ]; then
    echo "ERROR: Test binary not found at $TEST_BINARY"
    echo "  Compile it with: cd ../tests/symfit && gcc -o test test.c"
    exit 1
fi

echo "✓ Test binary found: $TEST_BINARY"

# Create test directory
WORK_DIR="/home/heng/git/symfit/mcp-workdir/docker-test"
mkdir -p "$WORK_DIR/output"

# Create test input
echo "test" > "$WORK_DIR/testfile"

echo "✓ Test environment ready"

# Test Docker execution
echo
echo "Testing Docker execution..."
docker run --rm \
  -v "$WORK_DIR:/workdir" \
  -v "$TEST_BINARY:/binary:ro" \
  -e "SYMCC_INPUT_FILE=/workdir/testfile" \
  -e "SYMCC_OUTPUT_DIR=/workdir/output" \
  -e "SYMCC_AFL_COVERAGE_MAP=/workdir/covmap" \
  -e "TAINT_OPTIONS=taint_file=/workdir/testfile" \
  -w /workdir \
  ghcr.io/bitsecurerlab/symfit:latest \
  /workspace/build/symsan/bin/fgtest \
  /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /binary

echo
echo "✓ Docker execution successful"

# Check if output was generated
if [ -d "$WORK_DIR/output" ] && [ "$(ls -A $WORK_DIR/output)" ]; then
    echo "✓ Generated test cases: $(ls $WORK_DIR/output | wc -l)"
else
    echo "WARNING: No test cases generated (this might be normal)"
fi

echo
echo "Docker-based MCP Server tests passed!"
echo
echo "The MCP server is configured to use Docker by default."
echo "To test the MCP server, reload VS Code and try:"
echo "  'Use SymFit to analyze the test binary with a 3-round campaign'"
