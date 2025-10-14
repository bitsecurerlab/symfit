#!/bin/bash
# Test script for custom input filename feature

set -e

echo "Testing Custom Input Filename Feature"
echo "======================================"
echo

# Create a test binary that reads from "input.dat" instead of "testfile"
TEST_DIR="/tmp/symfit-custom-test"
mkdir -p "$TEST_DIR"

cat > "$TEST_DIR/custom_reader.c" << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    char buf[32] = {0};
    FILE *f = fopen("input.dat", "r");  // Reads from "input.dat"

    if (!f) {
        fprintf(stderr, "Failed to open input.dat\n");
        return 1;
    }

    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (n < 1) {
        return 1;
    }

    // Some branches to explore
    if (buf[0] == 'X') {
        puts("Found X");
        if (buf[1] == 'Y') {
            puts("Found XY");
        }
    } else {
        puts("No X");
    }

    return 0;
}
EOF

echo "✓ Created test program that reads from 'input.dat'"

# Compile the test binary
gcc -o "$TEST_DIR/custom_reader" "$TEST_DIR/custom_reader.c"
echo "✓ Compiled custom_reader binary"

# Test with Docker using custom filename
WORK_DIR="$TEST_DIR/workdir"
mkdir -p "$WORK_DIR/output"

# Create input file with custom name
echo "test" > "$WORK_DIR/input.dat"
echo "✓ Created input.dat with test data"

# Run Docker with custom filename
echo
echo "Running symbolic execution with custom filename 'input.dat'..."
docker run --rm \
  --user $(id -u):$(id -g) \
  -v "$WORK_DIR:/workdir" \
  -v "$TEST_DIR/custom_reader:/binary:ro" \
  -e "SYMCC_INPUT_FILE=/workdir/input.dat" \
  -e "SYMCC_OUTPUT_DIR=/workdir/output" \
  -e "SYMCC_AFL_COVERAGE_MAP=/workdir/covmap" \
  -e "TAINT_OPTIONS=taint_file=/workdir/input.dat" \
  -w /workdir \
  ghcr.io/bitsecurerlab/symfit:latest \
  /workspace/build/symsan/bin/fgtest \
  /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /binary

echo
if [ -d "$WORK_DIR/output" ] && [ "$(ls -A $WORK_DIR/output 2>/dev/null)" ]; then
    GENERATED=$(ls "$WORK_DIR/output" | wc -l)
    echo "✓ SUCCESS: Generated $GENERATED test cases with custom filename!"
    echo
    echo "Generated files:"
    ls -lh "$WORK_DIR/output"
else
    echo "❌ FAILED: No test cases generated"
    exit 1
fi

# Cleanup
rm -rf "$TEST_DIR"

echo
echo "Test passed! Custom input filename feature works correctly."
