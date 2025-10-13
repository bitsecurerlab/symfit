#!/bin/bash
# Test script for stdin input mode

set -e

echo "Testing Stdin Input Mode"
echo "========================"
echo

# Create a test binary that reads from stdin
TEST_DIR="/tmp/symfit-stdin-test"
mkdir -p "$TEST_DIR"

cat > "$TEST_DIR/stdin_reader.c" << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    char buf[32] = {0};

    // Read from stdin instead of a file
    size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);

    if (n < 1) {
        return 1;
    }

    // Some branches to explore
    if (buf[0] == 'S') {
        puts("Found S");
        if (buf[1] == 'T') {
            puts("Found ST");
            if (buf[2] == 'D') {
                puts("Found STD");
                if (buf[3] == 'I') {
                    puts("Found STDIN");
                    if (buf[4] == 'N') {
                        puts("Complete: STDIN");
                    }
                }
            }
        }
    } else {
        puts("No S");
    }

    return 0;
}
EOF

echo "✓ Created test program that reads from stdin"

# Compile the test binary statically to avoid GLIBC issues
gcc -static -o "$TEST_DIR/stdin_reader" "$TEST_DIR/stdin_reader.c"
echo "✓ Compiled stdin_reader binary (static)"

# Test with Docker using stdin mode
WORK_DIR="$TEST_DIR/workdir"
mkdir -p "$WORK_DIR/output"

# Create input file (will be piped to stdin)
echo "test" > "$WORK_DIR/stdin_input"
echo "✓ Created stdin_input with test data"

# Run Docker with stdin mode
echo
echo "Running symbolic execution with stdin input..."
docker run --rm -i \
  --user $(id -u):$(id -g) \
  -v "$WORK_DIR:/workdir" \
  -v "$TEST_DIR/stdin_reader:/binary:ro" \
  -e "SYMCC_INPUT_FILE=/workdir/stdin_input" \
  -e "SYMCC_OUTPUT_DIR=/workdir/output" \
  -e "SYMCC_AFL_COVERAGE_MAP=/workdir/covmap" \
  -e "TAINT_OPTIONS=taint_file=/workdir/stdin_input" \
  -w /workdir \
  ghcr.io/bitsecurerlab/symfit:latest \
  /bin/sh -c "cat /workdir/stdin_input | /workspace/build/symsan/bin/fgtest /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 /binary"

echo
if [ -d "$WORK_DIR/output" ] && [ "$(ls -A $WORK_DIR/output 2>/dev/null)" ]; then
    GENERATED=$(ls "$WORK_DIR/output" | wc -l)
    echo "✓ SUCCESS: Generated $GENERATED test cases with stdin input!"
    echo
    echo "Generated files:"
    ls -lh "$WORK_DIR/output"
    echo
    echo "Sample generated inputs:"
    for f in $(ls "$WORK_DIR/output" | head -5); do
        echo "  $f: $(cat "$WORK_DIR/output/$f" | xxd -p | tr -d '\n' | head -c 40)..."
    done
else
    echo "❌ FAILED: No test cases generated"
    exit 1
fi

# Cleanup
rm -rf "$TEST_DIR"

echo
echo "Test passed! Stdin input mode works correctly."
