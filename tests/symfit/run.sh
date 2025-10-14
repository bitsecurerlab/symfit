#!/bin/bash
# SymFit Automated Testing Script
# Iteratively generates test cases using symbolic execution

set -e

# Enable debug mode if DEBUG=1
if [ "${DEBUG:-0}" = "1" ]; then
    set -x
fi

# Determine the project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$PROJECT_ROOT/build}"
TEST_BINARY="${TEST_BINARY:-$SCRIPT_DIR/test}"
SYMFIT="${SYMFIT:-$BUILD_DIR/symfit-symsan/x86_64-linux-user/symqemu-x86_64}"
FGTEST="${FGTEST:-$BUILD_DIR/symsan/bin/fgtest}"

# Working directories
WORK_DIR="$SCRIPT_DIR/workdir"
CORPUS_DIR="$WORK_DIR/corpus"
OUTPUT_DIR="$WORK_DIR/output"
COVERAGE_MAP="$WORK_DIR/covmap"

# Print configuration
echo "=== Configuration ==="
echo "SCRIPT_DIR: $SCRIPT_DIR"
echo "PROJECT_ROOT: $PROJECT_ROOT"
echo "BUILD_DIR: $BUILD_DIR"
echo "TEST_BINARY: $TEST_BINARY"
echo "SYMFIT: $SYMFIT"
echo "FGTEST: $FGTEST"
echo "WORK_DIR: $WORK_DIR"
echo ""

# Check if required binaries exist
echo "=== Checking Required Files ==="
if [ ! -f "$FGTEST" ]; then
    echo "ERROR: fgtest not found at: $FGTEST"
    exit 1
else
    echo "✓ fgtest found: $FGTEST"
fi

if [ ! -f "$SYMFIT" ]; then
    echo "ERROR: symqemu-x86_64 not found at: $SYMFIT"
    exit 1
else
    echo "✓ symqemu found: $SYMFIT"
fi
echo ""

# Create directories if they don't exist
mkdir -p "$CORPUS_DIR" "$OUTPUT_DIR"

# Initialize corpus with a simple seed if empty
if [ -z "$(ls -A "$CORPUS_DIR")" ]; then
    echo "Initializing corpus with seed files..."
    echo "test" > "$CORPUS_DIR/seed1"
    echo "ABCDEF" > "$CORPUS_DIR/seed2"
fi

# Compile test program if needed
if [ ! -f "$TEST_BINARY" ] || [ "$SCRIPT_DIR/test.c" -nt "$TEST_BINARY" ]; then
    echo "Compiling test program..."
    gcc -o "$TEST_BINARY" "$SCRIPT_DIR/test.c"
fi

# Multi-round iteration
MAX_ROUNDS=${MAX_ROUNDS:-5}

# Track new test cases to process (start with initial seeds)
NEW_QUEUE="$WORK_DIR/new_queue"
mkdir -p "$NEW_QUEUE"

# Initialize queue with seed files
for seed in "$CORPUS_DIR"/*; do
    [ -f "$seed" ] || continue
    ln -sf "$seed" "$NEW_QUEUE/$(basename "$seed")"
done

for round in $(seq 1 $MAX_ROUNDS); do
    echo "=== Round $round ==="
    echo "Current corpus size: $(ls "$CORPUS_DIR" | wc -l)"

    # Check if queue is empty before processing
    queue_size=$(ls "$NEW_QUEUE" 2>/dev/null | wc -l)
    echo "Test cases to process: $queue_size"

    if [ "$queue_size" -eq 0 ]; then
        echo "Queue is empty, stopping iteration"
        break
    fi

    # Count new cases found in this round
    new_cases=0

    # Create temporary directory for next round's queue
    NEXT_QUEUE="$WORK_DIR/next_queue"
    rm -rf "$NEXT_QUEUE"
    mkdir -p "$NEXT_QUEUE"

    # Process only the new test cases from the queue
    for seed in "$NEW_QUEUE"/*; do
        [ -f "$seed" ] || continue

        echo "Using seed: $(basename "$seed")"
        cp "$seed" "$WORK_DIR/testfile"

        # Set environment variables for symbolic execution
        export SYMCC_INPUT_FILE="$WORK_DIR/testfile"
        export SYMCC_OUTPUT_DIR="$OUTPUT_DIR"
        export SYMCC_AFL_COVERAGE_MAP="$COVERAGE_MAP"
        export TAINT_OPTIONS="taint_file=$WORK_DIR/testfile"

        # Run symbolic execution (change to work dir so relative paths work)
        cd "$WORK_DIR"
        if [ "${DEBUG:-0}" = "1" ]; then
            echo "Running: $FGTEST $SYMFIT $TEST_BINARY (cwd: $WORK_DIR)"
            "$FGTEST" "$SYMFIT" "$TEST_BINARY" || true
        else
            "$FGTEST" "$SYMFIT" "$TEST_BINARY" >/dev/null 2>&1 || true
        fi
        cd "$SCRIPT_DIR"

        # Add newly generated cases to the corpus and next round's queue
        for new_file in "$OUTPUT_DIR"/id-0-0-*; do
            if [ -f "$new_file" ]; then
                hash=$(sha1sum "$new_file" | cut -d' ' -f1)
                if [ ! -f "$CORPUS_DIR/$hash" ]; then
                    cp "$new_file" "$CORPUS_DIR/$hash"
                    ln -sf "$CORPUS_DIR/$hash" "$NEXT_QUEUE/$hash"
                    echo "  Added new testcase: $(basename "$new_file") -> $hash"
                    new_cases=$((new_cases + 1))
                fi
            fi
        done

        # Clean output directory for next iteration
        rm -f "$OUTPUT_DIR"/id-0-0-*
    done

    echo "New cases in round $round: $new_cases"
    if [ $new_cases -eq 0 ]; then
        echo "No new cases generated, stopping iteration"
        break
    fi

    # Replace current queue with next round's queue
    rm -rf "$NEW_QUEUE"
    mv "$NEXT_QUEUE" "$NEW_QUEUE"
done

# Clean up queue directory
rm -rf "$NEW_QUEUE"

echo "Testing complete. Final corpus size: $(ls "$CORPUS_DIR" | wc -l)"
