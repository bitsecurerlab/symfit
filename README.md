## What is SymFit?

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.

## Quick Start with Docker

You can check out our ready-to-use Docker container on GitHub Container Registry:

```bash
docker pull ghcr.io/bitsecurerlab/symfit:latest
```

## Building SymFit

To build SymFit from source, use the provided build script:

```bash
./build.sh
```

This will compile SymFit with the SymSan backend. The build artifacts will be located in:
- `build/symfit-symsan/` - SymFit QEMU binaries
- `build/symsan/` - SymSan tools and libraries

## Using SymFit

### Basic Usage

SymFit uses a modified QEMU to perform symbolic execution on binary programs. The basic workflow is:

1. **Prepare your target program** - Compile the program you want to analyze
2. **Set up environment variables** - Configure paths and options
3. **Run symbolic execution** - Execute the program with SymFit

### Running the Example Test

A complete example is provided in `tests/symfit/`:

```bash
cd tests/symfit
./run.sh
```

This automated test will:
- Compile the test program (`test.c`)
- Initialize a corpus with seed inputs
- Iteratively generate new test cases using symbolic execution
- Display progress and results

### Debug Mode

To see detailed execution information:

```bash
DEBUG=1 ./run.sh
```

### Environment Variables

The test script supports the following environment variables for customization:

- `BUILD_DIR` - Path to the build directory (default: `../../build`)
- `SYMFIT` - Path to the SymFit QEMU binary
- `FGTEST` - Path to the fgtest tool
- `TEST_BINARY` - Path to the test binary
- `MAX_ROUNDS` - Maximum number of testing rounds (default: 5)

Example with custom settings:

```bash
MAX_ROUNDS=10 BUILD_DIR=/custom/path ./run.sh
```

### Manual Execution

To manually run SymFit on a program:

```bash
# Set environment variables
export SYMCC_INPUT_FILE=/path/to/input
export SYMCC_OUTPUT_DIR=/path/to/output
export SYMCC_AFL_COVERAGE_MAP=/path/to/covmap
export TAINT_OPTIONS="taint_file=/path/to/input"

# Run symbolic execution
/path/to/build/symsan/bin/fgtest \
  /path/to/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /path/to/your/program
```

### Understanding the Output

SymFit generates new test inputs that explore different execution paths. Generated test cases are saved with names like `id-0-0-*` in the output directory. The test script:
- Deduplicates inputs using SHA1 hashing
- Shows the number of new cases discovered per round
- Stops when no new cases are generated

### Writing Your Own Test Programs

See `tests/symfit/test.c` for an example test program. Key points:

- The program should read input from a file (typically named "testfile")
- Include conditional branches to explore different paths
- Use symbolic input to drive path exploration

## Cite it
If you like to cite SymFit, use the following bibtex:
```
@inproceedings{qi2024symfit,
  title={SymFit: Making the Common (Concrete) Case Fast for Binary-Code Concolic Execution},
  author={Qi, Zhenxiao and Hu, Jie and Xiao, Zhaoqi and Yin, Heng},
  booktitle={USENIX Security Symposium},
  year={2024}
}
```

