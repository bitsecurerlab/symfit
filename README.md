## What is SymFit?

SymFit is a symbolic execution framework for analyzing binaries, supporting multiple backends such as SymCC and SymSan. This document provides instructions for building and running SymFit using Docker.

## Status

Currently porting to QEMU 9.0.

A version of SymFit that supports kernel concolic execution: [https://github.com/enlighten5/symfit-kernel](https://github.com/enlighten5/symfit-kernel)

## MCP Server for LLM Agents

SymFit now includes an MCP (Model Context Protocol) server that enables LLM agents to perform automated concolic execution on binaries. The MCP server provides a standardized interface for:

- Running symbolic execution campaigns
- Managing test case corpora
- Analyzing coverage and results
- Automating binary analysis workflows

See [mcp-server/README.md](mcp-server/README.md) for setup instructions and [mcp-server/EXAMPLES.md](mcp-server/EXAMPLES.md) for usage examples.

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

# Run SymFit
/path/to/build/symsan/bin/fgtest \
  /path/to/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /path/to/your/program
```

## Understanding the Output

SymFit generates:
- **New test cases** in `$SYMCC_OUTPUT_DIR` - Each file is a generated input that explores different execution paths
- **Coverage map** at `$SYMCC_AFL_COVERAGE_MAP` - AFL-style bitmap showing code coverage

## Docker Usage

The Docker image provides a pre-built environment with all dependencies:

```bash
# Run SymFit in Docker
docker run --rm \
  -v /path/to/your/binary:/binary:ro \
  -v /path/to/workdir:/workdir \
  ghcr.io/bitsecurerlab/symfit:latest \
  /workspace/build/symsan/bin/fgtest \
  /workspace/build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
  /binary
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

See LICENSE file for details.
