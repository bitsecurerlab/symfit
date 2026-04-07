## What is SymFit?

SymFit is a symbolic execution framework for analyzing binaries built around the SymSan backend. This document provides instructions for building and running SymFit using Docker.

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

## Interactive + Scripting Roadmap

The branch development plan for interactive analysis and scripting is documented in:

- [docs/interactive_scripting_contract.md](docs/interactive_scripting_contract.md)

This contract defines a versioned backend RPC surface that can support both interactive debugging-style workflows and symbolic execution commands through a unified API.

## Quick Start with Docker

You can check out our ready-to-use Docker container on GitHub Container Registry:

```bash
docker pull ghcr.io/bitsecurerlab/symfit:latest
```

## Building SymFit

SymFit now builds against a single Symsan checkout at `/mnt/d/git/symsan` to avoid having multiple copies and install trees in play.

Default paths:
- Symsan source: `/mnt/d/git/symsan`
- Symsan build dir: `/mnt/d/git/symsan/build`
- Symsan install/runtime dir: `/mnt/d/git/symsan/install`
- SymFit build dir: `build/symfit-symsan/`

If needed, clone Symsan there first:

```bash
git clone https://github.com/bitsecurerlab/symsan.git /mnt/d/git/symsan
```

Then build:

```bash
./build.sh all
```

Or just rebuild the SymFit binary against the existing Symsan install:

```bash
./build.sh symfit-symsan
```

You can still override paths explicitly:

```bash
SYMSAN_ROOT=/path/to/symsan ./build.sh all
```

This will compile SymFit with the SymSan backend. The build artifacts will be located in:
- `build/symfit-symsan/` - SymFit QEMU binaries
- `/mnt/d/git/symsan/install/` - SymSan tools and libraries used by SymFit

By default, `build.sh` builds both user targets:
- `x86_64-linux-user/symfit-x86_64` (for x86_64 binaries)
- `i386-linux-user/symfit-i386` (for i386 binaries)

You can override this with:

```bash
SYMFIT_TARGET_LIST=x86_64-linux-user ./build.sh symfit-symsan
```

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

### IA/RPC Smoke Test

To validate interactive IA/RPC commands end-to-end against a local build:

```bash
cd tests/symfit/interactive
./run_ia_rpc_smoke.sh
```

By default this runs `symfit-x86_64 /bin/sleep 2` to keep the target alive long
enough for run-control commands.

This smoke test exercises:

- `capabilities`
- `query_status`
- `start_trace`
- `get_registers`
- `read_memory`
- `list_memory_maps`
- `disassemble`
- `single_step`
- `resume_until_basic_block`
- `resume_until_address`
- `resume_until_any_address`
- `stop_trace`
- `resume`

Useful overrides:

```bash
# Default runner is direct. To force fgtest wrapper:
RUNNER=fgtest ./run_ia_rpc_smoke.sh

# Override paths
SYMFIT=/path/to/symfit-x86_64 FGTEST=/path/to/fgtest ./run_ia_rpc_smoke.sh

# Test a specific target program
TARGET=/path/to/your/program ./run_ia_rpc_smoke.sh -- --arg1 --arg2
```

Note: some `fgtest` builds print `Usage: fgtest target input` and do not support
wrapping SymFit (`fgtest <symfit> <target>`). In that case, use `RUNNER=direct`.

### IA/RPC Trace Smoke Test

To validate the RPC-managed trace flow end to end:

```bash
cd tests/symfit/interactive
./run_ia_rpc_trace_smoke.sh
```

This trace smoke test exercises:

- `start_trace`
- `query_status`
- `resume`
- `pause`
- `stop_trace`

It also verifies that the returned trace artifact path exists and contains
events.

### IA/RPC Reference Client

For manual probing of a single IA/RPC method, use the reference client:

```bash
cd tests/symfit/interactive
./run_ia_rpc_client.sh --spawn --method capabilities --pretty --target /bin/sleep -- 2
```

You can also call a specific method with parameters:

```bash
cd tests/symfit/interactive
./run_ia_rpc_client.sh \
  --spawn \
  --method get_registers \
  --params-json '{"names":["rip","rsp","rax"]}' \
  --pretty \
  --target /bin/sleep \
  -- 2
```

Tracing is now exposed through RPC as well. For example, to start a basic-block
trace, inspect status, and stop tracing in one spawned session:

```bash
cd tests/symfit/interactive
SOCKET_PATH="$PWD/../../../mcp-workdir/ia-client.sock" \
./run_ia_rpc_client.sh \
  --spawn \
  --sequence-json '[
    {"method":"start_trace","params":{"basic_block":true}},
    {"method":"query_status"},
    {"method":"stop_trace"}
  ]' \
  --pretty \
  --target /bin/sleep \
  -- 2
```

This client is intended as a minimal example for `dynamiq` integration and for
manual backend debugging. It is not a replacement for the smoke test.

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
# `fgtest` still uses the historical `SYMCC_*` variable names for I/O paths.
export SYMCC_INPUT_FILE=/path/to/input
export SYMCC_OUTPUT_DIR=/path/to/output
export SYMCC_AFL_COVERAGE_MAP=/path/to/covmap
export TAINT_OPTIONS="taint_file=/path/to/input"

# Run SymFit
/path/to/symsan/install/bin/fgtest \
  /path/to/build/symfit-symsan/x86_64-linux-user/symfit-x86_64 \
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
  /mnt/d/git/symsan/install/bin/fgtest \
  /workspace/build/symfit-symsan/x86_64-linux-user/symfit-x86_64 \
  /binary
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

See LICENSE file for details.
