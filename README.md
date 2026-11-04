## What is SymFit?

SymFit is a symbolic execution framework for analyzing binaries. It combines a
QEMU-based execution engine, the Symsan symbolic runtime/solver stack, and
Dynamiq's Python control layer for interactive analysis.

SymFit supports user-mode and system-mode analysis for i386, x86_64, and
AArch64 targets.

## Repository Layout

SymFit now carries its companion projects in this repository:

- `symsan/` - Symsan compiler, runtime, and solver sources
- `dynamiq/` - Python control and analysis tooling for live SymFit sessions
- `mcp-server/` - Node.js MCP server for campaign-style automation
- `tests/symfit/` - concolic, IA/RPC, and system-mode smoke tests
- `docs/interactive_scripting_contract.md` - IA/RPC contract for interactive analysis

Generated Symsan installs and libc++ build outputs are intentionally not tracked.
`build.sh` produces the runtime and solver install under `build/`. Instrumented
libc++ archives are optional and require the separate build described in
[symsan/README.md](symsan/README.md#libcxx).

## MCP Servers for LLM Agents

SymFit includes two MCP-facing integration points:

- `mcp-server/` exposes the original campaign-oriented Node.js server.
- `dynamiq/` exposes the newer interactive server and scripting API for live
  SymFit sessions.

The MCP interfaces provide a standardized way to:

- Run symbolic execution campaigns
- Manage test case corpora
- Analyze coverage and results
- Automate binary analysis workflows

See [mcp-server/README.md](mcp-server/README.md) for setup instructions and [mcp-server/EXAMPLES.md](mcp-server/EXAMPLES.md) for usage examples.
For live interactive control, see [dynamiq/README.md](dynamiq/README.md).

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

`build.sh` builds Symsan and SymFit from the monorepo. Symsan source builds
always use the in-tree `symsan/` directory.

Build everything from the monorepo defaults:

```bash
./build.sh
```

Print the effective paths and target list without building:

```bash
./build.sh --print-paths
```

The main build artifacts are:

- `build/symsan/` - Symsan tools, headers, and libraries used by SymFit
- `build/symsan-build/` - Symsan build tree
- `build/symfit/` - SymFit QEMU binaries

By default, `build.sh` builds i386, x86_64, and AArch64 user-mode targets,
plus x86_64 and AArch64 system-mode targets:

- `x86_64-linux-user/symfit-x86_64` (for x86_64 binaries)
- `i386-linux-user/symfit-i386` (for i386 binaries)
- `aarch64-linux-user/symfit-aarch64` (for AArch64 binaries)
- `x86_64-softmmu/symfit-system-x86_64`
- `aarch64-softmmu/symfit-system-aarch64`

You can override this with:

```bash
SYMFIT_TARGET_LIST=x86_64-linux-user ./build.sh
```

For AArch64 user-mode only:

```bash
SYMFIT_TARGET_LIST=aarch64-linux-user ./build.sh
```

### System-Mode Smoke Test

To validate the `symfit-system-*` binaries from a local build:

```bash
tests/symfit/system/run_symfit_system_smoke.sh
```

This checks the x86_64 and AArch64 system-mode binaries by default. It verifies
`--version`, machine discovery, a paused `-machine none` QMP launch/quit cycle,
and boots generated tiny guest images: an x86 boot sector and an AArch64 raw
kernel image. The same generated guests are also started paused under QMP and
resumed with `cont`, which verifies that run control reaches guest execution.
The smoke test also launches the generated guests with `IA_RPC_SOCKET` and
checks the direct system-mode IA/RPC surface for capabilities, paused status,
register reads, memory reads, symbolic-register expression lookup, and recent
path-constraint retrieval.

### SymFit Regression Tests

Run the user-mode RPC smoke tests from the repository root:

```bash
tests/symfit/interactive/run_ia_rpc_smoke.sh
tests/symfit/interactive/run_ia_rpc_trace_smoke.sh
tests/symfit/interactive/run_ia_rpc_expr_smoke.sh
```

The additional `ia_rpc_*_smoke.py` scripts in that directory take
`--symfit "$PWD/build/symfit/x86_64-linux-user/symfit-x86_64"`; the anagram
script instead requires the i386 runtime and its external target binary.

For Dynamiq unit tests and live 2-/4-vCPU regression checks:

```bash
cd dynamiq
.venv/bin/python -m pytest -q
RUN_LIVE_QEMU=1 .venv/bin/python -m pytest -q -rs \
  tests/test_live_system_backend.py tests/test_qemu_system_smp.py \
  tests/test_qmp_client.py
```

Create the Dynamiq environment first using its [setup instructions](dynamiq/README.md#quick-setup).
The live SMP checks launch actual multi-CPU guests and verify CPU discovery,
selection, isolated register values, and VM resume/pause. Local Unix sockets
must be permitted. See [Dynamiq's live test instructions](dynamiq/README.md#live-qemu-integration-tests-opt-in)
for user-mode endpoint settings and the separate Alpine boot test.

The standalone Symsan suite uses lit against `build/symsan-build/tests`; its
C++ tests require optional instrumented libc++ archives. Upstream QEMU
`make check` targets are broader tests, not the SymFit regression suite.

## Using SymFit

### Basic Usage

SymFit uses a modified QEMU to perform symbolic execution on binary programs.
The basic workflow is:

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

For AArch64 user-mode, point `SYMFIT` at the AArch64 runtime and run an AArch64
target binary:

```bash
SYMFIT="$PWD/../../../build/symfit/aarch64-linux-user/symfit-aarch64" \
TARGET=/path/to/aarch64-binary \
./run_ia_rpc_smoke.sh
```

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

This client is intended as a minimal example for Dynamiq integration and for
manual backend debugging. It is not a replacement for the smoke test.

## Dynamiq Interactive Control

Dynamiq can launch the right user-mode SymFit binary for a target when the
runtime paths are available. From the monorepo, install it in editable mode:

```bash
cd dynamiq
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

For quick repo-local use without installation:

```bash
PYTHONPATH=dynamiq/src python3 -m dynamiq.mcp_server
```

Dynamiq now discovers merged-build SymFit runtimes directly from
`build/symfit/<target>/symfit-*`. To build the x86 user-mode runtimes dynamiq
launches by default:

```bash
cd dynamiq
./scripts/build_qemu_toolchain.sh
```

See [dynamiq/README.md](dynamiq/README.md) for the scripting API, live QEMU
integration tests, and MCP tool list.

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
export TAINT_OPTIONS="taint_file=/path/to/input output_dir=/path/to/output solve_on_branch=1"
mkdir -p "$SYMCC_OUTPUT_DIR"

# Run SymFit
build/symsan/bin/fgtest \
  build/symfit/x86_64-linux-user/symfit-x86_64 \
  /path/to/your/program
```

For AArch64 targets, use:

```bash
build/symsan/bin/fgtest \
  build/symfit/aarch64-linux-user/symfit-aarch64 \
  /path/to/aarch64-program
```

With the in-tree Z3 runtime, `solve_on_branch=1` opts into automatic input
generation. Without it, symbolic branches are recorded for explicit queries.
Interactive IA/RPC workflows normally leave automatic generation disabled.

## Understanding the Output

With automatic generation enabled, SymFit can produce:

- **New test cases** in `$SYMCC_OUTPUT_DIR` - Each file is a generated input that explores different execution paths
- **Coverage map** at `$SYMCC_AFL_COVERAGE_MAP` - AFL-style bitmap showing code coverage

## Docker Usage

Prepare `/path/to/workdir/testfile` and `/path/to/workdir/output` first. The
image must contain a SymFit build compatible with these runtime options:

```bash
# Run SymFit in Docker
docker run --rm \
  -v /path/to/your/binary:/binary:ro \
  -v /path/to/workdir:/workdir \
  -w /workdir \
  -e SYMCC_INPUT_FILE=/workdir/testfile \
  -e SYMCC_OUTPUT_DIR=/workdir/output \
  -e SYMCC_AFL_COVERAGE_MAP=/workdir/covmap \
  -e "TAINT_OPTIONS=taint_file=/workdir/testfile output_dir=/workdir/output solve_on_branch=1" \
  ghcr.io/bitsecurerlab/symfit:latest \
  /workspace/build/symsan/bin/fgtest \
  /workspace/build/symfit/x86_64-linux-user/symfit-x86_64 \
  /binary
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

See LICENSE file for details.
