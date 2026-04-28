# Interactive Dynamic Analysis

Python runtime for interactive userspace binary analysis, using instrumented `qemu-user` as the first backend.

This project is analysis-first: it focuses on controllable execution plus structured state/event inspection for human and LLM workflows.

## Repository Contents

- runtime implementation in `src/dynamiq/`
- tests in `tests/`
- runnable examples in `examples/`
- architecture and scope notes in `design.md`
- live backend contract in `docs/live_backend_contract.md`
- project planning in `docs/project_plan.md`
- LLM operation guidance in `docs/LLM_PLAYBOOK.md`

## Quick Setup

Requirements:

- Python 3.10+
- (for demos) `gcc` and `qemu-x86_64`

Create a local environment and install dev dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
.venv/bin/python -m pip install -e '.[dev]'
```

If you are running repo-local scripts without installing dynamiq into the
active environment, use `PYTHONPATH=src` from the repo root:

```bash
cd /home/heng/git/dynamiq
PYTHONPATH=src .venv/bin/python your_script.py
```

### Build Instrumented Runtime Binaries

Build both supported dynamiq runtimes into `tools/qemu/`:

```bash
./scripts/build_qemu_toolchain.sh
```

By default this now builds from the local SymFit tree and copies the resulting
runtime binaries into dynamiq's `tools/qemu/` cache using the conventional
`qemu-*-instrumented` names expected by the launcher.

Common overrides:

```bash
./scripts/build_qemu_toolchain.sh \
  --symfit-src /path/to/symfit \
  --symsan-build /path/to/symfit/build/symsan \
  --build-dir /tmp/symfit-build-ia \
  --out-dir /path/to/dynamiq/tools/qemu \
  --clean
```

If you still want the legacy upstream-QEMU flow, use:

```bash
./scripts/build_qemu_toolchain.sh \
  --source-kind qemu \
  --qemu-src /path/to/qemu \
  --build-dir /tmp/qemu-build-ia \
  --clean
```

## Tests

Run the default test suite:

```bash
PYTHONPATH=src .venv/bin/pytest -q
```

### Live QEMU Integration Tests (opt-in)

Live tests are marked `live_qemu` and require a real backend/instrumentation environment.

Set:

- `RUN_LIVE_QEMU=1`
- `IA_LIVE_EVENT_SOCKET`
- `IA_LIVE_RPC_SOCKET`
- `IA_LIVE_TARGET`

Optional:

- `IA_LIVE_QMP_SOCKET`
- `IA_LIVE_ARGS`
- `IA_LIVE_CWD`
- `IA_LIVE_LAUNCH=1`
- `IA_LIVE_QEMU_USER_PATH`
- `IA_LIVE_QEMU_ARGS`

Then run:

```bash
PYTHONPATH=src .venv/bin/pytest -q -m live_qemu
```

`IA_LIVE_LAUNCH=1` tells the backend to launch `qemu-user` using the runtime launch contract. If unset, tests assume endpoints already exist.

## Demos

### End-to-end local demo

```bash
PYTHONPATH=src .venv/bin/python examples/demo_live_session.py
```

This demo will:

1. compile `examples/sample_target.c`
2. start `examples/instrumentation_sidecar.py`
3. launch the target through the runtime with `qemu-user`
4. run a short analysis session

### Real QEMU RPC slice (M1)

```bash
PYTHONPATH=src .venv/bin/python examples/demo_qemu_rpc_m1.py
```

This path expects an IA/RPC-capable runtime binary, typically from dynamiq's
local `tools/qemu/` cache, and exercises:

1. `query_status`
2. `get_registers`
3. `advance(mode="bb", count=1)`
4. `disassemble(...)` from live runtime `rip`
5. `advance(mode="insn", count=1)` for fine-grained motion
6. `read_memory`

## MCP Server (stdio)

The repo includes a minimal MCP server for external coding platforms.

Start it with:

```bash
PYTHONPATH=src .venv/bin/python -m dynamiq.mcp_server
```

In operator-managed deployments, launch the MCP server with the correct
instrumented runtime for the target class. Runtime selection is an environment
decision made by the launcher, not something delegated to the model.

Backward-compatible module path is still supported:

```bash
PYTHONPATH=src .venv/bin/python -m dynamiq.mcp_server
```

### Supported MCP methods

- `initialize`
- `tools/list`
- `tools/call`

### Exposed tools

- `start`, `close`, `caps`, `state`
- `advance`, `pause`
- `send_bytes`, `send_line`, `send_file`, `stdout`, `stderr`
- `regs`, `bt`, `disasm`, `mem`, `maps`, `syms`
- `symbolize_mem`, `symbolize_reg`, `expr`
- `trace_start`, `trace_stop`, `trace_status`, `trace_get`
- `bp_add`, `bp_del`, `bp_list`, `bp_clear`

`state` is the main summary view for agents. After you call `regs` or `recent_path_constraints`, it also surfaces cached symbolic summaries:
- `state.result.symbolic_registers`
- `state.result.recent_symbolic_pcs`

`regs` and `mem` still expose the full detailed symbolic metadata when the backend provides it:
- `regs.result.symbolic_registers`
- `mem.result.symbolic_bytes`

Use `symbolize_mem` and `symbolize_reg` to inject symbolic state into the current paused execution.
Use `expr` to render the symbolic expression for a specific non-zero label discovered through `regs` or `mem`.
For stdin-driven input, prefer the built-in queued stdin flow: `send_bytes`, `send_line`, and `send_file` now accept `symbolic: true`. When the runtime supports `queue_stdin_chunk`, dynamiq records each stdin write as an ordered concrete or symbolic chunk and SymFit applies symbolic labels automatically when the guest later consumes those bytes through stdin syscalls.
Use the older manual breakpoint-plus-`symbolize_mem` workflow only when the data source is not stdin, or when you need to symbolize some derived buffer instead of the original stdin stream.

For symbolic path reasoning in the scripting API, use:
- `session.get_state()` first to inspect `state["recent_symbolic_pcs"]` and `state["symbolic_registers"]`
- `session.recent_path_constraints(limit=...)` to discover recent path-condition labels, whether each branch was taken, and to refresh `recent_symbolic_pcs`
- `session.path_constraint_closure(label)` to inspect the chosen path-condition plus the nested earlier constraints it depends on, including their `taken` directions

Typical flow:
```python
state = session.get_state()["state"]
latest = state["recent_symbolic_pcs"][0]
label = latest["label"]
recent = session.recent_path_constraints(limit=8)
expr = session.get_symbolic_expression(label)
closure = session.path_constraint_closure(label)
```

### MCP quickstart for interactive stdin/stdout

Use this order for interactive programs:

1. `start`
2. `advance` with `{"mode":"continue"}`
3. one or more `send_bytes` / `send_line` / `send_file`
4. poll `stdout` and `stderr`

Example `tools/call` arguments:

- `start`
```json
{
  "target": "/path/to/target_binary",
  "cwd": "/path/to/workdir"
}
```

- `advance`
```json
{
  "mode": "continue",
  "timeout": 5.0
}
```

- `send_bytes` (required `data`)
```json
{
  "data": "1\\n"
}
```

- `send_bytes` with symbolic stdin queueing
```json
{
  "data": "AAAA",
  "symbolic": true
}
```

- `send_bytes` (raw bytes via hex)
```json
{
  "data_hex": "040000000680ffffffffffff"
}
```

- `send_line` (optional `line`, appends `\n`)
```json
{
  "line": "1"
}
```

- `send_line` with symbolic stdin queueing
```json
{
  "line": "AAAA",
  "symbolic": true
}
```

- `send_file` (required `path`, streams raw file bytes)
```json
{
  "path": "/tmp/pov_input.txt",
  "append_newline": true
}
```

- `send_file` with symbolic stdin queueing
```json
{
  "path": "/tmp/pov_input.txt",
  "append_newline": true,
  "symbolic": true
}
```

- `stdout` / `stderr`
```json
{
  "max_chars": 4096,
  "wait_ms": 150
}
```

- `bt` (best-effort stack backtrace)
```json
{
  "max_frames": 16
}
```

- `trace_start` (SymFit RPC backend)
```json
{
  "event_types": ["basic_block"]
}
```

- `trace_get`
```json
{
  "limit": 100,
  "since_start": true
}
```

`stdout` and `stderr` return `data`, `cursor`, and `eof`. The server tracks cursors internally, so repeated calls return only new output by default.

`bt` returns a gdb-like backtrace using current registers plus frame-pointer unwinding. It is best-effort and may be shallow if frame pointers are omitted or stack metadata is unavailable.

With the SymFit backend, tracing is started over RPC. The backend creates and
returns the trace artifact path, and `trace_get` consumes that artifact through
the backend adapter.

### MCP troubleshooting

- `send_bytes` appears stuck:
  Call includes neither `data` nor `data_hex`. Send `{"data":"...\\n"}` for text or `{"data_hex":"..."}` for raw bytes.
- `advance` returns timeout:
  This is often expected for interactive flows (waiting for input or breakpoint condition). Treat as non-fatal and immediately check `stdout`, `stderr`, and `state`.
- Session is `idle` and target is not running:
  Use `start` (defaults to launch mode), then `advance {"mode":"continue"}`.
- Trace start rejects unsupported filters:
  The SymFit RPC backend currently supports only `event_types=["basic_block"]`
  and does not support address-range filtering.
- Large multiline payloads fail in tool UI:
  Use `send_file` (preferred) or split into multiple `send_bytes` calls.

## Reference Docs

- [design.md](design.md)
- [docs/live_backend_contract.md](docs/live_backend_contract.md)
- [docs/LLM_PLAYBOOK.md](docs/LLM_PLAYBOOK.md)
- [docs/project_plan.md](docs/project_plan.md)
