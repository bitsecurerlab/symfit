# Interactive Binary Analysis Runtime

## 1. Goal

Build a Python runtime for interactive userspace binary analysis using instrumented `qemu-user` as the first backend.

This project is analysis-first, not debugger-first.

The primary objective is to let a human or LLM run a Linux userspace binary under emulation, observe structured execution events, inspect registers and memory, and drive repeated experiments through a stable API.

## 2. Phase 1 Decision

Phase 1 backend:

- `qemu-user-instrumented`

Phase 1 does not target full-system emulation.

That means:

- userspace binaries first
- no VM-centric assumptions in the public API
- no mandatory QMP dependency
- snapshots are optional, not foundational
- instrumentation is the primary control and data plane

## 3. Why User-Mode First

For the first usable version, user-mode QEMU is a better fit than full-system QEMU because it:

- reduces setup complexity
- targets the actual immediate use case: userspace binaries
- keeps the state model address-oriented
- lets instrumentation carry most of the analysis value
- avoids premature system-mode features such as VM lifecycle management

Tradeoffs:

- no natural VM snapshot model in phase 1
- weaker machine-level control than system-mode QEMU
- some system-mode concepts, such as `cpu_id`, may be absent or mostly irrelevant

## 4. Product Shape

The system has three layers:

1. Core runtime library
2. CLI for humans
3. MCP server for LLMs

The runtime is the source of truth.

CLI and MCP must stay thin adapters over the same runtime semantics.

## 5. Architecture

```text
Human User          LLM / Agent
    |                   |
    v                   v
   CLI               MCP Server
        \           /
         \         /
          v       v
       Analysis Runtime
              |
              +--> Session Manager
              +--> Control Adapter
              +--> Instrumentation Event Client
              +--> Instrumentation RPC Client
              +--> Trace Manager
              +--> Memory/Code Model
              +--> Annotation Store
              |
              v
      qemu-user + custom instrumentation
```

Notes:

- the control adapter may be implemented through instrumentation RPC in phase 1
- QMP is optional future support for system-mode backends
- the public API must not assume a VM monitor exists

## 6. Core Design Principle

The public model is built around analysis state, not debugger verbs.

Primary abstractions:

- `AnalysisSession`
- `ExecutionState`
- `Event`
- `TraceSlice`
- `Annotation`
- optional `Snapshot`

The system should expose:

- execution control
- bounded state inspection
- recent event retrieval
- recent trace retrieval
- annotations

It should not expose raw transport or backend protocol details.

## 7. Control Plane vs Observation Plane

### Control Plane

Phase-1 control is backend-specific and may be implemented by the instrumentation control/RPC channel.

Responsibilities:

- start the target
- stop or pause execution if supported
- resume execution
- query current high-level status

### Observation Plane

The observation plane is the instrumentation event stream.

Responsibilities:

- emit structured execution events
- provide enough information for trace reconstruction
- support waiting for important events or addresses
- enable analysis workflows without source-level assumptions

This split is intentional:

- control changes execution
- observation explains execution

## 8. Phase 1 Scope

Phase 1 assumes:

- one active userspace target per session
- one `qemu-user` process per session
- one event stream per session
- one RPC channel for structured queries
- bounded in-memory trace retention

Phase 1 does not require:

- source-level debugging
- file/line semantics
- full-system state
- VM snapshots
- system-mode monitor control

## 9. Primary Use Cases

The runtime should support workflows like:

- run until a target event occurs
- run until an address is observed
- inspect recent basic-block or branch history
- inspect registers and memory at a stop point
- inspect current memory mappings
- annotate interesting addresses or hypotheses
- gather evidence for control-flow or data-flow questions

## 10. Event-Driven Analysis Model

The runtime is event-centric.

Execution is observed through structured events emitted by instrumentation.

The runtime stores:

- recent event ring buffer
- recent trace window
- current normalized state
- annotations
- optional snapshots if supported by a backend

The LLM should reason primarily over:

- state
- recent events
- trace slices

not over raw textual logs.

## 11. Event Types

Minimum event taxonomy:

- `backend_ready`
- `basic_block`
- `branch`
- `call`
- `return`
- `memory_read`
- `memory_write`
- `syscall`
- `exception`
- `breakpoint`
- `execution_paused`
- `execution_resumed`

Optional event types:

- `snapshot_taken`

If snapshots are unsupported for a backend, `snapshot_taken` is absent and not considered an error.

Recommended lifecycle event:

- `backend_ready`

## 12. Event Model

Minimum normalized event shape:

```json
{
  "event_id": "e-001",
  "seq": 1,
  "type": "basic_block",
  "timestamp": 1710000000.0,
  "pc": "0x401146",
  "thread_id": "1",
  "cpu_id": null,
  "payload": {}
}
```

Rules:

- all addresses are lowercase `0x...` strings
- all events are bounded and serializable
- `cpu_id` may be `null` in user-mode backends
- payload schemas are event-type specific

## 13. Control/Data RPC

Phase 1 should use a structured request/response channel for non-streaming operations.

Minimum RPC methods:

- `resume`
- `pause`
- `query_status`
- `get_registers`
- `read_memory`
- `list_memory_maps`

Optional RPC methods:

- `take_snapshot`
- `restore_snapshot`
- `diff_snapshots`
- `step`

Phase-1 requirement:

- register, memory, and memory-map queries should not depend on raw monitor text

## 14. Execution State

Minimum normalized state:

```python
@dataclass
class ExecutionState:
    session_status: str = "not_started"   # not_started | idle | running | paused | stopped | exited | closed
    backend: str | None = None
    target: str | None = None
    args: list[str] = field(default_factory=list)
    cwd: str | None = None

    stop_reason: str | None = None
    exit_code: int | None = None
    exit_signal: str | None = None

    pc: str | None = None
    current_thread_id: str | None = None

    registers: dict[str, str] = field(default_factory=dict)
    memory_maps: list[dict] = field(default_factory=list)

    last_snapshot_id: str | None = None
    last_event_id: str | None = None
    trace_head: int = 0

    capabilities: dict[str, bool] = field(default_factory=dict)
    recent_events: list[dict] = field(default_factory=list)
    ingestion_stats: dict[str, int] = field(default_factory=dict)
```

## 15. Snapshot Model

Snapshots are optional in phase 1.

If supported by a backend, snapshot support must be capability-gated and surfaced through the same response model as other operations.

If unsupported:

- snapshot APIs may return `unsupported_operation`
- the rest of the runtime model remains valid

## 16. Public Runtime API

Phase 1 API:

```python
class AnalysisSession:
    def start(self, target: str, args: list[str] | None = None, cwd: str | None = None, qemu_config: dict | None = None) -> dict: ...
    def resume(self, timeout: float = 5.0) -> dict: ...
    def pause(self, timeout: float = 5.0) -> dict: ...
    def run_until_event(self, event_types: list[str], timeout: float = 5.0) -> dict: ...
    def run_until_address(self, address: str, timeout: float = 5.0) -> dict: ...

    def get_registers(self, names: list[str] | None = None) -> dict: ...
    def read_memory(self, address: str, size: int) -> dict: ...
    def list_memory_maps(self) -> dict: ...
    def get_recent_events(self, limit: int = 100, event_types: list[str] | None = None) -> dict: ...
    def get_trace(self, limit: int = 100) -> dict: ...

    def annotate(self, address: str, note: str, tags: list[str] | None = None) -> dict: ...
    def list_annotations(self, address: str | None = None) -> dict: ...

    def take_snapshot(self, name: str | None = None) -> dict: ...
    def restore_snapshot(self, snapshot_id: str) -> dict: ...
    def diff_snapshots(self, left_id: str, right_id: str) -> dict: ...

    def get_state(self) -> dict: ...
    def capabilities(self) -> dict: ...
    def close(self) -> dict: ...
```

Notes:

- snapshot methods stay in the API, but may be unsupported in phase 1
- this preserves a stable forward path toward richer backends later

## 17. Capability Model

Backends must declare capabilities explicitly.

Important phase-1 defaults for `qemu-user-instrumented`:

- `pause_resume`: true if the control channel supports it
- `read_registers`: true
- `read_memory`: true
- `list_memory_maps`: true
- `trace_basic_block`: true
- `trace_branch`: true
- `run_until_address`: true
- `take_snapshot`: false by default
- `restore_snapshot`: false by default
- `single_step`: false by default

## 18. Response Envelope

All public operations return a normalized envelope.

Success:

```json
{
  "ok": true,
  "command": "get_registers",
  "state": {
    "session_status": "paused",
    "pc": "0x401146"
  },
  "result": {
    "registers": {
      "rip": "0x401146"
    }
  }
}
```

Error:

```json
{
  "ok": false,
  "command": "take_snapshot",
  "message": "backend does not support snapshot restore",
  "error_type": "unsupported_operation",
  "state": {
    "session_status": "paused",
    "pc": "0x401146"
  }
}
```

## 19. Safety and Bounds

Phase 1 bounds:

- `read_memory`: hard cap 256 bytes
- `get_recent_events`: hard cap 500 events
- `get_trace`: hard cap 500 trace entries
- `get_registers`: hard cap 128 registers

Phase 1 safety rules:

- no arbitrary shell passthrough
- no raw backend command passthrough
- no unbounded dumps
- malformed events or RPC messages must not corrupt runtime state

## 20. CLI and MCP

The CLI and MCP server are thin adapters over the runtime.

They should expose:

- start
- resume/pause
- wait for event/address
- get registers
- read memory
- list memory maps
- get recent events
- get trace
- annotate

Snapshot commands may be present but should gracefully report unsupported backends.

## 21. Repository Structure

Suggested layout:

```text
dynamiq/
  src/dynamiq/
    session.py
    state.py
    events.py
    models.py
    annotations.py
    instrumentation/
      client.py
      rpc.py
      schema.py
    backends/
      qemu_instrumented.py
```

## 22. Required Tests

Minimum phase-1 tests:

- event normalization
- instrumentation event ingestion
- instrumentation RPC request/response
- backend state updates from real event/RPC flows
- bounded register/memory/map normalization
- process-backed integration tests over real pipes
- opt-in live backend smoke test

Snapshot tests should be optional or capability-gated for the user-mode backend.

## 23. Acceptance Criteria

Phase 1 is acceptable when:

- a userspace binary can be analyzed through the runtime
- the runtime ingests structured instrumentation events safely
- register, memory, and memory-map queries work through the structured RPC path
- outputs are bounded, normalized, and stable
- CLI and MCP can stay thin over the runtime
- the design does not assume system-mode QEMU features

## 24. Future Work

Likely future expansions:

- true single-step support
- backend-specific snapshot support
- full-system QEMU backend with QMP
- gdbstub-assisted debugging
- richer symbol/call-stack enrichment

Phase 1 should not distort the architecture around those future features.

## 25. QEMU Implementation Plan

The first real backend implementation should target QEMU `linux-user`, not system emulation.

Recommended implementation order:

1. `query_status`
2. `get_registers`
3. `read_memory`
4. `basic_block` events
5. `execution_resumed` / `execution_paused`
6. `branch` events
7. `list_memory_maps`

### 25.1 Internal State

The QEMU-side instrumentation should maintain one small internal state object:

- `attached`
- `running`
- `paused`
- `last_pc`
- `last_tid` when available

This state is the source of truth for control and inspection.

The Python runtime should not invent stop state on its own when the backend can provide it.

### 25.2 RPC First

Before implementing richer tracing, get a real RPC server working inside or alongside the QEMU modifications.

Required RPC methods:

- `query_status`
- `get_registers(names=[])`
- `read_memory(address, size)`
- `list_memory_maps()`

Response shapes must match the current Python-side normalized models.

### 25.3 Register Access

For `get_registers`, read directly from the current `CPUArchState` for the active emulated thread or CPU context.

For x86_64 user-mode, expose at least:

- `rip`
- `rsp`
- `rbp`
- `rax`
- `rbx`
- `rcx`
- `rdx`
- `rsi`
- `rdi`

Rules:

- return hex strings
- keep the output bounded
- prefer exact architectural values over derived summaries

### 25.4 Memory Read

Implement `read_memory(address, size)` against guest virtual memory.

Rules:

- reject requests larger than 256 bytes
- fail cleanly on unmapped pages
- return exact bytes in lowercase hex
- keep this separate from disassembly logic

### 25.5 Basic Block Events

Hook at translated block execution boundaries.

Emit:

```json
{
  "event_id": "e-12",
  "seq": 12,
  "type": "basic_block",
  "timestamp": 1710000000.0,
  "pc": "0x401146",
  "thread_id": "1",
  "cpu_id": null,
  "payload": {
    "start": "0x401146",
    "end": "0x40115a",
    "instruction_count": 5
  }
}
```

This is the highest-value early execution signal and should be implemented before branch-level tracing.

### 25.6 Pause and Resume

When execution is actually resumed, emit `execution_resumed`.

When execution is actually paused and register/memory state is stable, emit `execution_paused`.

That pause event is the stop acknowledgement.

The runtime should treat:

- events as observational
- RPC reads as authoritative current state

### 25.7 Branch Events

Implement branch events after basic-block tracing is stable.

Emit:

- source `pc`
- target
- `taken`
- optional `fallthrough`

Branch events are useful, but not required before basic-block coverage is working.

### 25.8 Memory Maps

For `list_memory_maps`, read from QEMU `linux-user` guest mapping state.

Return:

- `start`
- `end`
- `perm`
- optional `name` or backing path

This does not need to be exhaustive at first, but it should correctly identify major executable and mapped regions.

### 25.9 Validation Strategy

Replace the current synthetic handlers incrementally:

1. real `query_status`
2. real `get_registers`
3. real `read_memory`
4. real `basic_block`
5. real `execution_paused`

At each step:

- keep Python APIs stable
- keep result shapes unchanged
- compare live output against the synthetic demo contract

### 25.10 Design Rule

Do not make streamed events the source of truth for exact machine state.

Use:

- event stream for "what happened"
- RPC for "what is true now"

This separation is important for avoiding race conditions and stale stop-state interpretation.
