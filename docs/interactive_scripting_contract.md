# SymFit Interactive + Scripting Contract

This document defines the backend contract used to integrate SymFit with
interactive analysis runtimes (for example `dynamiq`).

The design goal is one backend surface that supports:

- low-latency interactive debugging/inspection
- scripted automation

## Scope

This contract targets Linux user-mode (`x86_64-linux-user`) first.

Transports:

- RPC channel: newline-delimited JSON over Unix socket

Environment variables:

- `IA_RPC_SOCKET`: Unix socket path for RPC server

## Protocol Versioning

- `protocol_version = 1`: interactive core methods

Servers SHOULD expose a `capabilities` method with:

- `protocol_version` (integer)
- `capabilities` object of boolean feature flags

Clients MUST:

- reject unknown major protocol versions
- gate calls by capability flags

## Common RPC Envelope

Request:

```json
{"id":1,"method":"get_registers","params":{"names":["rip","rax"]}}
```

Success response:

```json
{"id":1,"ok":true,"result":{"registers":{"rip":"0x401000","rax":"0x1"}}}
```

Error response:

```json
{"id":1,"ok":false,"error":{"code":"unknown_method","message":"..."}}
```

Notes:

- `id` must be an integer
- addresses are encoded as hex strings such as `0x401000`
- requests are processed synchronously
- the backend currently handles one client connection at a time

## Session Lifecycle

When `IA_RPC_SOCKET` is set, the backend creates the Unix socket during process
startup and enters the interactive state machine.

Current v1 behavior:

- the backend starts in `paused` state
- clients should wait for the Unix socket to appear before issuing RPCs
- `query_status` reports one of: `idle`, `running`, `paused`, `exited`
- once the target exits, `query_status` may briefly report `exited`, but clients
  must also tolerate the RPC socket closing as part of normal session shutdown
- `exit_code` is reported when available in the `query_status` result

## Core Interactive Methods (v1)

Required for interactive mode:

- `capabilities`
- `query_status`
- `resume`
- `pause`
- `get_registers`
- `read_memory`
- `list_memory_maps`

Optional (recommended):

- `single_step`
- `resume_until_address`
- `resume_until_basic_block`
- `resume_until_any_address`
- `disassemble`
- `get_symbolic_expression`
- `get_path_constraints`
- `get_recent_path_constraints`
- `queue_stdin_chunk`
- `start_trace`
- `stop_trace`

## Method Semantics

### `capabilities`

Returns:

- `protocol_version` as an integer
- `capabilities` as a boolean feature map

### `query_status`

Returns:

- `status`: `idle`, `running`, `paused`, or `exited`
- `exit_code`: optional integer when the target has exited
- `pending_stdin_bytes`: queued stdin bytes not yet consumed by the guest
- `pending_symbolic_stdin_bytes`: queued symbolic stdin bytes not yet consumed

### `resume`

Resumes execution from a paused state.

Returns:

- an empty result object on success

### `pause`

Requests that a running target stop at the next safe pause point.

Returns:

- `status`: typically `paused` or `exited`

### `get_registers`

Behavior:

- valid while paused
- if `names` is omitted, a default x86 register set is returned
- unknown register names are ignored rather than rejected

Parameters:

- `names`: optional array of register names

Returns:

- `registers`: object mapping register names to hex strings

### `read_memory`

Behavior:

- valid while paused

Parameters:

- `address`: hex string
- `size`: integer from 0 to 256

Returns:

- `address`: normalized hex string
- `size`: integer
- `bytes`: lowercase hex string

### `list_memory_maps`

Behavior:

- valid while paused
- current implementation is derived from `/proc/self/maps`

Returns:

- `regions`: array of region objects with `start`, `end`, `perm`, `offset`,
  `inode`, and optional `path`/`name`

### `single_step`

Behavior:

- valid while paused

Parameters:

- `count`: positive integer

Returns:

- `status`
- `count`
- `executed`
- `pc`

### `resume_until_address`

Behavior:

- valid while paused

Parameters:

- `address`: hex string

Returns:

- `status`
- `matched`: boolean
- `pc`
- `last_insn_pc`
- `matched_pc`

### `resume_until_any_address`

Behavior:

- valid while paused

Parameters:

- `addresses`: array of 1 to 64 hex strings

Returns:

- `status`
- `matched`: boolean
- `pc`
- `last_insn_pc`
- `matched_pc`

### `resume_until_basic_block`

Behavior:

- valid while paused

Parameters:

- `count`: positive integer

Returns:

- `status`
- `blocks_executed`
- `pc`

### `disassemble`

Behavior:

- valid while paused
- requires capstone support in the backend build

Parameters:

- `address`: hex string
- `count`: integer from 1 to 64

Returns:

- `instructions`: array of objects with `address`, `size`, `bytes`, and `text`

### `get_symbolic_expression`

Behavior:

- valid while paused

Parameters:

- `label`: symbolic label encoded as a hex string

Returns:

- `label`: normalized label hex string
- `expression`: formatted symbolic expression string
- `op`: label op name
- `size`: label bit width or boolean width marker
- `left_label`, `right_label`, `op1`, `op2`: backend label metadata

### `get_path_constraints`

Behavior:

- valid while paused
- `label` must identify a branch-condition label
- returns the nested path-constraint closure associated with that root label
- the returned `constraints` list excludes the root label itself
- constraint ordering is deterministic but does not imply execution order

Parameters:

- `label`: branch-condition label encoded as a hex string

Returns:

- `root`: symbolic-label object for the requested branch-condition label
- `constraints`: array of symbolic-label objects for nested constraints
- `count`: number of nested constraints returned

### `get_recent_path_constraints`

Behavior:

- returns recently observed symbolic path constraints from the current session
- entries are returned newest first
- a path constraint is recorded from the backend's symbolic condition handling
- entries are suitable roots for `get_path_constraints(label)`

Parameters:

- `limit`: optional integer from 1 to 256, default `16`

Returns:

- `constraints`: array of symbolic-label objects with additional `pc` and `taken`
- `count`: number of entries returned
- `truncated`: whether older entries were omitted

### `queue_stdin_chunk`

Behavior:

- records metadata for a pending stdin write
- does not itself write bytes into the target stdin pipe
- entries are consumed in order by successful `read(fd=0, ...)` syscalls
- concrete and symbolic chunks may be mixed in the same stdin stream
- only bytes consumed from symbolic chunks become symbolic in guest memory

Parameters:

- `size`: positive integer
- `symbolic`: optional boolean, default `false`

Returns:

- `size`: echoed queued chunk size
- `symbolic`: echoed symbolic mode
- `stream_offset`: symbolic stdin stream offset reserved for this chunk, or `0x0`
  for concrete chunks
- `pending_stdin_bytes`: total queued stdin bytes not yet consumed
- `pending_symbolic_stdin_bytes`: total queued symbolic stdin bytes not yet
  consumed

### `start_trace`

Behavior:

- starts backend-managed tracing for the current session
- the backend chooses the storage location and creates any temporary file it
  needs internally
- initial v1 scope is basic-block tracing

Parameters:

- `basic_block`: optional boolean, default `true`

Returns:

- `trace_active`: boolean
- `trace_kind`: string, for example `basic_block`
- `trace_file`: backend-created path for the trace artifact

### `stop_trace`

Behavior:

- stops the active trace session if one exists

Returns:

- `trace_active`: boolean
- `trace_kind`: optional string
- `trace_file`: optional path to the completed trace artifact

## Capability Flags

Current v1 capability flags:

- `pause_resume`
- `read_registers`
- `read_memory`
- `disassemble`
- `list_memory_maps`
- `run_until_any_address`
- `single_step`
- `run_until_address`
- `trace_basic_block`
- `read_symbolic_expression`
- `read_path_constraints`
- `read_recent_path_constraints`
- `queue_stdin_chunk`
- `symbolize_memory`
- `symbolize_register`

The backend may also expose additional capability flags for not-yet-implemented
features. Clients should gate behavior only on flags they understand.

Trace-related capability flags describe support, not whether tracing is
currently active for the session.

## Trace Artifacts

Trace output is backend-managed. Clients should not be required to provide a
trace file path up front.

When tracing is started, the backend may create a temporary NDJSON trace file
internally and return its path in the RPC result.

Current event types implemented by the backend:

- `backend_ready`
- `basic_block`

Future event types must be additive and gated by capabilities when applicable.

## Client Integration Notes

For `dynamiq`, the expected integration model is:

1. launch the SymFit backend process with `IA_RPC_SOCKET` set
2. wait for the Unix socket path to appear
3. call `capabilities`
4. call `query_status` and confirm the backend is in `paused` state
5. perform interactive inspection and run-control RPCs
6. tolerate normal socket closure when the target exits

Typical startup flow:

```text
spawn symfit target
wait for IA_RPC_SOCKET
capabilities
query_status
start_trace
get_registers
disassemble
single_step / resume_until_* / resume
stop_trace
```

Minimal example request sequence:

```json
{"id":1,"method":"capabilities"}
{"id":2,"method":"query_status"}
{"id":3,"method":"start_trace","params":{"basic_block":true}}
{"id":4,"method":"get_registers","params":{"names":["rip","rsp","rax"]}}
{"id":5,"method":"disassemble","params":{"address":"0x401000","count":4}}
{"id":6,"method":"single_step","params":{"count":1}}
{"id":7,"method":"stop_trace"}
```

Client guidance:

- treat `capabilities` as the feature gate for optional UI/actions
- only issue register, memory-map, memory-read, and disassembly requests while paused
- expect address-like values in results to be hex strings
- expect some run-control requests to return `status: "exited"` if the target finishes
- treat trace file paths returned by RPC as backend-created artifacts
- if the socket closes after a `resume`-style request, treat that as a normal terminal
  condition and confirm process exit separately if needed

## Dynamiq Adapter Checklist

For an initial `dynamiq` integration, the adapter should:

- launch SymFit with `IA_RPC_SOCKET` set to a unique Unix socket path
- wait until the socket exists before opening a client connection
- issue `capabilities` first and cache the returned feature flags
- issue `query_status` next and verify the backend starts paused
- model backend state transitions using `query_status` plus RPC results
- allow inspection actions only while the backend is paused
- encode request addresses as hex strings such as `0x401000`
- decode register values, PCs, and addresses from hex strings in responses
- treat `unknown_method`, `unsupported_feature`, and `unsupported_arch` as feature-gating outcomes, not generic transport failures
- treat `invalid_state` as a client sequencing bug or stale UI action
- tolerate socket closure after `resume` when the target exits normally
- separately observe the backend process exit code when lifecycle ownership matters
- treat returned trace artifacts as optional telemetry outputs, not as the primary control plane

Recommended minimum command surface in `dynamiq`:

- session start
- session status
- registers
- memory read
- memory maps
- disassemble
- single step
- run until address
- run until any address
- run until basic block
- start trace
- stop trace
- resume
- pause

Recommended first-run validation:

- start a backend on `/bin/sleep 2`
- confirm `capabilities.protocol_version == 1`
- confirm initial `query_status.status == "paused"`
- start tracing and confirm `trace_active == true`
- fetch registers and disassembly at the current PC
- single-step once and confirm the PC changes or execution state remains coherent
- stop tracing and confirm the returned trace artifact path is stable
- resume and confirm either a later pause or clean exit

Reference client:

- `tests/symfit/interactive/ia_rpc_client.py` provides a minimal example client
  that can connect to an existing socket or spawn SymFit and issue one RPC call
  or a short sequence of RPC calls within the same session

## Error Codes

Current stable error code strings:

- `invalid_request`
- `invalid_params`
- `invalid_state`
- `not_attached`
- `invalid_address`
- `unknown_method`
- `unsupported_arch`
- `unsupported_feature`
- `internal_error`

## Migration Notes

1. Existing interactive clients continue to work with protocol v1.
2. New methods MUST be additive; avoid breaking v1 method semantics.
