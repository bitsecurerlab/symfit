# Live Backend Contract

This is the Dynamiq integration summary for SymFit user-mode and system-mode
backends. The [SymFit IA/RPC contract](../../docs/interactive_scripting_contract.md)
defines current method semantics and mode-specific capabilities. The original
phase-1 design is historical; it does not limit current system-mode support.

## Overview

The runtime expects:

1. A target binary for `qemu-user`, or a VM command line for `qemu-system`
2. An RPC endpoint
3. For system mode, a QMP endpoint for VM-level monitor control

The runtime may either:

- attach to an already-running RPC endpoint
- or launch QEMU itself and then attach to the RPC endpoint

## Environment

When the runtime launches QEMU, it will set:

- `IA_RPC_SOCKET`

Your instrumentation side should use that value to know where to serve RPC.
For `qemu-system`, the runtime also creates a QMP Unix socket and passes it to
QEMU with `-qmp unix:...,server,nowait` when the caller has not already supplied
a QMP argument.

## Transport

IA/RPC v1 uses newline-delimited JSON over a Unix socket.

### RPC channel

Direction:

- runtime -> instrumentation
- instrumentation -> runtime

Request shape:

```json
{"id":1,"method":"get_registers","params":{"names":["rax","rip"]}}
```

Response shape:

```json
{"id":1,"ok":true,"result":{"registers":{"rax":"0x1","rip":"0x401000"}}}
```

Error response:

```json
{"id":1,"ok":false,"error":{"code":"unknown_method","message":"unsupported method"}}
```

## Common RPC Methods

### `resume`

Request:

```json
{"id":1,"method":"resume","params":{}}
```

Response:

```json
{"id":1,"ok":true,"result":{}}
```

### `pause`

Same envelope as `resume`.

### `query_status`

Response:

```json
{"id":1,"ok":true,"result":{"status":"paused"}}
```

Status values:

- `idle`
- `running`
- `paused`
- `exited`

### `get_registers`

Response:

```json
{"id":1,"ok":true,"result":{"registers":{"rip":"0x401000","rsp":"0x7fffffffe000"}}}
```

Rules:

- register names are strings
- register values are strings
- hex values should use `0x` form when applicable

### `read_memory`

Request:

```json
{"id":1,"method":"read_memory","params":{"address":"0x401000","size":16}}
```

System-mode physical memory reads use `address_space`:

```json
{"id":1,"method":"read_memory","params":{"address":"0x7c00","size":4,"address_space":"physical"}}
```

Response:

```json
{"id":1,"ok":true,"result":{"address":"0x401000","size":16,"bytes":"554889e5909090909090909090909090"}}
```

Rules:

- `bytes` is a lowercase hex string
- maximum read size is 256 bytes

### `list_memory_maps` (user mode only)

System mode advertises `list_memory_maps: false`.

Response:

```json
{
  "id": 1,
  "ok": true,
  "result": {
    "regions": [
      {
        "start": "0x400000",
        "end": "0x401000",
        "perm": "r-x",
        "name": "/path/to/target"
      }
    ]
  }
}
```

## Trace Artifacts

Tracing is RPC-managed. The backend owns any trace artifact storage it needs and
may return a file path for later consumption.

Recommended trace RPC methods:

- `start_trace`
- `stop_trace`

Current v1 scope for SymFit is basic-block tracing.

## Startup Expectations

If the runtime is in launch mode:

1. it starts `qemu-user` or `qemu-system`
2. for system mode, it first waits for QMP and negotiates QMP capabilities
3. it waits for the instrumentation RPC socket and connects the RPC client
4. it negotiates RPC capabilities and queries the initial state

If the runtime is in attach mode:

1. the instrumentation RPC endpoint already exists
2. the runtime only connects to it

## Integration Checks

A live integration should negotiate capabilities and exercise supported methods:

- `resume`
- `pause`
- `query_status`
- `get_registers`
- `read_memory`
- `list_memory_maps` in user mode
- `select_cpu` in system mode when advertised
- `start_trace`
- `stop_trace`
- one or more useful trace event types such as `basic_block`

## Readiness

Socket availability plus a successful `capabilities` or `query_status` call is
the readiness handshake. A socket appearing alone does not establish readiness.

## SMP and Snapshots

System sessions use QMP for CPU discovery and VM lifecycle, plus IA/RPC
`select_cpu` for the paused inspection context. Dynamiq preserves HMP CPU
selection by passing `cpu-index` on each monitor command. Per-CPU stop/continue
is unsupported; VM-wide resume/pause remains available.

Live regression cases launch 2 and 4 vCPUs and verify distinct CPU/thread
identities, persistent selection, and independent register values. Snapshots
need a writable disk that supports them, such as qcow2; a capability flag alone
does not make a diskless VM snapshot-capable.

## Timeout Recovery

Run-control timeouts leave execution in progress. Dynamiq reconnects the RPC
channel and attempts one status resync without retrying execution. The original
timeout still reaches the caller. If resync fails, cached status remains
running; inspect output and explicitly decide the next operation. See the
[timeout contract](../../docs/interactive_scripting_contract.md#timeouts-and-reconnection)
for raw-client recovery.
