# Live Backend Contract

This document defines the minimum phase-1 contract for a real `qemu-user` backend integration.

## Overview

The runtime expects three moving parts:

1. A target binary
2. An RPC endpoint

The runtime may either:

- attach to an already-running RPC endpoint
- or launch `qemu-user` itself and then attach to the RPC endpoint

## Environment

When the runtime launches `qemu-user`, it will set:

- `IA_RPC_SOCKET`

Your instrumentation side should use that value to know where to serve RPC.

## Transport

Phase 1 uses newline-delimited JSON over a Unix socket.

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

## Required RPC Methods

### `resume`

Request:

```json
{"id":1,"method":"resume","params":{}}
```

Response:

```json
{"id":1,"result":{}}
```

### `pause`

Same envelope as `resume`.

### `query_status`

Response:

```json
{"id":1,"result":{"status":"paused"}}
```

Allowed status values for phase 1:

- `idle`
- `running`
- `paused`
- `exited`

### `get_registers`

Response:

```json
{"id":1,"result":{"registers":{"rip":"0x401000","rsp":"0x7fffffffe000"}}}
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

Response:

```json
{"id":1,"result":{"address":"0x401000","size":16,"bytes":"554889e5..."}}
```

Rules:

- `bytes` is a lowercase hex string
- max size in phase 1 is 256 bytes

### `list_memory_maps`

Response:

```json
{
  "id": 1,
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

1. it starts `qemu-user`
2. it expects the instrumentation side to create the RPC socket
3. it then connects an RPC client to that socket

If the runtime is in attach mode:

1. the instrumentation RPC endpoint already exists
2. the runtime only connects to it

## Minimal Success Criteria

A valid live backend integration for phase 1 should support:

- `resume`
- `pause`
- `query_status`
- `get_registers`
- `read_memory`
- `list_memory_maps`
- `start_trace`
- `stop_trace`
- one or more useful trace event types such as `basic_block`

## Readiness

Socket availability plus a successful `capabilities` or `query_status` call is
the readiness handshake for phase 1.
