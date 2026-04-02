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
- Event channel (optional): newline-delimited JSON over Unix socket
- Trace file (optional fallback): newline-delimited JSON file

Environment variables:

- `IA_RPC_SOCKET`: Unix socket path for RPC server
- `IA_EVENT_SOCKET`: Unix socket path for event stream publisher
- `IA_TRACE_FILE`: NDJSON trace output path (fallback and archival)

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
{"id":1,"result":{"registers":{"rip":"0x401000","rax":"0x1"}}}
```

Error response:

```json
{"id":1,"error":{"code":"unsupported_method","message":"..."}}
```

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

## Capability Flags

Minimum recommended flags:

- `pause_resume`
- `read_registers`
- `read_memory`
- `list_memory_maps`
- `single_step`
- `run_until_address`
- `trace_basic_block`
- `trace_branch`

## Event Types

Suggested event types:

- `backend_ready`
- `basic_block`
- `branch`
- `stop`

## Error Codes

Suggested stable error code strings:

- `invalid_params`
- `unsupported_method`
- `unsupported_capability`
- `timeout`
- `internal_error`

## Migration Notes

1. Existing interactive clients continue to work with protocol v1.
2. New methods MUST be additive; avoid breaking v1 method semantics.
