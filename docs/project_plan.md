# Project Plan

## 1. Scope Split

Treat this effort as two coupled projects plus one shared contract layer.

Tracks:

1. Runtime track
2. QEMU backend track
3. Contract track

### Runtime track

Owns:

- Python runtime
- state models
- event and RPC clients
- CLI and MCP integration
- fake sidecar and demo harness
- contract-level tests

### QEMU backend track

Owns:

- QEMU source modifications
- instrumentation hooks
- real RPC implementation
- real event emission
- backend-specific build and validation

### Contract track

Owns:

- event schema
- RPC schema
- stop semantics
- capability model
- versioning and compatibility rules

The contract track is the shared boundary between runtime and QEMU work.

## 2. Repository Strategy

Recommended layout:

- keep this repository as the runtime and contract repository
- keep QEMU modifications in a separate fork or a separate repo

Do not couple day-to-day runtime work to a full vendored QEMU tree unless there is a strong operational reason.

Practical recommendation:

- this repo: Python runtime, docs, tests, examples
- separate QEMU fork: `qemu-user` instrumentation implementation

## 3. Contract Freeze v0

Before real QEMU work begins, freeze the initial protocol contract.

Contract documents:

- [design.md](../design.md)
- [docs/live_backend_contract.md](./live_backend_contract.md)

Freeze these items for v0:

- event shapes
- RPC request and response shapes
- `execution_paused` acknowledgement semantics
- bounded output rules
- capability names

Rule:

- do not redesign schemas casually during backend implementation

## 4. Milestones

## M0: Runtime Beta

Goal:

- stable Python runtime against the synthetic sidecar

Done when:

- process-backed tests pass
- demo works locally
- stop semantics are coherent
- event and trace models are stable

Current status:

- in place

## M1: Real RPC from QEMU User

Goal:

- replace synthetic RPC handlers with real `qemu-user` backed state

Scope:

- real `query_status`
- real `get_registers`
- real `read_memory`

Done when:

- runtime can talk to QEMU-modified backend without changing Python-side schemas
- register values reflect real target state
- memory reads reflect real target memory
- status transitions reflect real control state

## M2: Real Stop Protocol

Goal:

- replace synthetic stop lifecycle with real backend stop handling

Scope:

- real `execution_resumed`
- real `execution_paused`
- coherent stop acknowledgement

Done when:

- matched event, paused acknowledgement, and RPC reads all refer to the same stop point

## M3: Real Basic-Block Tracing

Goal:

- emit real `basic_block` events from QEMU execution

Scope:

- translated block hook
- structured event emission
- bounded trace behavior

Done when:

- live trace is driven by real execution rather than synthetic producers

## M4: Memory Maps and Branch Events

Goal:

- add richer userspace analysis context

Scope:

- real `list_memory_maps`
- optional real `branch` events

Done when:

- runtime can reason about executable and mapped regions from real backend data

## M5: Hardening

Goal:

- make the system practical for repeated development use

Scope:

- disconnect handling
- startup ordering
- version checks
- compatibility notes
- reproducible backend build steps

Done when:

- one documented QEMU revision is supported end to end

## 5. Task Breakdown

Break work down by vertical capability, not by subsystem.

Good task examples:

- implement RPC `query_status` in QEMU backend
- implement RPC `get_registers` for x86_64 linux-user
- implement bounded guest virtual memory reads
- emit `execution_paused` after stop state is stable
- emit `basic_block` on translated block entry
- add live integration assertion for register stability at stop point

Avoid vague tasks like:

- improve backend
- work on instrumentation

## 6. Definition Of Done

A task is done only when:

- contract impact is documented
- tests are added or updated
- demo path still works, if relevant
- failure mode is understandable
- required manual steps are written down

## 7. Branching Strategy

Recommended:

- `main` for stable runtime and docs
- short-lived feature branches for runtime work
- separate long-lived QEMU backend branch or separate repo for QEMU work

If using a QEMU fork:

- keep patches layered
- prefer small reviewable commits
- avoid a single giant unstructured instrumentation patch

## 8. Versioning

Add a simple protocol version early.

Recommended:

- RPC method: `get_protocol_info`
- event stream version field documented in the contract

At minimum, version:

- protocol version
- backend kind
- supported capabilities

This is the main guard against drift between Python and QEMU implementations.

## 9. Immediate Next Tasks

Recommended next sequence:

1. freeze contract v0
2. start QEMU backend milestone M1
3. implement real `query_status`
4. implement real `get_registers`
5. implement real `read_memory`

Runtime-side rule during M1:

- keep Python schemas stable unless a true blocker is discovered

## 10. Acceptance Criteria For M1

M1 is complete when:

- a modified `qemu-user` backend responds to `query_status`
- `get_registers` returns real x86_64 register values
- `read_memory` returns real bytes from guest virtual memory
- Python runtime consumes these responses without schema changes
- a live demo shows real, not synthetic, register and memory values
