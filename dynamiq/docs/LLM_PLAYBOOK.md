# LLM Playbook for Interactive Dynamic Analysis MCP

This playbook defines the required operating pattern for LLM-driven analysis sessions.

## Core Rules

1. Do not guess runtime addresses.
- Always resolve symbols per session using `syms`.
- Always set breakpoints from `symbols[].loaded_address`.

2. Do not assume output/state.
- Poll `stdout` and `stderr` after each `advance` with `mode=continue` and after each `send_*`.
- Check `state` to confirm `session_status` transitions.

3. Keep the interaction loop tight.
- `start` -> `syms` -> `bp_add` (optional) -> `advance {"mode":"continue"}` -> `stdout`/`stderr` -> `send_line`/`send_bytes` -> `advance {"mode":"continue"}` -> repeat.

4. Use the right input tool.
- `send_line` for menu/prompt-driven interaction.
- `send_bytes` for long or structured payloads (include `\n` explicitly when needed).
- `send_file` for very large payload files (preferred over huge inline `send_bytes`).

## Canonical Session Flow

1. `start`
2. `state` (confirm session started)
3. `syms` (optional name filter)
4. `bp_clear` then `bp_add` as needed
5. `advance {"mode":"continue"}`
6. `stdout` + `stderr`
7. `send_line` or `send_bytes`
8. `advance {"mode":"continue"}`
9. `state`, `regs`, `disasm`, `mem`, `maps` as needed
10. `close`

## Symbolic State

- Use `mem` for both concrete bytes and symbolic byte metadata.
- Use `regs` for both concrete register values and symbolic register labels.
- Use `symbolize_mem` only while paused to make a guest memory range symbolic.
- Use `symbolize_reg` only while paused to make a guest register symbolic.
- After discovering a non-zero label in `regs.result.symbolic_registers` or `mem.result.symbolic_bytes`, use `expr` to inspect that label's symbolic expression.

## Breakpoint Behavior

- `advance` uses one of four modes: `continue`, `insn`, `bb`, or `return`.
- `advance` timeout is non-fatal:
  - treat as `timed_out` (waiting for input/condition), not session failure
  - always follow with `stdout` + `stderr` + `state` before deciding recovery
- `pause` is independent and can be called anytime during an active session.

## Memory/Register Safety Rules

- Always call `regs` immediately before stack memory reads.
- Use `regs.result.registers.rsp` directly for stack `mem` reads.
- If memory read fails:
  - call `maps`
  - verify region coverage and permissions
  - retry with smaller `size`

## Failure Recovery

If behavior is inconsistent, stale, or unexpected:

1. `state`
2. `stdout` + `stderr`
3. `close`
4. `start` fresh
5. re-run `syms` and re-add breakpoints from current `loaded_address`

## Anti-Patterns (Do Not Do)

- Do not hardcode addresses from previous sessions.
- Do not compute `base + offset` manually when `syms` is available.
- Do not send multiple blind inputs without reading output between steps.
- Do not infer stack addresses from patterns (`0x7fff...` etc.); always use live `regs`.
