---
name: dynamiq-mcp
description: Use when driving the Dynamiq MCP server (`dynamiq`) for live binary sessions: start/advance loops, stdin delivery/EOF, breakpoints, write watchpoints, memory inspection/search, symbolic input, symbolic expressions, and path-constraint discovery.
---

# Dynamiq MCP Skill

Use this skill when operating the `dynamiq` MCP tools for live binary analysis.

## Core Rules

1. Use session data, not guesses.
- Resolve runtime addresses with `syms`.
- Use `loaded_address` for `bp_add`.
- Treat `regs`, `mem`, `maps`, `bt`, and `state` as the source of truth.

2. Do not choose the runtime binary.
- The MCP server launcher controls which `qemu-user` / SymFit binary is used.

3. `advance {"mode":"continue"}` should drive execution.
- It should stop on meaningful execution boundaries such as input wait, breakpoint-like stops, terminal pending-exit, or timeout.
- Do not assume stdout alone is a stop condition.

4. Always inspect after a stop.
- Common follow-up loop: `state` -> `stdout` -> `stderr`.
- Then use `regs`, `bt`, `disasm`, `mem`, `expr`, or path-constraint tools as needed.
- `status: "blocked"` with `stop_reason: "syscall_block"` is inspectable; treat it like a useful stop, not like an error.

5. Close the session when done.
- Use `close` at the end of a workflow.

## Minimal Loop

1. `start`
2. `state`
3. `advance {"mode":"continue"}`
4. `stdout`
5. `stderr`
6. Repeat until you hit the point you care about
7. `close`

## Common Tool Patterns

### Basic interactive loop

1. `start {"target":"/abs/path/to/program"}`
2. `advance {"mode":"continue"}`
3. `stdout`
4. `stderr`
5. `state`

### Breakpoint workflow

1. Prefer library-relative breakpoints for ASLR and dlopen'd code:
- `bp_add {"module":"libfoo.so", "offset":"0xad1548"}`
- `bp_add {"module":"libfoo.so", "symbol":"write_frame_8"}`

2. For main-binary symbols, `syms {"name_filter":"main"}` is also fine.
3. `bp_clear`
4. `bp_add {"address":"<loaded_address>"}` or a module-relative form above
5. `advance {"mode":"continue"}`
6. `regs`
7. `bt`
8. `disasm`

### Library-relative breakpoints

Use module-relative breakpoints whenever the target code lives in a shared object, especially one loaded with `dlopen`. Do not manually compute an absolute address from an old run: ASLR means it will change between sessions.

Good:
- `bp_add {"module":"libc.so", "symbol":"malloc"}`
- `bp_add {"module":"libffmpeg.so", "offset":"0xad1548"}`
- `bp_add {"module":"libffmpeg.so", "symbol":"write_frame_8"}`

Dynamiq may query `maps` while the target is running so it can resolve loaded module bases before arming the breakpoint. If the module is not loaded yet, first run to a point after `dlopen`, then retry the module-relative breakpoint. Avoid falling back to absolute addresses unless you are deliberately pinning one specific already-observed runtime address.

Fallback absolute-address flow:
1. `syms {"name_filter":"main"}`
2. `bp_clear`
3. `bp_add {"address":"<loaded_address>"}`
4. `advance {"mode":"continue"}`
5. `regs`
6. `bt`
7. `disasm`

### Exact stdin workflow

Use:
- `send_line` for prompt-driven text input
- `send_bytes` for exact byte sequences
- `send_file` for larger payloads

Typical loop:
1. `send_line` or `send_bytes`
2. `advance {"mode":"continue"}`
3. `stdout`
4. `stderr`
5. `state`

If `advance` reports `status: "blocked"` / `stop_reason: "syscall_block"`,
the guest is sleeping in a host syscall such as `read`, `poll`, `recv`, `futex`,
or `wait`. Inspection tools still work there:
- `regs`
- `mem`
- `disasm`
- `maps`
- `syms`
- `symbolize_mem`

Use this to inspect parser buffers or symbolize data before sending more input
or calling `close_stdin`. Avoid setting blind breakpoints just to get an
inspectable state.

### Memory search workflow

Use `mem_search` to locate byte signatures, heap metadata, embedded files, or
struct markers without guessing addresses and reading chunks manually.

Examples:
- `mem_search {"pattern_hex":"0000000c6a502020"}`
- `mem_search {"pattern_hex":"0000000c6a502020", "start":"0x4000000000", "end":"0x4200000000"}`

If `start` and `end` are omitted, Dynamiq searches readable mapped regions from
`maps`. Prefer `pattern_hex` for binary signatures with NUL bytes.

### Write watchpoint workflow

Use `watch` when you need the exact write that corrupts a watched guest address
range. This is better than breaking every loop iteration and manually checking
the destination pointer.

Example:
- `watch {"address":"0x41651d47a0", "size":8, "mode":"write"}`
- `advance {"mode":"continue"}`
- inspect `state.watchpoint`, `regs`, `bt`, `disasm`, and `mem`
- `advance {"mode":"continue"}` to let the trapped store execute

Semantics:
- Watchpoints are persistent until `watch_clear` or session close.
- A hit stops before the overlapping store executes.
- Continuing reexecutes that one store once, without immediately trapping on the
  same instruction.
- Later overlapping writes still trap.
- Watchpoints work in both concrete and symbolic SymFit execution modes.

At a hit, expect:
- `state.stop_reason == "watchpoint"`
- `state.watchpoint.mode == "write"`
- `state.watchpoint.address` / `size`: configured watched range
- `state.watchpoint.hit_address` / `hit_size`: actual store range
- `state.watchpoint.pc`: writer instruction

Use `watch_clear` before changing to a different watched object or when a
watchpoint becomes too noisy.

## Symbolic Features

Dynamiq supports two main symbolic workflows:
- symbolic stdin
- explicit symbolization of memory/registers

### Symbolic stdin

Prefer symbolic stdin when the target reads from stdin normally.

Examples:
- `send_line {"line":"AAAA", "symbolic": true}`
- `send_bytes {"data":"AAAA", "symbolic": true}`
- `send_file {"path":"/tmp/payload.bin", "symbolic": true}`

Important:
- Keep byte order exact. Dynamiq preserves stdin chunk order.
- Mixed concrete + symbolic stdin is supported.
- Symbolic stdin does not matter until the guest actually consumes it.

Practical loop:
1. `start`
2. `send_line` / `send_bytes` with `symbolic: true`
3. `advance {"mode":"continue"}` until the input has been consumed
4. Inspect with `regs` or `mem`
5. Use `expr` or path-constraint tools

### Explicit symbolization

Use these when the interesting data source is not stdin, or when you want to symbolize a specific paused location.

- `symbolize_mem {"address":"0x...", "size": N}`
- `symbolize_reg {"register":"rax"}`

After symbolizing:
1. `advance`
2. inspect with `regs` / `mem`
3. call `expr` on a non-zero label

## Expression Workflow

Use this when you want a symbolic expression for a specific byte/register/value.

1. Find a symbolic label from:
- `regs.result.symbolic_registers`
- `mem.result.symbolic_bytes`

2. Call:
- `expr {"label":"0x..."}`

Typical flow:
1. send symbolic input or explicitly symbolize memory/registers
2. `advance`
3. `regs` or `mem`
4. pick the first non-zero label
5. `expr`

## Path-Constraint Workflow

Use this after symbolic data has influenced control flow.

Tools:
- `recent_path_constraints`
- `path_constraint_closure`

Typical flow:
1. send symbolic stdin or symbolize data explicitly
2. `advance {"mode":"continue"}` until the program reaches a branch, failure, success path, or terminal pending-exit
3. call `recent_path_constraints {"limit": 5}`
4. pick the newest label from `constraints[0].label`
5. call `path_constraint_closure {"label":"<newest>"}`

Read the results like this:
- `expression`: the branch condition
- `taken`: which direction was observed in this run
- `pc`: where the condition was recorded

Good times to query path constraints:
- after a branch-oriented breakpoint
- after a symbolic failure path like `You lose!`
- during terminal pending-exit before final process teardown

## End-to-End Symbolic Example

Goal: send symbolic stdin, inspect a symbolic branch, then inspect its expression.

1. `start`
2. `send_bytes {"data":"AAAA", "symbolic": true}`
3. `advance {"mode":"continue"}`
4. `stdout`
5. `state`
6. `recent_path_constraints {"limit": 5}`
7. take `constraints[0].label`
8. `path_constraint_closure {"label":"<that label>"}`
9. if needed, use `regs` or `mem` to find a specific symbolic label
10. `expr {"label":"0x..."}`

## Tool Guide

- `start`: begin a session
- `close`: terminate the session
- `state`: current lifecycle and stop state
- `advance`: main motion control
- `pause`: force a pause while running
- `syms`: resolve runtime symbols for this session
- `bp_add` / `bp_del` / `bp_clear` / `bp_list`: breakpoint management
- `watch` / `watch_clear`: persistent write watchpoints for guest memory ranges
- `stdout` / `stderr`: incremental stream reads
- `send_line` / `send_bytes` / `send_file`: stdin delivery
- `close_stdin`: close stdin so EOF-driven readers stop blocking
- `regs`: register snapshot and symbolic register labels
- `mem`: memory bytes and symbolic byte labels
- `mem_search`: search guest memory for byte patterns
- `disasm`: instruction view around an address
- `bt`: quick call-chain context
- `maps`: guest memory map summary
- `symbolize_mem` / `symbolize_reg`: explicit symbolic injection
- `expr`: symbolic expression for one label
- `recent_path_constraints`: newest observed path conditions
- `path_constraint_closure`: nested constraint closure for one label
- `trace_start` / `trace_stop` / `trace_status` / `trace_get`: trace capture workflow

## Recovery

If the session looks stale or inconsistent:
1. `state`
2. `stdout`
3. `stderr`
4. `close`
5. `start` again
6. rebuild breakpoints from fresh `syms`

## Notes

- Prefer absolute paths in `start`.
- Do not reuse addresses from earlier sessions.
- For stack inspection, get `rsp` from `regs` first.
- For stdin-driven symbolic analysis, prefer `send_line` / `send_bytes` / `send_file` with `symbolic: true` over manual post-read buffer symbolization.
- Query path constraints only after the symbolic bytes have actually affected control flow.
