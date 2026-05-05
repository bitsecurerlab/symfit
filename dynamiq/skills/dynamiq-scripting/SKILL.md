---
name: dynamiq-scripting
description: Use when implementing autonomous program analysis, testing, or security scanning workflows. For persistent session control with Python, including stepping, breakpoints, write watchpoints, memory inspection/search, symbolic stdin, path-constraint solving, and event tracing—without JSON-RPC round-trips.
---

# Dynamiq Scripting API Skill

Use this skill when building autonomous systems that need to control and analyze target programs programmatically. This is the Python scripting interface (not MCP).

Examples below assume one of these setups:
- dynamiq is installed into the active Python environment, or
- you are running from the repo root with `PYTHONPATH=src`

Repo-local example runner:
```bash
cd /home/heng/git/dynamiq
PYTHONPATH=src .venv/bin/python your_script.py
```

## When to Use Scripting API

The **Scripting API** (`ScriptSession` class) is designed for:
- **Autonomous testing**: Deterministic test suites with checkpoints and assertions
- **Security scanning**: Continuous analysis with breakpoints, memory watches, syscall tracing
- **CI/CD pipelines**: Automated validation of binary behavior before deployment
- **Complex workflows**: Multi-step analysis where session state must persist between operations

**Avoid scripting if:** You need interactive exploration with an LLM (use MCP instead).

## Quick Start

```python
from dynamiq.script_api import ScriptSession

# Simplest usage - QEMU auto-configured
with ScriptSession(target="/path/to/binary", args=["arg1"]) as session:
    session.step(5)                           # Step 5 instructions
    regs = session.get_registers(["rax"])    # Read registers
    session.bp_add("0x401000")                # Add breakpoint
    session.bp_run(timeout=2.0)               # Execute until breakpoint
    trace = session.trace_get(limit=100)      # Get execution trace
```

### System-mode VM quick start

Use `ScriptSession.system(...)` for instrumented `qemu-system` sessions:

```python
from dynamiq.script_api import ScriptSession

with ScriptSession.system(
    qemu_args=["-machine", "pc", "-display", "none", "-S"],
    arch="x86_64",
) as session:
    regs = session.get_registers(["rip", "rsp"])
    boot = session.read_memory("0x7c00", 4, address_space="physical")
```

System-mode sessions use QMP plus the instrumentation RPC socket. They can read
guest physical memory with `address_space="physical"` and do not expose stdin as
a target process stream.

## Core Concepts

### 1. Session Lifecycle (context manager)
```python
# Automatic cleanup
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    # Session started; ready for commands
    session.step(10)
    # Session auto-closes on exit
```

### 2. All AnalysisSession Methods Available
- **Lifecycle**: `start()`, `close()`, `capabilities()`
- **Execution**: `step()`, `run()`, `pause()`, `advance_basic_blocks()`, `run_until_address()`
- **Breakpoints/watchpoints**: `bp_add()`, `bp_del()`, `bp_list()`, `bp_clear()`, `bp_run()`, `watch()`, `watch_clear()`
- **Inspection**: `get_registers()`, `read_memory()`, `mem_search()`, `backtrace()`, `disassemble()`, `symbols()`, `list_memory_maps()`, `get_state()`
- **I/O**: `write_stdin()`, `write_stdin_and_advance()`, `read_stdout()`, `read_stderr()`
- **Tracing**: `trace_start()`, `trace_stop()`, `trace_status()`, `trace_get()`, `get_recent_events()`
- **Snapshots**: `take_snapshot()`, `restore_snapshot()`, `diff_snapshots()`
- **Annotations**: `annotate()`, `list_annotations()`

### 3. Symbolic Execution Support

The scripting API now exposes symbolic-execution helpers through `AnalysisSession`:
- `symbolize_memory(address, size, name=None)`
- `symbolize_register(register, name=None)`
- `get_symbolic_expression(label)`
- `recent_path_constraints(limit=16)`
- `path_constraint_closure(label)`
- `solve_path_constraint(label, negate=True)`
- `dynamiq.script_helpers.solve_for(session, target_pc, replay, ...)` for verified rerun through a harness-specific replay adapter

Important:
- Dynamiq does not symbolize argv, stack buffers, heap buffers, or derived parser buffers automatically.
- For stdin-driven input, prefer `write_stdin(..., symbolic=True)`. When the runtime supports `queue_stdin_chunk`, dynamiq records each stdin write as an ordered concrete or symbolic chunk, and the consumed stdin bytes become symbolic automatically at the syscall boundary.
- Use explicit `symbolize_memory(...)` or `symbolize_register(...)` for non-stdin sources or when you want to symbolize a later derived buffer instead of the original stdin stream.

Typical symbolic stdin workflow:
```python
with ScriptSession(target="/path/to/target", auto_start=True) as session:
    session.write_stdin("1\n", symbolic=False)   # concrete menu choice
    session.write_stdin("AAAA", symbolic=True)   # symbolic stdin payload
    session.advance(mode="continue", timeout=2.0)

    # Once the target has consumed the stdin bytes, inspect memory or registers.
    mem = session.read_memory("0x404030", 8)
    first_symbolic = next(
        entry["label"]
        for entry in mem["result"]["symbolic_bytes"]
        if entry["symbolic"]
    )

    expr = session.get_symbolic_expression(first_symbolic)
    recent = session.recent_path_constraints(limit=8)
    label = recent["result"]["constraints"][0]["label"]
    closure = session.path_constraint_closure(label)
    model = session.solve_path_constraint(label, negate=True)
    assert closure["result"]["root"]["taken"] is True
```

Use `solve_for` when you need to prove a target PC is reachable. It negates
recent path constraints and asks a replay adapter to rerun the real harness with
the candidate bytes. The adapter is responsible for patching seed input,
launching the target, driving WAIT states, closing stdin, setting verification
breakpoints, and returning `{"reached": True}` only after the target PC is
actually hit.

For deeper exploration, the adapter's replay verdict may return additional
`candidates`. `solve_for` queues those candidates breadth-first and keeps
replaying them up to `max_replays`, which is useful when SymFit reruns are cheap.

```python
from dynamiq.script_helpers import BytesReplayAdapter, solve_for

def run_candidate(candidate: bytes, target_pc: str, timeout: float) -> dict:
    # Harness-specific replay and verification.
    return {"reached": False}

replay = BytesReplayAdapter(seed=seed_bytes, runner=run_candidate)
result = solve_for(session, "0x4218b6faf0", replay, limit=16, max_replays=128)
```

### 4. Auto-Detection (Zero Configuration)
```python
# QEMU binary path auto-detected from target architecture
# RPC socket auto-created in temp directory
# Everything just works
with ScriptSession(target="/bin/ls") as session:
    pass
```

### 5. Blocked Syscalls Are Inspectable

When `advance(mode="continue")` returns `session_status == "blocked"` and
`stop_reason == "syscall_block"`, the guest is sleeping in a host syscall such
as `read`, `poll`, `recv`, `futex`, or `wait`. Treat that like an inspectable
stop:

```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    stopped = session.advance(mode="continue", timeout=5.0)
    if stopped["state"]["session_status"] == "blocked":
        regs = session.get_registers(["rip", "rsp"])
        maps = session.list_memory_maps()
        buf = session.symbols(name_filter="input_buf")["result"]["symbols"][0]["loaded_address"]
        before = session.read_memory(buf, 16)
        session.symbolize_memory(buf, 16, name="blocked_input")
```

This is the right time to inspect or symbolize known buffers before sending
more stdin or calling `close_stdin()`. Do not set blind breakpoints just to make
the target inspectable.

When stdin may immediately unblock execution and hit a breakpoint, prefer
`write_stdin_and_advance(...)` over separate `write_stdin()` and
`advance(mode="continue")` calls:

```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    session.bp_add("0x401234")
    session.advance(mode="continue", timeout=5.0)  # stops blocked in read()
    hit = session.write_stdin_and_advance(b"A", timeout=5.0)
    assert hit["result"]["advance"]["stop_reason"] == "breakpoint"
```

This writes stdin and then observes the next stop without issuing an extra
resume first, avoiding a race where the process can hit the breakpoint and exit
between two separate calls.

## Helper Utilities

Import from `dynamiq.script_helpers`:

### Convenience Functions
```python
from dynamiq.script_helpers import (
    run_until_event,
    run_until_instruction,
    collect_trace_between_addresses,
    inspect_function_with_trace,
)

# Run until syscall event
event = run_until_event(session, ["syscall"], timeout=2.0)

# Run until instruction mnemonic
if run_until_instruction(session, "call"):
    print("Found call instruction")

# Trace execution between two addresses
trace = collect_trace_between_addresses(session, "0x401000", "0x401100")
```

### Context Managers
```python
from dynamiq.script_helpers import (
    breakpoint_group,
    trace_region_context,
    MemoryWatch,
)

# Temporary breakpoint group
with breakpoint_group(session, ["0x401000", "0x401100"]):
    session.bp_run(timeout=10.0)

# Trace specific region
with trace_region_context(session, "0x401000", "0x402000"):
    session.run(timeout=5.0)

# Watch memory for changes
watch = MemoryWatch(session, "0x404000", 32)
watch.check()  # Returns True if memory changed
```

### Assertions for Testing
```python
from dynamiq.script_helpers import (
    assert_memory_pattern,
    assert_register_value,
    checkpoint_restore_test,
)

# Validate memory
assert_memory_pattern(session, "0x401000", b"\x55\x48\x89", "function prologue")

# Validate registers
assert_register_value(session, "rax", "0x42", "return value")

# Repeatable testing via checkpoint/restore
def test_scenario(s):
    s.step(10)
    return s.get_registers(["rax"])

results = checkpoint_restore_test(session, test_scenario, num_iterations=3)
```

## Common Workflows

### Workflow 1: Breakpoint-Driven Analysis
```python
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    # Find main in the main executable.
    symbols = session.symbols(name_filter="main")
    main_addr = symbols["result"]["symbols"][0]["loaded_address"]
    
    # Run to main
    session.bp_add(main_addr)
    session.bp_run(timeout=2.0)
    
    # Inspect at main
    regs = session.get_registers(["rsp", "rip"])
    print(f"At main: RIP={regs['result']['registers']['rip']}")
```

For shared libraries, prefer module-relative breakpoints so ASLR and `dlopen`
do not force you to recompute absolute addresses:

```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    session.bp_add(module="libc.so", symbol="malloc")
    session.bp_add(module="libffmpeg.so", offset="0xad1548")
    session.bp_run(timeout=5.0)
```

Dynamiq can query memory maps while the target is running, so module-relative
breakpoint resolution does not require manually pausing just to read `maps`. If
the module has not been loaded yet, run until after the `dlopen` point and retry
the same module-relative `bp_add`.

### Workflow 2: Trace Syscalls
```python
with ScriptSession(target="/bin/ls", auto_start=True) as session:
    session.trace_start(event_types=["syscall"])
    
    for _ in range(100):
        session.step(count=10, timeout=1.0)
    
    trace = session.trace_get(limit=1000)
    for event in trace["result"]["trace"]:
        print(f"Syscall: {event.get('name')}")
```

### Workflow 3: Memory Search
```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    # Find a JP2 box signature without guessing the heap address.
    result = session.mem_search(
        b"\x00\x00\x00\x0cjP  ",
        start="0x4000000000",
        end="0x4200000000",
    )
    print(result["result"]["matches"])
```

Omit `start` and `end` to search all readable mapped regions. Use bytes for
binary signatures; strings are treated as byte-sized latin-1 text.

### Workflow 4: Automated Testing
```python
def test_function():
    with ScriptSession(target="/bin/myapp", auto_start=True) as session:
        # Set breakpoint at function
        session.bp_add("0x401234")
        session.bp_run(timeout=2.0)
        
        # Verify state at breakpoint
        state = session.get_state()
        assert state["state"]["session_status"] == "paused"
        
        # Read memory, inspect registers
        memory = session.read_memory("0x404000", 32)
        assert memory["result"]["bytes"] == "deadbeef..."
        
        # Verify function was called
        return True
```

### Workflow 5: Memory Watching
Use runtime write watchpoints when you need to stop at the exact instruction
that writes a watched guest address range:

```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    session.watch(address="0x41651d47a0", size=8, mode="write")

    hit = session.advance(mode="continue", timeout=5.0)
    assert hit["result"]["stop_reason"] == "watchpoint"
    print(hit["state"]["watchpoint"])

    # The store has not executed yet at the watchpoint stop. Continuing
    # reexecutes that instruction once, then later matching writes still trap.
    session.advance(mode="continue", timeout=5.0)
```

Watchpoints are persistent until `watch_clear()` or session close. They work in
both concrete and symbolic execution modes. Use them for corruption debugging,
for example catching the write that changes a struct field or heap metadata.

Use polling-style `MemoryWatch` only when you want change detection from Python
and do not need the exact writer instruction:

```python
from dynamiq.script_helpers import MemoryWatch

def on_change(addr, old, new):
    print(f"Memory changed at {addr}: {old.hex()} → {new.hex()}")

with ScriptSession(target="/bin/ls", auto_start=True) as session:
    watch = MemoryWatch(session, "0x404000", 8, on_change=on_change)
    
    with watch:
        while not watch.check():
            session.step(count=1, timeout=1.0)
            # Check triggers on_change callback if memory changed
```

### Workflow 6: Mixed Concrete and Symbolic Stdin
```python
with ScriptSession(target="/bin/myapp", auto_start=True) as session:
    session.write_stdin("1\n", symbolic=False)    # concrete menu input
    session.write_stdin("AAAA", symbolic=True)    # symbolic stdin payload
    session.advance(mode="continue", timeout=2.0)

    # Inspect where the program consumed the stdin bytes.
    mem = session.read_memory("0x404030", 8)
    symbolic_labels = [
        entry["label"]
        for entry in mem["result"]["symbolic_bytes"]
        if entry["symbolic"]
    ]

    if symbolic_labels:
        expr = session.get_symbolic_expression(symbolic_labels[0])
        print(expr["result"]["expression"])
```

## Required Operating Rules

1. **Always use context manager for cleanup**
   ```python
   with ScriptSession(target=...) as session:
       # Session will be properly closed even if exception occurs
   ```

2. **Check session status before operations**
   ```python
   if session.is_paused:
       regs = session.get_registers()
   ```

3. **Use helper functions for complex patterns**
   - Don't manually loop checking PC; use `run_until_event()`, `run_until_instruction()`
   - Don't manually manage breakpoint sets; use `breakpoint_group()`
   - Don't manually track checkpoints; use `checkpoint_restore_test()`

4. **Understand instruction vs. basic block stepping**
   ```python
   session.step(count=5)                    # Step 5 instructions
   session.advance_basic_blocks(count=3)    # Advance 3 basic blocks
   ```

5. **Use assertions for test validation**
   ```python
   assert_register_value(session, "rax", "0x42")  # Fails loudly if mismatch
   assert_memory_pattern(session, "0x401000", b"...")
   ```

6. **Override only what you need**
   ```python
   # Default QEMU auto-detection works; override only if needed
   with ScriptSession(
       target="/bin/ls",
       qemu_config={"qemu_user_path": "/custom/qemu-x86_64"}  # Override only QEMU path
   ) as session:
       pass
   ```

7. **Use queued symbolic stdin for stdin-driven input**
   ```python
   session.write_stdin("menu\n", symbolic=False)
   session.write_stdin("AAAA", symbolic=True)
   ```
   This is the preferred path for stdin. Use `symbolize_memory(...)` only for non-stdin sources or later derived buffers.

8. **Verify symbolic state immediately**
   ```python
   mem = session.read_memory(buf, 8)
   assert mem["result"]["symbolic_bytes"][0]["symbolic"] is True
   label = mem["result"]["symbolic_bytes"][0]["label"]
   expr = session.get_symbolic_expression(label)
   ```

## Error Handling

Errors are Python exceptions (not JSON), making debugging easier:

```python
from dynamiq.errors import InvalidStateError

try:
    session.read_memory("0x401000", 1000000)  # Size too large
except InvalidStateError as e:
    print(f"Error: {e}")
    # Handle gracefully in autonomous context
```

## Integration with Autonomous Systems

The Scripting API is designed for **non-interactive automation**:

- **No human intervention needed**: QEMU auto-detected, sockets auto-created
- **Deterministic execution**: Checkpoint/restore for repeatable test scenarios
- **Full state access**: Get complete ExecutionState dict, not just formatted JSON
- **Long-running safe**: Context managers and assertions prevent resource leaks

Example autonomous security scanner:

```python
def scan_binary(binary_path):
    issues = []
    
    with ScriptSession(target=binary_path, auto_start=True) as session:
        # Find all syscalls
        session.trace_start(event_types=["syscall"])
        for _ in range(1000):
            session.step(count=10, timeout=1.0)
        
        trace = session.trace_get(limit=10000)
        
        # Detect dangerous syscalls
        dangerous = ["execve", "system", "setuid"]
        for event in trace["result"]["trace"]:
            if event.get("name") in dangerous:
                issues.append(f"Dangerous syscall: {event['name']}")
        
        # Check for stack buffer overflows
        # ... more analysis ...
    
    return issues
```

## Comparison: MCP vs Scripting API

| Operation | MCP | Scripting |
|-----------|-----|----------|
| One line of Python to step 5x | ❌ Multiple JSON-RPC calls | ✅ `session.step(5)` |
| Maintain session state | ❌ Manual in LLM | ✅ Automatic |
| Set 3 breakpoints | ❌ 3 separate tool calls | ✅ `session.bp_add()` × 3 (auto-batched) |
| Checkpoint/restore | ❌ Manual snapshots | ✅ `checkpoint_restore_test()` |
| Error handling | ❌ JSON errors | ✅ Python exceptions |
| Real-time feedback | ✅ Interactive with human | ❌ Not interactive |
| Setup overhead | ✅ None (MCP server) | ❌ Python environment needed |

## Examples

See `examples/` directory:
- `script_basic_control.py` — Basic session start/step/inspect operations
- `script_automated_testing.py` — Test harness with assertions and checkpoint/restore
- `script_security_analysis.py` — Syscall tracing, memory analysis, function detection
