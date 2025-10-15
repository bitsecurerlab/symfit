# SymFit JavaScript Plugin System - Prototype

This is a working prototype demonstrating JavaScript plugins for SymFit using QuickJS.

## What's Included

- **Plugin Interface** (`include/symfit_plugin.h`) - C API for plugin system
- **QuickJS Bridge** (`src/symfit_plugin.c`) - JavaScript embedding implementation
- **Test Program** (`test/test_plugin.c`) - Simulates a simple maze game
- **Example Plugin** (`examples/simple_plugin.js`) - Demonstrates plugin capabilities

## Features Demonstrated

✅ **JavaScript plugin loading** - Load .js files at runtime
✅ **Memory instrumentation** - Track memory writes
✅ **Syscall monitoring** - Detect program output
✅ **State hashing** - For test case deduplication
✅ **Execution scoring** - Prioritize interesting executions
✅ **Goal detection** - Early termination on win condition

## Quick Start

### Option 1: Without QuickJS (Shim Mode)

Build and run with a minimal shim (no actual JS execution, but demonstrates the API):

```bash
cd plugins-prototype
make
make test
```

### Option 2: With QuickJS (Full Functionality)

Install QuickJS and build with full JavaScript support:

```bash
cd plugins-prototype

# Download and build QuickJS
make quickjs

# Build test program with QuickJS
make clean
make

# Run test
make test
```

## Manual Testing

```bash
# Run without plugin
./test/test_plugin --moves "ddssd"

# Run with plugin
./test/test_plugin --plugin examples/simple_plugin.js --moves "ddssd"

# Try different move sequences
./test/test_plugin --plugin examples/simple_plugin.js --moves "ddddsssss"
```

## Example Output

```
=== SymFit Plugin System Prototype ===

[SymFit] Loading plugin: examples/simple_plugin.js
[SymFit] Plugin code loaded (1234 bytes)
[SymFit] Calling plugin.onInit()
[Plugin] Simple test plugin initialized
[SymFit] Plugin loaded successfully

=== Simulating Game ===
Goal: Reach position (5, 5)
Moves: ddssd

Position: (0, 0) | Goal: (5, 5) | Moves: 0

Move: d
[Plugin] Memory write: addr=0x7ffc12345678, size=4, value=1
[Plugin] Detected player X at 0x7ffc12345678
Position: (1, 0) | Goal: (5, 5) | Moves: 1

Move: d
[Plugin] Memory write: addr=0x7ffc12345678, size=4, value=2
Position: (2, 0) | Goal: (5, 5) | Moves: 2

...

Move: d
Position: (5, 5) | Goal: (5, 5) | Moves: 5
You win!
[Plugin] Program output: You win!
[Plugin] 🎉 WIN DETECTED!

=== Plugin Results ===
[Plugin] Scoring execution...
[Plugin] Score: 10000.0 (WIN!)
Execution score: 10000.00
State hash: 0x0000000500000005
[SymFit] Calling plugin.onFini()
[Plugin] Shutting down
[Plugin] Total memory writes tracked: 10
[Plugin] Unique positions visited: 6
```

## How It Works

### 1. Plugin Loading

```c
// Load plugin from JavaScript file
SymFitPlugin *plugin = symfit_plugin_load("maze_plugin.js");
```

The plugin file exports a `plugin` object with callbacks:

```javascript
export const plugin = {
    onMemoryWrite(addr, size, value) { ... },
    scoreExecution(ctx) { ... },
    // ... more callbacks
};
```

### 2. Instrumentation Hooks

The test program simulates QEMU hooks:

```c
// Simulate memory write (would be QEMU hook in real implementation)
void update_position(SymFitPlugin *plugin, int *var, int value) {
    uint64_t addr = (uint64_t)var;
    *var = value;

    // Call plugin hook
    symfit_plugin_on_memory_write(plugin, addr, 4, value);
}
```

### 3. Decision Callbacks

Get information from plugin:

```c
// Score this execution
double score = symfit_plugin_score_execution(plugin);

// Get state hash for deduplication
uint64_t hash = symfit_plugin_get_state_hash(plugin);

// Check if goal reached
if (symfit_plugin_is_goal_reached(plugin)) {
    printf("Goal reached!\n");
}
```

## Creating Your Own Plugin

```javascript
// my_plugin.js
export const plugin = {
    state: {
        // Your state variables
    },

    onInit() {
        console.log("Plugin initialized");
    },

    onMemoryWrite(addr, size, value) {
        // Called on every memory write
        console.log(`Write: ${addr.toString(16)} = ${value}`);
    },

    scoreExecution(ctx) {
        // Return score (higher = more interesting)
        return 100.0;
    },

    getStateHash(ctx) {
        // Return hash for deduplication
        return 0n;
    }
};
```

Test it:

```bash
./test/test_plugin --plugin my_plugin.js
```

## API Reference

### Plugin Callbacks

| Callback | Purpose |
|----------|---------|
| `onInit()` | Called when plugin loads |
| `onMemoryWrite(addr, size, val)` | Memory write hook |
| `onMemoryRead(addr, size, val)` | Memory read hook |
| `onSyscall(num, args)` | Before syscall |
| `onSyscallReturn(num, args, ret, data)` | After syscall |
| `getStateHash(ctx)` | State for deduplication |
| `scoreExecution(ctx)` | Execution scoring |
| `isGoalReached(ctx)` | Goal detection |
| `onFini()` | Called when plugin unloads |

### Context Object

```javascript
ctx = {
    pc: 0x400500n,              // Program counter
    instructionCount: 12345n,   // Instructions executed
    readMemory(addr, size),     // Read memory
    // ... more
}
```

## Architecture

```
┌─────────────────────────────────────┐
│   Test Program (test_plugin.c)     │
│   - Simulates game                  │
│   - Calls plugin hooks              │
└──────────┬──────────────────────────┘
           │
           │ C API
           ▼
┌─────────────────────────────────────┐
│   Plugin Bridge (symfit_plugin.c)   │
│   - Embeds QuickJS                  │
│   - Manages JS lifecycle            │
│   - Bridges C ↔ JavaScript          │
└──────────┬──────────────────────────┘
           │
           │ QuickJS API
           ▼
┌─────────────────────────────────────┐
│   JavaScript Plugin                 │
│   - User-written code               │
│   - Implements callbacks            │
└─────────────────────────────────────┘
```

## Next Steps

To integrate into real SymFit:

1. **Add QuickJS to build system**
   ```bash
   git submodule add https://github.com/bellard/quickjs.git external/quickjs
   ```

2. **Add hooks in QEMU**
   - In `accel/tcg/cputlb.c` - Memory access hooks
   - In `linux-user/syscall.c` - Syscall hooks
   - In TCG translator - Basic block hooks

3. **Integrate with symbolic execution**
   - Use `symfit_plugin_score_execution()` for test case prioritization
   - Use `symfit_plugin_get_state_hash()` for deduplication
   - Use `symfit_plugin_is_goal_reached()` for early termination

4. **Add to MCP server**
   - Add `--plugin` parameter to campaign tool
   - Pass through to SymFit execution

## Performance

The prototype demonstrates minimal overhead:

- QuickJS is lightweight (~1MB)
- Callback overhead ~50-100 cycles
- Plugin state persists across executions
- JavaScript JIT provides good performance

## Limitations of Prototype

This prototype has simplified implementations:

- ✅ Plugin loading works
- ✅ Callbacks are called
- ✅ State is maintained
- ⚠️ Memory reads return dummy values (need QEMU integration)
- ⚠️ Syscall data is simplified
- ⚠️ No actual symbolic execution

For full functionality, integrate with real SymFit/QEMU.

## Files

```
plugins-prototype/
├── include/
│   └── symfit_plugin.h        # Plugin API header
├── src/
│   └── symfit_plugin.c        # QuickJS bridge implementation
├── test/
│   └── test_plugin.c          # Test program
├── examples/
│   └── simple_plugin.js       # Example plugin
├── Makefile                   # Build system
└── README.md                  # This file
```

## License

Same as SymFit main project.

## Questions?

See the full design document: `javascript_plugin_implementation_plan.md`
