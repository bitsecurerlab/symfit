# SymFit JavaScript Plugins - Quick Start

## What You Can Do

With JavaScript plugins, you can:
- **Track program state** (e.g., player position in a game)
- **Detect win conditions** (e.g., "You win!" message)
- **Score executions** (prioritize interesting paths)
- **Deduplicate test cases** (one test per unique state)
- **Guide symbolic execution** (suggest promising inputs)

**No compilation needed** - write JavaScript, run immediately!

## Complete Example: Maze Solving

### Step 1: Write Plugin (by LLM or human)

```javascript
// maze_plugin.js
export const plugin = {
    state: {
        visitedPositions: new Set(),
        playerAddr: null
    },

    // Auto-detect player position in memory
    onMemoryWrite(addr, size, value) {
        if (size === 4 && value < 50n && !this.state.playerAddr) {
            console.log(`Detected position at ${addr.toString(16)}`);
            this.state.playerAddr = addr;
        }
    },

    // Detect win condition
    onSyscallReturn(num, args, ret, data) {
        if (num === 1 && data.buffer?.toString().includes("You win")) {
            console.log("🎉 WIN!");
            return { stopCampaign: true };
        }
    },

    // Deduplicate by position
    getStateHash(ctx) {
        if (!this.state.playerAddr) return 0n;
        return ctx.readMemory(this.state.playerAddr, 4);
    },

    // Score by exploration
    scoreExecution(ctx) {
        if (!this.state.playerAddr) return 1.0;

        const pos = ctx.readMemory(this.state.playerAddr, 4);
        if (!this.state.visitedPositions.has(pos)) {
            this.state.visitedPositions.add(pos);
            console.log(`New position: ${pos}`);
            return 100.0;  // High priority!
        }
        return 1.0;
    }
};
```

### Step 2: Run SymFit with Plugin

```bash
# Command line
./build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 \
    --plugin maze_plugin.js \
    /tmp/maze_test/maze-nosleep

# Or via MCP server
node mcp-server/index.js run-campaign \
    --binary /tmp/maze_test/maze-nosleep \
    --corpus /tmp/corpus \
    --plugin maze_plugin.js
```

### Step 3: See Results

```
[Maze] Plugin initialized
[Maze] Detected position at 0x601040
[Maze] New position: 0
[Maze] New position: 1
[Maze] New position: 5
...
[Maze] 🎉 WIN CONDITION DETECTED!
[Maze] Solution: ssssddddwwaawwddddsddw

Campaign completed in 45 seconds
Unique positions explored: 24
Solution found: YES ✓
```

## API Cheat Sheet

### Available Hooks

```javascript
export const plugin = {
    // === Lifecycle ===
    onInit() { },                    // Plugin loaded
    onExecutionStart(input) { },     // Before each test
    onExecutionEnd(ctx) { },         // After each test
    onFini() { },                    // Plugin unloaded

    // === Instrumentation ===
    onBasicBlock(pc, size) { },      // Each basic block
    onMemoryWrite(addr, size, val) { }, // Memory writes
    onMemoryRead(addr, size, val) { },  // Memory reads
    onSyscall(num, args) { },        // Before syscall
    onSyscallReturn(num, args, ret, data) { }, // After syscall

    // === Decisions ===
    getStateHash(ctx) { },           // For deduplication
    scoreExecution(ctx) { },         // Prioritization
    isGoalReached(ctx) { },          // Early termination
    suggestInputs(input, ctx) { }    // Input generation
};
```

### Context Object

```javascript
ctx = {
    pc: 0x400500n,                   // Program counter
    instructionCount: 12345n,        // Instructions executed
    regs: { rax: 0n, rbx: 0n, ... }, // CPU registers

    readMemory(addr, size),          // Read from memory
    readString(addr, maxLen),        // Read C string
    getCurrentInput()                // Current test input
}
```

### Return Values

```javascript
// Stop campaign early
onSyscallReturn(...) {
    return { stopCampaign: true };
}

// Suggest inputs
suggestInputs(currentInput, ctx) {
    return [input1, input2, input3];  // Array of Uint8Array
}
```

## Common Patterns

### Pattern 1: Auto-Detect Variables

```javascript
// Detect small integer variables (coordinates, counters, etc.)
onMemoryWrite(addr, size, value) {
    if (size === 4 && value < 100n) {
        this.trackAddr(addr);
    }
}
```

### Pattern 2: Parse Program Output

```javascript
onSyscallReturn(num, args, ret, data) {
    if (num === 1 && data.buffer) {
        const output = data.buffer.toString();

        // Extract score
        const match = output.match(/Score: (\d+)/);
        if (match) {
            this.currentScore = parseInt(match[1]);
        }
    }
}
```

### Pattern 3: Track Visited States

```javascript
state: {
    visited: new Set()
},

getStateHash(ctx) {
    const x = ctx.readMemory(this.xAddr, 4);
    const y = ctx.readMemory(this.yAddr, 4);
    return (x << 32n) | y;
},

scoreExecution(ctx) {
    const hash = this.getStateHash(ctx);
    if (!this.state.visited.has(hash)) {
        this.state.visited.add(hash);
        return 100.0;  // New state!
    }
    return 1.0;
}
```

### Pattern 4: Distance-Based Scoring

```javascript
scoreExecution(ctx) {
    const playerX = ctx.readMemory(this.playerAddr, 4);
    const playerY = ctx.readMemory(this.playerAddr + 4n, 4);

    const goalX = 10n, goalY = 10n;

    const dist = Math.abs(Number(playerX - goalX)) +
                Math.abs(Number(playerY - goalY));

    return 100.0 / (dist + 1);  // Closer = higher score
}
```

## LLM Workflow

### 1. LLM Writes Initial Plugin

```
User: "Help me solve this maze binary"

LLM: "I'll create a plugin to track the maze state..."
[writes maze_plugin.js]
```

### 2. User Runs, Shares Results

```bash
$ symfit --plugin maze_plugin.js /tmp/maze
[Maze] Detected position at 0x601040
[Maze] New position: 0
[Maze] No solution found in 5 rounds
```

### 3. LLM Improves Plugin

```
User: "It found some positions but no solution"

LLM: "Let me add distance-based scoring to guide
      the search toward the goal..."
[updates plugin with goal-directed search]
```

### 4. Success

```bash
$ symfit --plugin maze_plugin_v2.js /tmp/maze
[Maze] New position: 0
[Maze] New position: 5 (closer to goal!)
[Maze] New position: 8 (getting closer!)
[Maze] 🎉 WIN! Solution: ssssddddwwaawwddddsddw
```

## Debugging Tips

### 1. Use console.log Liberally

```javascript
onMemoryWrite(addr, size, value) {
    console.log(`Write: ${addr.toString(16)} = ${value}`);
}
```

### 2. Check for Undefined

```javascript
getStateHash(ctx) {
    if (!this.state.playerAddr) {
        console.log("Warning: playerAddr not detected yet");
        return 0n;
    }
    return ctx.readMemory(this.state.playerAddr, 4);
}
```

### 3. Handle BigInt Properly

```javascript
// ✅ Correct
const addr = 0x601040n;
const next = addr + 4n;

// ❌ Wrong
const addr = 0x601040;  // Missing 'n'
const next = addr + 4;   // Mixed types
```

### 4. Validate Memory Reads

```javascript
readPosition() {
    if (!this.playerAddr) return null;

    try {
        return ctx.readMemory(this.playerAddr, 4);
    } catch (e) {
        console.log("Failed to read position:", e);
        return null;
    }
}
```

## Performance Tips

### 1. Disable Unused Hooks

```javascript
// Don't implement hooks you don't need
// Commenting out = not called = faster

// onBasicBlock(pc, size) { },  // Disabled - too verbose
// onMemoryRead(...) { },        // Disabled - don't need
```

### 2. Limit Console Output

```javascript
state: {
    logCount: 0
},

onMemoryWrite(addr, size, value) {
    // Only log first 10
    if (this.state.logCount++ < 10) {
        console.log(`Write: ${addr.toString(16)}`);
    }
}
```

### 3. Use Sets for Fast Lookup

```javascript
// ✅ Fast: O(1) lookup
visited: new Set()
visited.has(position)

// ❌ Slow: O(n) lookup
visited: []
visited.includes(position)
```

## Example Plugins

### Execution Tracer

```javascript
export const plugin = {
    state: { trace: [] },

    onBasicBlock(pc, size) {
        this.state.trace.push(pc);
    },

    onExecutionEnd(ctx) {
        console.log("Trace:", this.state.trace.map(pc =>
            `0x${pc.toString(16)}`
        ).join(" -> "));
    }
};
```

### Syscall Logger

```javascript
export const plugin = {
    onSyscallReturn(num, args, ret, data) {
        const names = { 1: 'write', 2: 'open', 3: 'close' };
        console.log(`${names[num] || num}() = ${ret}`);
    }
};
```

### Memory Tracker

```javascript
export const plugin = {
    state: { writes: new Map() },

    onMemoryWrite(addr, size, value) {
        const key = addr.toString(16);
        this.state.writes.set(key, {
            addr, size, value,
            count: (this.state.writes.get(key)?.count || 0) + 1
        });
    },

    onFini() {
        console.log("Most written addresses:");
        const sorted = [...this.state.writes.entries()]
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 10);

        for (const [addr, info] of sorted) {
            console.log(`  0x${addr}: ${info.count} writes`);
        }
    }
};
```

## Next Steps

1. **Try the examples**: Start with `maze_plugin.js`
2. **Experiment**: Modify and re-run immediately
3. **Create custom plugins**: For your specific binaries
4. **Share**: Plugins are reusable across similar programs

## Resources

- Full API docs: `docs/plugin-api.md`
- More examples: `examples/plugins/`
- Implementation: `javascript_plugin_implementation_plan.md`

## Getting Help

If your plugin isn't working:

1. Check console output for errors
2. Add more `console.log()` statements
3. Verify BigInt usage (use `n` suffix)
4. Check that hooks return correct types
5. Test with simpler binaries first

Happy plugin writing! 🚀
