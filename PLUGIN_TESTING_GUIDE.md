# SymFit Plugin Testing Guide

## Quick Test: Verify Integration Works

After integrating the plugin system, run this quick test:

```bash
cd /home/heng/git/symfit/plugins-prototype
./test/test_plugin --plugin examples/simple_plugin.js --moves "dddddsssss"
```

**Expected output**:
```
[Plugin] Simple test plugin initialized
[Plugin] Memory write: addr=0x..., size=4, value=1
[Plugin] Detected player X at ...
...
[Plugin] 🎉 WIN DETECTED!
[Plugin] Score: 10000.0 (WIN!)
```

If this works, the plugin system is functional ✅

---

## Test 1: Basic Memory Tracking

**Goal**: Track all memory writes during execution

**Plugin**: `/tmp/test1_memory_tracker.js`

```javascript
globalThis.plugin = {
    name: "Memory Tracker",

    state: {
        writeCount: 0,
        addressMap: new Map(),
    },

    onInit() {
        console.log("[Plugin] Memory tracker initialized");
    },

    onMemoryWrite(addr, size, value) {
        this.state.writeCount++;

        const key = addr.toString();
        if (!this.state.addressMap.has(key)) {
            this.state.addressMap.set(key, []);
        }
        this.state.addressMap.get(key).push(value);

        if (this.state.writeCount <= 10) {
            console.log(`[Plugin] Write #${this.state.writeCount}: ` +
                       `addr=0x${addr.toString(16)}, value=${value}`);
        }
    },

    scoreExecution(ctx) {
        // More memory activity = more interesting
        return this.state.writeCount * 1.0;
    },

    onFini() {
        console.log(`[Plugin] Total writes: ${this.state.writeCount}`);
        console.log(`[Plugin] Unique addresses: ${this.state.addressMap.size}`);
    }
};
```

**Test**:
```bash
./symfit --plugin /tmp/test1_memory_tracker.js /tmp/maze_test/maze-nosleep <<< "ddd"
```

**Expected**: Should see write counts and score based on activity

---

## Test 2: Output-Based Win Detection

**Goal**: Detect win condition from program output

**Plugin**: `/tmp/test2_win_detector.js`

```javascript
globalThis.plugin = {
    name: "Win Detector",

    state: {
        allOutput: "",
        winDetected: false,
    },

    onSyscallReturn(syscallNum, args, returnValue, data) {
        // Syscall 1 = write
        if (syscallNum === 1 && data.buffer) {
            const text = data.buffer.toString();
            this.state.allOutput += text;

            console.log(`[Plugin] Output: ${text.trim()}`);

            // Check for win patterns
            if (text.includes("You win") ||
                text.includes("WIN") ||
                text.includes("Success") ||
                text.includes("Congratulations")) {
                console.log("[Plugin] 🎉🎉🎉 WIN DETECTED! 🎉🎉🎉");
                this.state.winDetected = true;
            }
        }
    },

    scoreExecution(ctx) {
        // Massive bonus for winning
        return this.state.winDetected ? 1000000.0 : 1.0;
    },

    isGoalReached(ctx) {
        return this.state.winDetected;
    },

    onFini() {
        console.log("[Plugin] Full output:");
        console.log(this.state.allOutput);
        console.log(`[Plugin] Win detected: ${this.state.winDetected}`);
    }
};
```

**Test**:
```bash
# Losing move sequence
./symfit --plugin /tmp/test2_win_detector.js /tmp/maze_test/maze-nosleep <<< "aaa"
# Score should be 1.0

# Winning move sequence
./symfit --plugin /tmp/test2_win_detector.js /tmp/maze_test/maze-nosleep <<< "dddddsssss"
# Score should be 1000000.0, goal reached = true
```

---

## Test 3: Position-Based State Tracking

**Goal**: Track player position in maze, score by distance to goal

**Plugin**: `/tmp/test3_position_tracker.js`

```javascript
globalThis.plugin = {
    name: "Position Tracker",

    state: {
        playerXAddr: null,
        playerYAddr: null,
        playerX: 0,
        playerY: 0,
        goalX: 5,
        goalY: 5,
        visitedStates: new Set(),
    },

    onMemoryWrite(addr, size, value) {
        // Auto-detect position variables
        // First write of value 1 -> likely X coordinate
        if (!this.state.playerXAddr && value === 1) {
            this.state.playerXAddr = addr;
            this.state.playerX = value;
            console.log(`[Plugin] Detected playerX at 0x${addr.toString(16)}`);
            return;
        }

        // Second different address with value 1 -> likely Y coordinate
        if (!this.state.playerYAddr && value === 1 &&
            this.state.playerXAddr && addr !== this.state.playerXAddr) {
            this.state.playerYAddr = addr;
            this.state.playerY = value;
            console.log(`[Plugin] Detected playerY at 0x${addr.toString(16)}`);
            return;
        }

        // Update tracked positions
        if (this.state.playerXAddr && addr === this.state.playerXAddr) {
            this.state.playerX = value;
        }
        if (this.state.playerYAddr && addr === this.state.playerYAddr) {
            this.state.playerY = value;
        }
    },

    getStateHash(ctx) {
        // State = player position
        const x = BigInt(this.state.playerX);
        const y = BigInt(this.state.playerY);
        return (x << 32n) | y;
    },

    scoreExecution(ctx) {
        if (!this.state.playerXAddr) {
            return 50.0; // Position not detected yet
        }

        // Score based on Manhattan distance to goal
        const distX = Math.abs(this.state.playerX - this.state.goalX);
        const distY = Math.abs(this.state.playerY - this.state.goalY);
        const distance = distX + distY;

        // Closer = higher score
        const score = 1000.0 - (distance * 100.0);

        console.log(`[Plugin] Position: (${this.state.playerX}, ${this.state.playerY}), ` +
                   `Distance: ${distance}, Score: ${score}`);

        return score;
    },

    isGoalReached(ctx) {
        return this.state.playerX === this.state.goalX &&
               this.state.playerY === this.state.goalY;
    },

    onFini() {
        console.log(`[Plugin] Final position: (${this.state.playerX}, ${this.state.playerY})`);
        console.log(`[Plugin] Goal: (${this.state.goalX}, ${this.state.goalY})`);
        console.log(`[Plugin] Visited states: ${this.state.visitedStates.size}`);
    }
};
```

**Test**:
```bash
# Test different paths
./symfit --plugin /tmp/test3_position_tracker.js /tmp/maze_test/maze-nosleep <<< "ddd"
# Should show position (3,0), score ~800

./symfit --plugin /tmp/test3_position_tracker.js /tmp/maze_test/maze-nosleep <<< "sss"
# Should show position (0,3), score ~800

./symfit --plugin /tmp/test3_position_tracker.js /tmp/maze_test/maze-nosleep <<< "dddss"
# Should show position (3,2), score ~1000 (closer to goal)
```

---

## Test 4: Campaign with Plugin (Full Integration)

**Goal**: Run full symbolic execution campaign guided by plugin

**Plugin**: `/tmp/test4_maze_solver.js`

```javascript
globalThis.plugin = {
    name: "Maze Solver",

    state: {
        // Position tracking
        playerXAddr: null,
        playerYAddr: null,
        currentX: 0,
        currentY: 0,

        // Goal
        goalX: 5,
        goalY: 5,

        // Statistics
        visitedPositions: new Set(),
        winDetected: false,
    },

    onMemoryWrite(addr, size, value) {
        // Auto-detect position variables (same as test 3)
        if (!this.state.playerXAddr && value === 1) {
            this.state.playerXAddr = addr;
            this.state.currentX = value;
        } else if (!this.state.playerYAddr && value === 1 &&
                   this.state.playerXAddr && addr !== this.state.playerXAddr) {
            this.state.playerYAddr = addr;
            this.state.currentY = value;
        }

        // Update current position
        if (this.state.playerXAddr && addr === this.state.playerXAddr) {
            this.state.currentX = value;
        }
        if (this.state.playerYAddr && addr === this.state.playerYAddr) {
            this.state.currentY = value;
        }

        // Track visited positions
        const posKey = `${this.state.currentX},${this.state.currentY}`;
        this.state.visitedPositions.add(posKey);
    },

    onSyscallReturn(syscallNum, args, returnValue, data) {
        if (syscallNum === 1 && data.buffer) {
            const text = data.buffer.toString();
            if (text.includes("You win") || text.includes("WIN")) {
                this.state.winDetected = true;
            }
        }
    },

    getStateHash(ctx) {
        // State = current position (for deduplication)
        const x = BigInt(this.state.currentX);
        const y = BigInt(this.state.currentY);
        return (x << 32n) | y;
    },

    scoreExecution(ctx) {
        // Win = maximum score
        if (this.state.winDetected) {
            return 10000.0;
        }

        if (!this.state.playerXAddr) {
            return 1.0; // Positions not detected
        }

        // Base score on distance to goal (closer = better)
        const distX = Math.abs(this.state.currentX - this.state.goalX);
        const distY = Math.abs(this.state.currentY - this.state.goalY);
        const distance = distX + distY;
        const distanceScore = 1000.0 - (distance * 100.0);

        // Bonus for exploring new positions
        const explorationBonus = this.state.visitedPositions.size * 10.0;

        return distanceScore + explorationBonus;
    },

    isGoalReached(ctx) {
        return this.state.winDetected;
    },

    onFini() {
        console.log("[Plugin] === Maze Solver Statistics ===");
        console.log(`[Plugin] Final position: (${this.state.currentX}, ${this.state.currentY})`);
        console.log(`[Plugin] Goal position: (${this.state.goalX}, ${this.state.goalY})`);
        console.log(`[Plugin] Unique positions explored: ${this.state.visitedPositions.size}`);
        console.log(`[Plugin] Win detected: ${this.state.winDetected}`);

        if (this.state.winDetected) {
            console.log("[Plugin] 🎉 SUCCESS! Solution found!");
        }
    }
};
```

**Test Campaign**:

```bash
# Initialize corpus
mkdir -p /tmp/maze-corpus-plugin
echo -n "ddss" > /tmp/maze-corpus-plugin/seed1
echo -n "ssdd" > /tmp/maze-corpus-plugin/seed2

# Run campaign with plugin
./symfit \
    --plugin /tmp/test4_maze_solver.js \
    --corpus /tmp/maze-corpus-plugin \
    --max-rounds 10 \
    --timeout 5000 \
    /tmp/maze_test/maze-nosleep

# Check results
echo "=== Campaign Results ==="
ls -la /tmp/maze-corpus-plugin/
cat /tmp/maze-corpus-plugin/*.log
```

**Expected Results**:
- Should generate more test cases
- Test cases should gradually move toward (5,5)
- Should find winning input within 10 rounds
- Final corpus should contain solution

---

## Test 5: Performance Benchmarking

**Goal**: Measure plugin overhead

**Test Script**: `/tmp/test5_benchmark.sh`

```bash
#!/bin/bash

BINARY="/tmp/maze_test/maze-nosleep"
INPUT="dddddsssss"
ITERATIONS=100

# Test 1: Without plugin
echo "=== Baseline (No Plugin) ==="
time for i in $(seq 1 $ITERATIONS); do
    echo "$INPUT" | ./symfit $BINARY > /dev/null 2>&1
done

# Test 2: With minimal plugin
cat > /tmp/minimal_plugin.js << 'EOF'
globalThis.plugin = {
    onMemoryWrite() {},
    scoreExecution() { return 1.0; },
    getStateHash() { return 0n; }
};
EOF

echo -e "\n=== With Minimal Plugin ==="
time for i in $(seq 1 $ITERATIONS); do
    echo "$INPUT" | ./symfit --plugin /tmp/minimal_plugin.js $BINARY > /dev/null 2>&1
done

# Test 3: With full plugin
echo -e "\n=== With Full Plugin ==="
time for i in $(seq 1 $ITERATIONS); do
    echo "$INPUT" | ./symfit --plugin /tmp/test4_maze_solver.js $BINARY > /dev/null 2>&1
done
```

**Run**:
```bash
chmod +x /tmp/test5_benchmark.sh
/tmp/test5_benchmark.sh
```

**Expected**:
- Minimal plugin overhead: < 5%
- Full plugin overhead: < 15%
- If overhead > 20%, investigate bottlenecks

---

## Test 6: Error Handling

**Goal**: Verify plugin errors are handled gracefully

**Bad Plugin 1**: Syntax error

```bash
echo "this is not valid javascript {{{" > /tmp/bad_plugin1.js
./symfit --plugin /tmp/bad_plugin1.js /tmp/maze_test/maze-nosleep <<< "d"
# Expected: Error message, program continues without plugin
```

**Bad Plugin 2**: Runtime error

```javascript
globalThis.plugin = {
    onMemoryWrite(addr, size, value) {
        throw new Error("Intentional error!");
    },
    scoreExecution() { return 1.0; }
};
```

```bash
echo '...' > /tmp/bad_plugin2.js  # (use code above)
./symfit --plugin /tmp/bad_plugin2.js /tmp/maze_test/maze-nosleep <<< "d"
# Expected: Error logged, execution continues
```

**Bad Plugin 3**: Missing required callbacks

```javascript
globalThis.plugin = {
    // Missing scoreExecution and getStateHash
};
```

```bash
echo '...' > /tmp/bad_plugin3.js
./symfit --plugin /tmp/bad_plugin3.js /tmp/maze_test/maze-nosleep <<< "d"
# Expected: Warning about missing callbacks, defaults used
```

---

## Test 7: Complex State Tracking

**Goal**: Track complex program state (multiple variables)

**Plugin**: `/tmp/test7_complex_state.js`

```javascript
globalThis.plugin = {
    name: "Complex State Tracker",

    state: {
        variables: new Map(),  // addr -> [values]
        writeSequence: [],     // Ordered list of writes
    },

    onMemoryWrite(addr, size, value) {
        const addrStr = addr.toString();

        // Track all values for this address
        if (!this.state.variables.has(addrStr)) {
            this.state.variables.set(addrStr, []);
        }
        this.state.variables.get(addrStr).push(value);

        // Track write sequence
        this.state.writeSequence.push({
            addr: addr,
            value: value,
            timestamp: this.state.writeSequence.length
        });
    },

    getStateHash(ctx) {
        // Hash = combination of all tracked variables
        let hash = 0n;
        for (const [addr, values] of this.state.variables) {
            const lastValue = values[values.length - 1];
            hash ^= (BigInt(addr) * BigInt(lastValue));
        }
        return hash;
    },

    scoreExecution(ctx) {
        // More unique variable states = higher score
        let uniqueStates = 0;
        for (const [addr, values] of this.state.variables) {
            const unique = new Set(values);
            uniqueStates += unique.size;
        }
        return uniqueStates * 10.0;
    },

    onFini() {
        console.log(`[Plugin] Tracked ${this.state.variables.size} variables`);
        console.log(`[Plugin] Total writes: ${this.state.writeSequence.length}`);

        // Show write patterns
        console.log("[Plugin] Write patterns:");
        for (const [addr, values] of this.state.variables) {
            console.log(`  0x${BigInt(addr).toString(16)}: [${values.slice(0, 10).join(', ')}...]`);
        }
    }
};
```

---

## Test 8: LLM Workflow Simulation

**Goal**: Simulate how an LLM would iteratively improve a plugin

**Iteration 1**: Basic plugin

```javascript
// LLM writes initial version
globalThis.plugin = {
    scoreExecution() { return 1.0; },
    getStateHash() { return 0n; }
};
```

**Run**: Campaign finds no solution

**Iteration 2**: LLM adds position tracking

```javascript
globalThis.plugin = {
    state: { playerXAddr: null, playerYAddr: null },

    onMemoryWrite(addr, size, value) {
        if (!this.state.playerXAddr && value === 1) {
            this.state.playerXAddr = addr;
        }
    },

    getStateHash() {
        return this.state.playerXAddr || 0n;
    },

    scoreExecution() { return 100.0; }
};
```

**Run**: Better, but still not finding solution

**Iteration 3**: LLM adds distance-based scoring

```javascript
globalThis.plugin = {
    // ... (full implementation like test4)
};
```

**Run**: Finds solution!

**Total time**: ~5-10 minutes from problem to solution

---

## Debugging Tips

### Enable Debug Logging

```bash
export SYMFIT_PLUGIN_DEBUG=1
./symfit --plugin plugin.js binary
```

### Check Plugin is Loaded

```bash
./symfit --plugin plugin.js binary 2>&1 | grep "Plugin loaded"
# Should see: "Plugin loaded successfully"
```

### Test Plugin Standalone

```bash
cd /home/heng/git/symfit/plugins-prototype
./test/test_plugin --plugin /tmp/myplugin.js --moves "test"
```

### Verify Callbacks Fire

Add console.log to each callback:

```javascript
globalThis.plugin = {
    onInit() { console.log("onInit called"); },
    onMemoryWrite() { console.log("onMemoryWrite called"); },
    // ...
};
```

### Check JavaScript Errors

Look for QuickJS error messages in stderr:

```bash
./symfit --plugin plugin.js binary 2>&1 | grep -i "error"
```

---

## Success Criteria

✅ **All tests pass**
✅ **Plugin overhead < 15%**
✅ **Campaign with plugin finds maze solution**
✅ **Win detection works reliably**
✅ **No memory leaks (valgrind clean)**
✅ **Documentation complete**

When all criteria met → Plugin system ready for production! 🚀
