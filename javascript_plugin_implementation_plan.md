# JavaScript Plugin System for SymFit - Implementation Plan

## Overview

Add JavaScript plugin support to SymFit using QuickJS, enabling LLMs to write instrumentation code that runs during symbolic execution.

**Goal:** LLM writes `maze_plugin.js` → User runs SymFit → Immediate results → Iterate

## Architecture

```
┌──────────────────────────────────────────────────────┐
│            SymFit Core (C/C++ QEMU)                   │
│                                                       │
│  ┌────────────────────────────────────────────────┐ │
│  │         QuickJS Runtime (Embedded)             │ │
│  │                                                 │ │
│  │  ┌──────────────────────────────────────────┐ │ │
│  │  │    User Plugin (maze_plugin.js)          │ │ │
│  │  │                                           │ │ │
│  │  │  export const plugin = {                 │ │ │
│  │  │    onMemoryWrite(addr, size, val) {...}  │ │ │
│  │  │    onSyscall(num, args) {...}            │ │ │
│  │  │    getStateHash(ctx) {...}               │ │ │
│  │  │    scoreExecution(ctx) {...}             │ │ │
│  │  │  }                                        │ │ │
│  │  └──────────────────────────────────────────┘ │ │
│  │                                                 │ │
│  └────────────────────────────────────────────────┘ │
│                      ▲                               │
│                      │ JS callbacks                  │
│  ┌───────────────────┴──────────────────────────┐  │
│  │      SymFit Instrumentation Hooks             │  │
│  │  - Basic block entry                          │  │
│  │  - Memory read/write                          │  │
│  │  - Syscall entry/exit                         │  │
│  │  - Register updates                           │  │
│  └───────────────────────────────────────────────┘  │
│                                                       │
│  ┌───────────────────────────────────────────────┐  │
│  │      Symbolic Execution Engine                 │  │
│  │  - Uses plugin scores for prioritization      │  │
│  │  - Uses plugin state hash for deduplication   │  │
│  │  - Early termination on goal condition        │  │
│  └───────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## JavaScript Plugin API

### Basic Plugin Structure

```javascript
// maze_plugin.js

export const plugin = {
    // Plugin metadata
    name: "Maze Tracker",
    version: "1.0.0",
    description: "Tracks player position in maze games",

    // State (persistent across executions)
    state: {
        visitedPositions: new Set(),
        playerAddr: null,
        goalReached: false
    },

    // === Lifecycle Hooks ===

    /**
     * Called once when plugin is loaded
     */
    onInit() {
        console.log("[Plugin] Maze tracker initialized");
    },

    /**
     * Called at the start of each execution
     */
    onExecutionStart(inputData) {
        console.log(`[Plugin] Starting execution with input: ${inputData}`);
    },

    /**
     * Called at the end of each execution
     */
    onExecutionEnd(ctx) {
        console.log(`[Plugin] Execution ended. Instructions: ${ctx.instructionCount}`);
    },

    // === Instrumentation Hooks ===

    /**
     * Called when a basic block is entered
     * @param {BigInt} pc - Program counter
     * @param {number} size - Basic block size in bytes
     */
    onBasicBlock(pc, size) {
        // Optional: track execution trace
        // console.log(`BB: 0x${pc.toString(16)}`);
    },

    /**
     * Called on memory write
     * @param {BigInt} addr - Memory address
     * @param {number} size - Write size (1, 2, 4, 8 bytes)
     * @param {BigInt} value - Value written
     */
    onMemoryWrite(addr, size, value) {
        // Auto-detect player position variable
        if (size === 4 && value < 100n) {
            // Small integers might be coordinates
            if (!this.state.playerAddr) {
                console.log(`[Plugin] Detected potential position at ${addr.toString(16)}`);
                this.state.playerAddr = addr;
            }
        }
    },

    /**
     * Called on memory read
     * @param {BigInt} addr - Memory address
     * @param {number} size - Read size
     * @param {BigInt} value - Value read
     */
    onMemoryRead(addr, size, value) {
        // Usually not needed, can omit
    },

    /**
     * Called before syscall execution
     * @param {number} syscallNum - Syscall number (e.g., 1 = write)
     * @param {Array<BigInt>} args - Syscall arguments
     */
    onSyscall(syscallNum, args) {
        // Syscall 1 = write
        if (syscallNum === 1) {
            const fd = args[0];
            const bufAddr = args[1];
            const length = args[2];

            // We'll get the actual data in onSyscallReturn
        }
    },

    /**
     * Called after syscall execution
     * @param {number} syscallNum - Syscall number
     * @param {Array<BigInt>} args - Original arguments
     * @param {BigInt} returnValue - Syscall return value
     * @param {Object} data - Additional data (e.g., buffer contents for write)
     */
    onSyscallReturn(syscallNum, args, returnValue, data) {
        // Check write syscall for win condition
        if (syscallNum === 1 && data.buffer) {
            const output = data.buffer.toString();
            if (output.includes("You win")) {
                console.log("[Plugin] 🎉 GOAL REACHED!");
                this.state.goalReached = true;
                return { stopCampaign: true };  // Signal to stop
            }
        }
    },

    // === Decision Hooks ===

    /**
     * Get hash of current program state (for deduplication)
     * @param {Object} ctx - Execution context
     * @returns {BigInt} State hash
     */
    getStateHash(ctx) {
        if (!this.state.playerAddr) {
            return 0n;
        }

        // Read player position from memory
        const pos = ctx.readMemory(this.state.playerAddr, 4);

        // Hash = position value
        return pos;
    },

    /**
     * Score this execution (higher = more interesting)
     * @param {Object} ctx - Execution context
     * @returns {number} Score (0.0 - 10000.0)
     */
    scoreExecution(ctx) {
        let score = 0.0;

        // Huge bonus for winning
        if (this.state.goalReached) {
            return 10000.0;
        }

        // Bonus for new position
        if (this.state.playerAddr) {
            const pos = ctx.readMemory(this.state.playerAddr, 4);
            if (!this.state.visitedPositions.has(pos)) {
                this.state.visitedPositions.add(pos);
                score += 100.0;
                console.log(`[Plugin] New position: ${pos} (total: ${this.state.visitedPositions.size})`);
            }
        }

        // Small bonus for longer executions (exploring deeper)
        score += ctx.instructionCount * 0.001;

        return score;
    },

    /**
     * Check if goal condition is reached
     * @param {Object} ctx - Execution context
     * @returns {boolean} True if goal reached
     */
    isGoalReached(ctx) {
        return this.state.goalReached;
    },

    /**
     * Suggest next inputs to try
     * @param {Uint8Array} currentInput - Current input that led to this state
     * @param {Object} ctx - Execution context
     * @returns {Array<Uint8Array>} Array of suggested inputs
     */
    suggestInputs(currentInput, ctx) {
        // For maze: try extending with each direction
        const suggestions = [];

        // Append each direction
        for (const dir of ['w', 'a', 's', 'd']) {
            const newInput = new Uint8Array(currentInput.length + 1);
            newInput.set(currentInput);
            newInput[currentInput.length] = dir.charCodeAt(0);
            suggestions.push(newInput);
        }

        return suggestions;
    }
};
```

### Context Object API

The `ctx` object passed to plugin functions:

```javascript
const ctx = {
    // Program counter
    pc: 0x400500n,

    // Register values (x86_64)
    regs: {
        rax: 0n, rbx: 0n, rcx: 0n, rdx: 0n,
        rsi: 0n, rdi: 0n, rbp: 0n, rsp: 0n,
        r8: 0n, r9: 0n, r10: 0n, r11: 0n,
        r12: 0n, r13: 0n, r14: 0n, r15: 0n,
        rip: 0n, rflags: 0n
    },

    // Execution statistics
    instructionCount: 12345n,
    basicBlockCount: 456n,

    // Memory access helper
    readMemory(addr, size) {
        // Returns BigInt for sizes 1,2,4,8
        // Returns Uint8Array for larger sizes
    },

    // Get memory region info
    getMemoryRegion(addr) {
        return {
            start: 0x600000n,
            end: 0x601000n,
            permissions: "rw-",
            name: "[heap]"
        };
    },

    // Read string from memory
    readString(addr, maxLength = 256) {
        // Returns string, stops at null terminator
    },

    // Get current input being tested
    getCurrentInput() {
        return new Uint8Array([...]);
    }
};
```

## Implementation Steps

### Phase 1: QuickJS Integration (Week 1)

**File structure:**
```
symfit/
├── include/
│   └── symfit/
│       └── plugin.h          # Plugin interface (C header)
├── plugins/
│   ├── plugin-manager.c      # Plugin loading/management
│   ├── quickjs-bridge.c      # QuickJS<->SymFit bridge
│   └── Makefile
├── external/
│   └── quickjs/              # QuickJS submodule
└── examples/
    └── plugins/
        ├── maze_plugin.js
        ├── trace_plugin.js
        └── syscall_logger.js
```

**Step 1.1: Add QuickJS as dependency**

```bash
# Add QuickJS as git submodule
cd /home/heng/git/symfit
git submodule add https://github.com/bellard/quickjs.git external/quickjs
cd external/quickjs
make
```

**Step 1.2: Create plugin interface (C)**

```c
// include/symfit/plugin.h

#ifndef SYMFIT_PLUGIN_H
#define SYMFIT_PLUGIN_H

#include <stdint.h>
#include <stdbool.h>

// Plugin handle (opaque)
typedef struct SymFitPlugin SymFitPlugin;

// Initialize plugin system
void symfit_plugin_init(void);

// Load JavaScript plugin
SymFitPlugin* symfit_plugin_load(const char *plugin_path);

// Unload plugin
void symfit_plugin_unload(SymFitPlugin *plugin);

// === Instrumentation Callbacks ===

// Called on basic block entry
void symfit_plugin_on_basic_block(SymFitPlugin *plugin,
                                   uint64_t pc, uint32_t size);

// Called on memory write
void symfit_plugin_on_memory_write(SymFitPlugin *plugin,
                                    uint64_t addr, uint32_t size, uint64_t value);

// Called on memory read
void symfit_plugin_on_memory_read(SymFitPlugin *plugin,
                                   uint64_t addr, uint32_t size, uint64_t value);

// Called before syscall
void symfit_plugin_on_syscall(SymFitPlugin *plugin,
                               int num, uint64_t args[6]);

// Called after syscall
// buffer: for read/write syscalls, contains the buffer data
// buffer_len: length of buffer
void symfit_plugin_on_syscall_return(SymFitPlugin *plugin,
                                      int num, uint64_t args[6],
                                      int64_t ret,
                                      const uint8_t *buffer, size_t buffer_len);

// === Decision Callbacks ===

// Get program state hash
uint64_t symfit_plugin_get_state_hash(SymFitPlugin *plugin);

// Score execution
double symfit_plugin_score_execution(SymFitPlugin *plugin);

// Check if goal reached
bool symfit_plugin_is_goal_reached(SymFitPlugin *plugin);

// Suggest next inputs
// Returns number of suggestions, fills suggestions array
int symfit_plugin_suggest_inputs(SymFitPlugin *plugin,
                                  const uint8_t *current_input, size_t input_len,
                                  uint8_t ***suggestions, size_t **suggestion_lens);

#endif // SYMFIT_PLUGIN_H
```

**Step 1.3: Implement QuickJS bridge**

```c
// plugins/quickjs-bridge.c

#include "quickjs.h"
#include "symfit/plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct SymFitPlugin {
    JSRuntime *rt;
    JSContext *ctx;
    JSValue plugin_obj;

    // Cached callback functions
    JSValue on_basic_block_fn;
    JSValue on_memory_write_fn;
    JSValue on_syscall_fn;
    JSValue on_syscall_return_fn;
    JSValue get_state_hash_fn;
    JSValue score_execution_fn;
    JSValue is_goal_reached_fn;
    JSValue suggest_inputs_fn;

    // Context for memory access
    uint64_t current_pc;
    void *cpu_state;  // CPU state for memory reads
};

// Global plugin (for now, single plugin support)
static SymFitPlugin *g_plugin = NULL;

// === Helper: Create context object ===

static JSValue create_context_object(JSContext *ctx, SymFitPlugin *plugin) {
    JSValue obj = JS_NewObject(ctx);

    // Add PC
    JS_SetPropertyStr(ctx, obj, "pc", JS_NewBigUint64(ctx, plugin->current_pc));

    // Add instruction count (would get from QEMU)
    JS_SetPropertyStr(ctx, obj, "instructionCount", JS_NewBigUint64(ctx, 12345));

    // Add readMemory helper
    JSValue read_memory_fn = JS_NewCFunction(ctx, js_read_memory, "readMemory", 2);
    JS_SetPropertyStr(ctx, obj, "readMemory", read_memory_fn);

    return obj;
}

// === JavaScript Native Functions ===

static JSValue js_read_memory(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    if (argc < 2) return JS_UNDEFINED;

    uint64_t addr;
    uint32_t size;

    JS_ToBigUint64(ctx, &addr, argv[0]);
    JS_ToUint32(ctx, &size, argv[1]);

    // Read from QEMU memory (would call actual QEMU function)
    uint64_t value = 0;  // Placeholder
    // value = cpu_ldq_data(g_plugin->cpu_state, addr);

    return JS_NewBigUint64(ctx, value);
}

static JSValue js_console_log(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; i++) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            printf("%s%s", i > 0 ? " " : "", str);
            JS_FreeCString(ctx, str);
        }
    }
    printf("\n");
    return JS_UNDEFINED;
}

// === Plugin Loading ===

SymFitPlugin* symfit_plugin_load(const char *plugin_path) {
    SymFitPlugin *plugin = calloc(1, sizeof(SymFitPlugin));

    // Create QuickJS runtime
    plugin->rt = JS_NewRuntime();
    if (!plugin->rt) {
        fprintf(stderr, "Failed to create JS runtime\n");
        free(plugin);
        return NULL;
    }

    plugin->ctx = JS_NewContext(plugin->rt);
    if (!plugin->ctx) {
        fprintf(stderr, "Failed to create JS context\n");
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    // Add console.log
    JSValue global = JS_GetGlobalObject(plugin->ctx);
    JSValue console = JS_NewObject(plugin->ctx);
    JS_SetPropertyStr(plugin->ctx, console, "log",
                     JS_NewCFunction(plugin->ctx, js_console_log, "log", 1));
    JS_SetPropertyStr(plugin->ctx, global, "console", console);
    JS_FreeValue(plugin->ctx, global);

    // Read plugin file
    FILE *f = fopen(plugin_path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open plugin: %s\n", plugin_path);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *code = malloc(size + 1);
    fread(code, 1, size, f);
    code[size] = '\0';
    fclose(f);

    // Evaluate plugin code
    JSValue result = JS_Eval(plugin->ctx, code, size, plugin_path,
                            JS_EVAL_TYPE_MODULE);
    free(code);

    if (JS_IsException(result)) {
        js_std_dump_error(plugin->ctx);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    // Get plugin object
    global = JS_GetGlobalObject(plugin->ctx);
    plugin->plugin_obj = JS_GetPropertyStr(plugin->ctx, global, "plugin");
    JS_FreeValue(plugin->ctx, global);

    if (!JS_IsObject(plugin->plugin_obj)) {
        fprintf(stderr, "Plugin must export 'plugin' object\n");
        JS_FreeValue(plugin->ctx, result);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    // Cache callback functions
    plugin->on_memory_write_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onMemoryWrite");
    plugin->on_syscall_return_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onSyscallReturn");
    plugin->get_state_hash_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "getStateHash");
    plugin->score_execution_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "scoreExecution");
    plugin->is_goal_reached_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "isGoalReached");

    // Call onInit if present
    JSValue on_init = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onInit");
    if (JS_IsFunction(plugin->ctx, on_init)) {
        JS_Call(plugin->ctx, on_init, plugin->plugin_obj, 0, NULL);
    }
    JS_FreeValue(plugin->ctx, on_init);

    JS_FreeValue(plugin->ctx, result);

    g_plugin = plugin;
    printf("[SymFit] Plugin loaded: %s\n", plugin_path);

    return plugin;
}

// === Callback Implementations ===

void symfit_plugin_on_memory_write(SymFitPlugin *plugin,
                                    uint64_t addr, uint32_t size, uint64_t value) {
    if (!JS_IsFunction(plugin->ctx, plugin->on_memory_write_fn)) {
        return;
    }

    JSValue args[3] = {
        JS_NewBigUint64(plugin->ctx, addr),
        JS_NewUint32(plugin->ctx, size),
        JS_NewBigUint64(plugin->ctx, value)
    };

    JSValue result = JS_Call(plugin->ctx, plugin->on_memory_write_fn,
                             plugin->plugin_obj, 3, args);

    // Check for errors
    if (JS_IsException(result)) {
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, args[0]);
    JS_FreeValue(plugin->ctx, args[1]);
    JS_FreeValue(plugin->ctx, args[2]);
}

uint64_t symfit_plugin_get_state_hash(SymFitPlugin *plugin) {
    if (!JS_IsFunction(plugin->ctx, plugin->get_state_hash_fn)) {
        return 0;
    }

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue args[1] = { ctx_obj };

    JSValue result = JS_Call(plugin->ctx, plugin->get_state_hash_fn,
                             plugin->plugin_obj, 1, args);

    uint64_t hash = 0;
    if (!JS_IsException(result)) {
        JS_ToBigUint64(plugin->ctx, &hash, result);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);

    return hash;
}

double symfit_plugin_score_execution(SymFitPlugin *plugin) {
    if (!JS_IsFunction(plugin->ctx, plugin->score_execution_fn)) {
        return 1.0;
    }

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue args[1] = { ctx_obj };

    JSValue result = JS_Call(plugin->ctx, plugin->score_execution_fn,
                             plugin->plugin_obj, 1, args);

    double score = 1.0;
    if (!JS_IsException(result)) {
        JS_ToFloat64(plugin->ctx, &score, result);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);

    return score;
}

void symfit_plugin_unload(SymFitPlugin *plugin) {
    if (!plugin) return;

    // Call onFini if present
    JSValue on_fini = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onFini");
    if (JS_IsFunction(plugin->ctx, on_fini)) {
        JS_Call(plugin->ctx, on_fini, plugin->plugin_obj, 0, NULL);
    }
    JS_FreeValue(plugin->ctx, on_fini);

    // Free all cached functions
    JS_FreeValue(plugin->ctx, plugin->on_memory_write_fn);
    JS_FreeValue(plugin->ctx, plugin->score_execution_fn);
    // ... free others

    JS_FreeValue(plugin->ctx, plugin->plugin_obj);
    JS_FreeContext(plugin->ctx);
    JS_FreeRuntime(plugin->rt);
    free(plugin);

    if (g_plugin == plugin) {
        g_plugin = NULL;
    }
}
```

### Phase 2: QEMU Integration (Week 2)

**Step 2.1: Add hooks in TCG (Tiny Code Generator)**

```c
// accel/tcg/translator.c

#include "symfit/plugin.h"

// In tb_gen_code() - called for each basic block
void tb_gen_code(CPUState *cpu, TranslationBlock *tb) {
    // ... existing code ...

    // Call plugin hook
    if (g_symfit_plugin) {
        symfit_plugin_on_basic_block(g_symfit_plugin, tb->pc, tb->size);
    }

    // ... rest of code ...
}
```

**Step 2.2: Add memory access hooks**

```c
// accel/tcg/cputlb.c

// In store helper functions
void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr,
                        uint8_t val, MemOpIdx oi, uintptr_t retaddr) {
    // ... existing store code ...

    // Call plugin
    if (g_symfit_plugin) {
        symfit_plugin_on_memory_write(g_symfit_plugin, addr, 1, val);
    }
}

// Similar for stw, stl, stq (2, 4, 8 byte stores)
```

**Step 2.3: Add syscall hooks**

```c
// linux-user/syscall.c

long do_syscall(void *cpu_env, int num, ...) {
    uint64_t args[6];

    // ... extract arguments ...

    // Call plugin before syscall
    if (g_symfit_plugin) {
        symfit_plugin_on_syscall(g_symfit_plugin, num, args);
    }

    // Execute syscall
    long ret = actual_syscall(num, args);

    // For write syscall, pass buffer to plugin
    if (num == SYS_write && g_symfit_plugin) {
        uint8_t *buf = lock_user(VERIFY_READ, args[1], args[2], 1);
        symfit_plugin_on_syscall_return(g_symfit_plugin, num, args, ret,
                                        buf, args[2]);
        unlock_user(buf, args[1], 0);
    } else if (g_symfit_plugin) {
        symfit_plugin_on_syscall_return(g_symfit_plugin, num, args, ret,
                                        NULL, 0);
    }

    return ret;
}
```

### Phase 3: Integration with Symbolic Execution (Week 2-3)

**Step 3.1: Use plugin scores for test case prioritization**

```c
// In SymFit's test case selection logic

typedef struct TestCase {
    uint8_t *input;
    size_t input_len;
    double score;      // NEW: plugin score
    uint64_t state_hash;  // NEW: plugin state hash
} TestCase;

// Score test case using plugin
void score_test_case(TestCase *tc) {
    // Run execution with this input
    run_symbolic_execution(tc->input, tc->input_len);

    // Get score from plugin
    if (g_symfit_plugin) {
        tc->score = symfit_plugin_score_execution(g_symfit_plugin);
        tc->state_hash = symfit_plugin_get_state_hash(g_symfit_plugin);
    } else {
        tc->score = tc->coverage;  // Fallback to coverage
        tc->state_hash = 0;
    }
}

// Sort test cases by score
int compare_test_cases(const void *a, const void *b) {
    TestCase *tc_a = (TestCase*)a;
    TestCase *tc_b = (TestCase*)b;

    // Higher score = better
    if (tc_a->score > tc_b->score) return -1;
    if (tc_a->score < tc_b->score) return 1;
    return 0;
}

// Main campaign loop
void run_campaign(const char *binary, const char *corpus) {
    for (int round = 0; round < MAX_ROUNDS; round++) {
        TestCase *cases = load_corpus(corpus);
        int num_cases = get_num_cases();

        // Score all test cases
        for (int i = 0; i < num_cases; i++) {
            score_test_case(&cases[i]);
        }

        // Sort by score
        qsort(cases, num_cases, sizeof(TestCase), compare_test_cases);

        // Process highest scored cases first
        for (int i = 0; i < num_cases; i++) {
            run_symbolic_execution(cases[i].input, cases[i].input_len);

            // Check if goal reached
            if (g_symfit_plugin && symfit_plugin_is_goal_reached(g_symfit_plugin)) {
                printf("Goal reached! Stopping campaign.\n");
                return;
            }
        }
    }
}
```

**Step 3.2: Use plugin state hash for deduplication**

```c
// Deduplicate test cases by plugin state hash
bool is_duplicate_state(TestCase *tc, TestCase *existing[], int num_existing) {
    if (!g_symfit_plugin) {
        return false;  // No plugin, can't deduplicate
    }

    uint64_t hash = tc->state_hash;

    for (int i = 0; i < num_existing; i++) {
        if (existing[i]->state_hash == hash) {
            return true;  // Duplicate state
        }
    }

    return false;
}
```

### Phase 4: MCP Server Integration (Week 3)

**Step 4.1: Add plugin parameter to MCP tools**

```javascript
// mcp-server/index.js

// Add plugin_file parameter to run_campaign tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "run_campaign") {
    const {
      binary_path,
      corpus_dir,
      plugin_file,  // NEW
      max_rounds = 10,
      timeout = 5000,
      // ...
    } = args;

    // Build command with plugin
    const symqemuArgs = [];

    if (plugin_file) {
      symqemuArgs.push('--plugin', plugin_file);
    }

    // ... rest of campaign logic
  }
});
```

**Step 4.2: Pass plugin option to SymFit**

```bash
# Command line usage
symqemu-x86_64 --plugin maze_plugin.js /tmp/maze_test/maze-nosleep

# Environment variable (alternative)
export SYMFIT_PLUGIN=maze_plugin.js
symqemu-x86_64 /tmp/maze_test/maze-nosleep
```

## Example Plugins

### Example 1: Minimal Plugin

```javascript
// minimal_plugin.js
export const plugin = {
    onMemoryWrite(addr, size, value) {
        console.log(`Write: ${addr.toString(16)} = ${value}`);
    }
};
```

### Example 2: Execution Tracer

```javascript
// trace_plugin.js
export const plugin = {
    state: {
        trace: []
    },

    onBasicBlock(pc, size) {
        this.state.trace.push(pc);

        // Limit trace size
        if (this.state.trace.length > 1000) {
            this.state.trace.shift();
        }
    },

    onExecutionEnd(ctx) {
        console.log(`Execution trace (${this.state.trace.length} blocks):`);
        for (const pc of this.state.trace.slice(-10)) {
            console.log(`  0x${pc.toString(16)}`);
        }
    }
};
```

### Example 3: Syscall Logger

```javascript
// syscall_logger.js
export const plugin = {
    onSyscallReturn(num, args, ret, data) {
        const syscallNames = {
            0: 'read',
            1: 'write',
            2: 'open',
            3: 'close',
            // ... more
        };

        const name = syscallNames[num] || `sys_${num}`;
        console.log(`[Syscall] ${name}(...) = ${ret}`);

        if (num === 1 && data.buffer) {
            console.log(`  Output: ${data.buffer.toString().slice(0, 100)}`);
        }
    }
};
```

### Example 4: Complete Maze Plugin

```javascript
// Complete maze_plugin.js (as shown in API section above)
```

## Testing Plan

### Unit Tests

```javascript
// test/plugin_basic.js
export const plugin = {
    onInit() {
        console.log("TEST: onInit called");
    },

    scoreExecution(ctx) {
        console.log("TEST: scoreExecution called");
        return 42.0;
    }
};

// Test: Load plugin, verify score returned
```

### Integration Tests

```bash
# Test 1: Basic plugin loading
./symqemu-x86_64 --plugin test/plugin_basic.js /bin/echo "hello"

# Test 2: Memory tracking
./symqemu-x86_64 --plugin test/plugin_memory.js /tmp/test_binary

# Test 3: Maze solving
./run_campaign.sh --binary /tmp/maze --plugin examples/maze_plugin.js
```

## Build System Changes

### Makefile modifications

```makefile
# Add QuickJS to build
QUICKJS_DIR = $(SRC_PATH)/external/quickjs
QUICKJS_LIB = $(QUICKJS_DIR)/libquickjs.a

$(QUICKJS_LIB):
	$(MAKE) -C $(QUICKJS_DIR)

# Add plugin library
PLUGIN_OBJS = plugins/plugin-manager.o plugins/quickjs-bridge.o
libsymfit-plugin.a: $(PLUGIN_OBJS) $(QUICKJS_LIB)
	$(AR) rcs $@ $^

# Link with main binary
symqemu-x86_64: ... libsymfit-plugin.a
	$(CC) -o $@ $^ $(LIBS)
```

## Documentation

### User Guide

```markdown
# SymFit JavaScript Plugins

## Quick Start

1. Create a plugin file:

```javascript
// my_plugin.js
export const plugin = {
    scoreExecution(ctx) {
        return Math.random() * 100;
    }
};
```

2. Run with SymFit:

```bash
symqemu-x86_64 --plugin my_plugin.js /path/to/binary
```

## API Reference

See full API documentation in `docs/plugin-api.md`
```

## Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| 1 | QuickJS integration, basic plugin loading | Load & execute JS plugins |
| 2 | QEMU hooks, callback implementation | Memory/syscall hooks working |
| 3 | Symbolic execution integration, MCP server | Full integration, can run campaigns |
| 4 | Testing, documentation, examples | Production-ready |

## Success Criteria

✅ LLM writes `maze_plugin.js`
✅ User runs: `symfit --plugin maze_plugin.js /tmp/maze`
✅ Plugin tracks position, scores executions
✅ Campaign finds solution in < 5 minutes
✅ No compilation required
✅ Clear error messages when plugin has bugs

## Next Steps

1. **Create QuickJS integration PR**
   - Add QuickJS submodule
   - Implement plugin loading
   - Add basic hooks

2. **Test with LLM workflow**
   - Have LLM write plugins
   - Iterate on API based on feedback

3. **Expand hook coverage**
   - Add more instrumentation points
   - Performance optimization

Ready to start implementation?
