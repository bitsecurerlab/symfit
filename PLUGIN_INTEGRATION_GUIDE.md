# SymFit Plugin System Integration Guide

## Overview

This guide shows how to integrate the JavaScript plugin system (prototype in `plugins-prototype/`) into the main SymFit symbolic execution engine.

**Timeline**: 3-4 weeks for complete integration
**Complexity**: Moderate - requires QEMU internals knowledge
**Benefit**: Enables LLM-driven custom symbolic execution strategies

---

## Phase 1: Build System Integration (2-3 days)

### Step 1.1: Add Plugin Source Files

Copy the plugin implementation into SymFit's source tree:

```bash
cd /home/heng/git/symfit

# Create plugin directory
mkdir -p plugin-system

# Copy implementation
cp plugins-prototype/include/symfit_plugin.h plugin-system/
cp plugins-prototype/src/symfit_plugin.c plugin-system/

# Update paths in symfit_plugin.c to use external/quickjs
```

### Step 1.2: Update SymFit's Build System

**File: `meson.build` (or main Makefile)**

```meson
# Add QuickJS dependency
quickjs_dep = dependency('quickjs', required: false)

if not quickjs_dep.found()
  # Build QuickJS from submodule
  quickjs_proj = subproject('quickjs')
  quickjs_dep = quickjs_proj.get_variable('quickjs_dep')
endif

# Add plugin system library
plugin_sources = files(
  'plugin-system/symfit_plugin.c',
)

libsymfit_plugin = static_library('symfit_plugin',
  plugin_sources,
  dependencies: [quickjs_dep],
  include_directories: include_directories('plugin-system')
)

symfit_plugin_dep = declare_dependency(
  link_with: libsymfit_plugin,
  include_directories: include_directories('plugin-system'),
  dependencies: [quickjs_dep]
)

# Add to main SymFit build
symfit_deps += [symfit_plugin_dep]
```

### Step 1.3: Verify Build

```bash
cd /home/heng/git/symfit
meson setup builddir
meson compile -C builddir
```

**Expected**: Clean build with plugin system included

---

## Phase 2: QEMU Hook Integration (1 week)

### Step 2.1: Add Global Plugin State

**File: `accel/tcg/tcg-runtime.h`** (or appropriate header)

```c
#include "symfit_plugin.h"

// Global plugin instance
extern SymFitPlugin *g_symfit_plugin;

// Plugin initialization
void symfit_plugin_global_init(const char *plugin_path);
void symfit_plugin_global_shutdown(void);
```

**File: `accel/tcg/tcg-runtime.c`**

```c
#include "symfit_plugin.h"

SymFitPlugin *g_symfit_plugin = NULL;

void symfit_plugin_global_init(const char *plugin_path) {
    if (!plugin_path) return;

    symfit_plugin_init();
    g_symfit_plugin = symfit_plugin_load(plugin_path);

    if (!g_symfit_plugin) {
        fprintf(stderr, "Failed to load plugin: %s\n", plugin_path);
    }
}

void symfit_plugin_global_shutdown(void) {
    if (g_symfit_plugin) {
        symfit_plugin_unload(g_symfit_plugin);
        g_symfit_plugin = NULL;
    }
    symfit_plugin_shutdown();
}
```

### Step 2.2: Add Memory Write Hooks

**File: `accel/tcg/cputlb.c`** (memory store operations)

Add instrumentation to all store helpers:

```c
// Example: helper_ret_stb_mmu (1-byte store)
void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr,
                        uint8_t val, MemOpIdx oi, uintptr_t retaddr)
{
    // ... existing store code ...

    // Plugin hook AFTER successful write
    if (g_symfit_plugin) {
        symfit_plugin_on_memory_write(g_symfit_plugin, addr, 1, val);
    }
}

// Repeat for:
// - helper_ret_stw_mmu (2-byte store)
// - helper_ret_stl_mmu (4-byte store)
// - helper_ret_stq_mmu (8-byte store)
```

**Key locations** in `accel/tcg/cputlb.c`:
- Around line 2000: `store_helper()` or `store_memop()`
- All `helper_*_st*_mmu` functions

### Step 2.3: Add Memory Read Hooks (Optional)

If plugin needs read tracking:

```c
// In helper_ret_ldub_mmu, etc.
void helper_ret_ldub_mmu(CPUArchState *env, target_ulong addr,
                         MemOpIdx oi, uintptr_t retaddr)
{
    uint8_t val = /* ... existing load code ... */;

    // Plugin hook AFTER successful read
    if (g_symfit_plugin) {
        symfit_plugin_on_memory_read(g_symfit_plugin, addr, 1, val);
    }

    return val;
}
```

### Step 2.4: Add Syscall Hooks

**File: `linux-user/syscall.c`** (for Linux user-mode emulation)

```c
#include "symfit_plugin.h"
extern SymFitPlugin *g_symfit_plugin;

abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                    abi_long arg2, abi_long arg3, abi_long arg4,
                    abi_long arg5, abi_long arg6, abi_long arg7,
                    abi_long arg8)
{
    // ... existing syscall dispatch ...

    abi_long ret = /* syscall execution */;

    // Plugin hook for write syscall (num == TARGET_NR_write)
    if (g_symfit_plugin && num == TARGET_NR_write) {
        uint64_t args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};

        // Capture write buffer
        void *buf = lock_user(VERIFY_READ, arg2, arg3, 1);
        if (buf) {
            symfit_plugin_on_syscall_return(g_symfit_plugin, num, args,
                                           ret, buf, arg3);
            unlock_user(buf, arg2, 0);
        }
    }

    return ret;
}
```

**Key syscalls to instrument**:
- `write` (1) - Program output
- `read` (0) - Program input (optional)
- `open` (2) - File access (optional)

### Step 2.5: Add Basic Block Hooks (Optional)

For instruction-level tracking:

**File: `accel/tcg/translator.c`**

```c
// In translator_loop() or gen_intermediate_code()
void translator_loop(const TranslatorOps *ops, DisasContextBase *db,
                     CPUState *cpu, TranslationBlock *tb, int max_insns)
{
    // ... existing translation ...

    // Plugin hook at basic block start
    if (g_symfit_plugin) {
        symfit_plugin_set_context(g_symfit_plugin, db->pc_first, cpu);
    }

    // ... continue translation ...
}
```

---

## Phase 3: Symbolic Execution Integration (3-4 days)

### Step 3.1: Add Plugin Support to Campaign Loop

**File: `symfit_campaign.c` (or equivalent)**

```c
#include "symfit_plugin.h"

typedef struct TestCase {
    uint8_t *data;
    size_t len;
    double score;       // NEW: Plugin-assigned score
    uint64_t state_hash; // NEW: Plugin state hash
} TestCase;

void run_campaign(const char *binary, const char *corpus_dir,
                  const char *plugin_path, int max_rounds) {

    // Initialize plugin
    if (plugin_path) {
        symfit_plugin_global_init(plugin_path);
    }

    for (int round = 0; round < max_rounds; round++) {
        TestCase *cases = load_corpus(corpus_dir);
        int num_cases = count_corpus(corpus_dir);

        // Execute each test case
        for (int i = 0; i < num_cases; i++) {
            // Run symbolic execution
            run_symbolic_execution(binary, cases[i].data, cases[i].len);

            // Get plugin evaluation
            if (g_symfit_plugin) {
                cases[i].score = symfit_plugin_score_execution(g_symfit_plugin);
                cases[i].state_hash = symfit_plugin_get_state_hash(g_symfit_plugin);

                // Check early termination
                if (symfit_plugin_is_goal_reached(g_symfit_plugin)) {
                    printf("Plugin goal reached! Stopping campaign.\n");
                    goto cleanup;
                }
            } else {
                cases[i].score = calculate_edge_coverage(cases[i]);
            }
        }

        // Sort by score (highest first)
        qsort(cases, num_cases, sizeof(TestCase), compare_by_score);

        // Generate new test cases from top scorers
        generate_new_cases(cases, num_cases, corpus_dir);

        free_test_cases(cases, num_cases);
    }

cleanup:
    if (plugin_path) {
        symfit_plugin_global_shutdown();
    }
}

int compare_by_score(const void *a, const void *b) {
    const TestCase *ta = a;
    const TestCase *tb = b;
    if (ta->score > tb->score) return -1;
    if (ta->score < tb->score) return 1;
    return 0;
}
```

### Step 3.2: Add Command-Line Option

**File: `symfit_main.c`**

```c
static const QemuOptsList qemu_symfit_opts = {
    .name = "symfit",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_symfit_opts.head),
    .desc = {
        {
            .name = "plugin",
            .type = QEMU_OPT_STRING,
            .help = "JavaScript plugin file for custom instrumentation",
        },
        // ... other options ...
    },
};

int main(int argc, char **argv) {
    // ... option parsing ...

    const char *plugin_path = qemu_opt_get(opts, "plugin");
    if (plugin_path) {
        symfit_plugin_global_init(plugin_path);
    }

    // ... rest of main ...
}
```

### Step 3.3: Add State-Based Deduplication

**File: `symfit_corpus.c`**

```c
// Use plugin state hash for deduplication instead of edge coverage

bool is_duplicate_state(const char *corpus_dir, uint64_t state_hash) {
    char hash_file[256];
    snprintf(hash_file, sizeof(hash_file), "%s/.state_hashes", corpus_dir);

    FILE *f = fopen(hash_file, "r");
    if (!f) return false;

    uint64_t existing_hash;
    while (fread(&existing_hash, sizeof(existing_hash), 1, f) == 1) {
        if (existing_hash == state_hash) {
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

void add_test_case_with_state(const char *corpus_dir, const uint8_t *data,
                               size_t len, uint64_t state_hash) {
    // Check if state is new
    if (is_duplicate_state(corpus_dir, state_hash)) {
        return; // Skip duplicate
    }

    // Add to corpus
    add_to_corpus(corpus_dir, data, len);

    // Record state hash
    char hash_file[256];
    snprintf(hash_file, sizeof(hash_file), "%s/.state_hashes", corpus_dir);
    FILE *f = fopen(hash_file, "a");
    if (f) {
        fwrite(&state_hash, sizeof(state_hash), 1, f);
        fclose(f);
    }
}
```

---

## Phase 4: MCP Server Integration (2 days)

### Step 4.1: Add Plugin Parameter to Tools

**File: `mcp-server/index.js`**

```javascript
// Update run_campaign tool definition
{
  name: "run_campaign",
  description: "Run iterative symbolic execution campaign",
  inputSchema: {
    type: "object",
    properties: {
      binary_path: {
        type: "string",
        description: "Path to target binary"
      },
      corpus_dir: {
        type: "string",
        description: "Path to corpus directory"
      },
      plugin_file: {
        type: "string",
        description: "Path to JavaScript plugin (optional)"
      },
      // ... other parameters ...
    },
    required: ["binary_path", "corpus_dir"]
  }
}
```

### Step 4.2: Pass Plugin to SymFit

```javascript
async function runCampaign(params) {
  const { binary_path, corpus_dir, plugin_file, max_rounds, timeout } = params;

  const args = [
    '--symfit-mode', 'campaign',
    '--binary', binary_path,
    '--corpus', corpus_dir,
  ];

  // Add plugin if specified
  if (plugin_file) {
    args.push('--plugin', plugin_file);
  }

  if (max_rounds) {
    args.push('--max-rounds', max_rounds.toString());
  }

  // Execute SymFit
  const result = await executeSymFit(args, timeout);
  return result;
}
```

### Step 4.3: Add Plugin Management Tools

```javascript
// Tool: write_plugin
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "write_plugin") {
    const { plugin_path, plugin_code } = request.params.arguments;

    // Write plugin file
    await fs.promises.writeFile(plugin_path, plugin_code, 'utf-8');

    // Validate plugin syntax
    try {
      new Function(plugin_code); // Quick syntax check
      return { success: true, message: "Plugin written successfully" };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
});
```

---

## Phase 5: Testing & Documentation (3 days)

### Step 5.1: Integration Tests

**File: `tests/plugin-integration/test_maze.sh`**

```bash
#!/bin/bash

# Test 1: Run maze with plugin
echo "=== Test 1: Maze with Plugin ==="

# Write plugin
cat > /tmp/maze_plugin.js << 'EOF'
globalThis.plugin = {
    state: { playerXAddr: null, playerYAddr: null },

    onMemoryWrite(addr, size, value) {
        if (!this.state.playerXAddr && value === 1) {
            this.state.playerXAddr = addr;
        } else if (!this.state.playerYAddr && value === 1) {
            this.state.playerYAddr = addr;
        }
    },

    getStateHash(ctx) {
        if (!this.state.playerXAddr) return 0n;
        const x = ctx.readMemory(this.state.playerXAddr, 4);
        const y = this.state.playerYAddr ?
                  ctx.readMemory(this.state.playerYAddr, 4) : 0n;
        return (x << 32n) | y;
    },

    scoreExecution(ctx) {
        // Higher score for positions closer to (5,5)
        const x = ctx.readMemory(this.state.playerXAddr, 4);
        const y = this.state.playerYAddr ?
                  ctx.readMemory(this.state.playerYAddr, 4) : 0n;
        const dist = Math.abs(Number(x) - 5) + Math.abs(Number(y) - 5);
        return 1000.0 - dist * 10.0;
    }
};
EOF

# Run campaign
./build/symfit-qemu-x86_64 \
    --plugin /tmp/maze_plugin.js \
    --symfit-campaign \
    --corpus /tmp/maze-corpus \
    --max-rounds 10 \
    /tmp/maze_test/maze-nosleep

# Check results
if [ -f /tmp/maze-corpus/winning_input ]; then
    echo "SUCCESS: Plugin found solution!"
    exit 0
else
    echo "FAILED: No solution found"
    exit 1
fi
```

### Step 5.2: Performance Testing

```bash
# Test overhead
time ./symfit --plugin plugin.js binary  # With plugin
time ./symfit binary                      # Without plugin

# Expected: < 10% overhead
```

### Step 5.3: Documentation

Create user documentation:

**File: `docs/PLUGIN_GUIDE.md`**

```markdown
# SymFit Plugin Guide

## Quick Start

1. Write a plugin:

```javascript
globalThis.plugin = {
    onMemoryWrite(addr, size, value) {
        console.log(`Write: ${addr.toString(16)} = ${value}`);
    },

    scoreExecution(ctx) {
        return 100.0; // Your custom score
    }
};
```

2. Run SymFit with plugin:

```bash
./symfit --plugin myplugin.js --corpus ./corpus target_binary
```

## API Reference

See PLUGIN_API.md for complete API documentation.
```

---

## Phase 6: Advanced Features (Optional, 1 week)

### 6.1: Multi-Plugin Support

Allow loading multiple plugins:

```c
SymFitPlugin *g_symfit_plugins[MAX_PLUGINS];
int g_num_plugins = 0;

void symfit_load_multiple_plugins(const char **paths, int count) {
    for (int i = 0; i < count && i < MAX_PLUGINS; i++) {
        g_symfit_plugins[i] = symfit_plugin_load(paths[i]);
        if (g_symfit_plugins[i]) g_num_plugins++;
    }
}
```

### 6.2: Plugin Hot Reload

```c
void symfit_plugin_reload(SymFitPlugin **plugin, const char *path) {
    // Preserve state
    JSValue saved_state = JS_GetPropertyStr((*plugin)->ctx,
                                            (*plugin)->plugin_obj, "state");

    // Reload
    symfit_plugin_unload(*plugin);
    *plugin = symfit_plugin_load(path);

    // Restore state
    if (*plugin) {
        JS_SetPropertyStr((*plugin)->ctx, (*plugin)->plugin_obj,
                         "state", saved_state);
    }
}
```

### 6.3: Plugin Performance Monitoring

```c
typedef struct {
    uint64_t total_calls;
    uint64_t total_cycles;
    double avg_time_ns;
} PluginStats;

void symfit_plugin_get_stats(SymFitPlugin *plugin, PluginStats *stats) {
    stats->total_calls = plugin->callback_count;
    // ... compute timing stats ...
}
```

---

## Integration Checklist

### Build System
- [ ] QuickJS added as dependency
- [ ] Plugin system compiles
- [ ] Links with main SymFit binary
- [ ] No build warnings

### QEMU Hooks
- [ ] Memory write hooks added
- [ ] Memory read hooks added (optional)
- [ ] Syscall hooks added
- [ ] Basic block hooks added (optional)
- [ ] Hooks tested individually

### Symbolic Execution
- [ ] Plugin scoring integrated
- [ ] State-based deduplication works
- [ ] Early termination on goal works
- [ ] Command-line option added

### MCP Server
- [ ] Plugin parameter added to tools
- [ ] Plugin files can be uploaded
- [ ] Results include plugin scores

### Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Performance acceptable (<10% overhead)
- [ ] Memory leaks checked (valgrind)

### Documentation
- [ ] User guide written
- [ ] API reference complete
- [ ] Example plugins provided
- [ ] Integration guide (this document)

---

## Troubleshooting

### Issue: Plugin doesn't load

**Check**:
1. File path is absolute
2. Plugin syntax is valid JavaScript
3. `globalThis.plugin` is defined
4. QuickJS is built correctly

**Debug**:
```bash
# Test plugin standalone
./plugins-prototype/test/test_plugin --plugin myplugin.js
```

### Issue: Callbacks not firing

**Check**:
1. Global plugin pointer is set
2. Hooks are in correct QEMU functions
3. `JS_IsFunction()` returns true for callback

**Debug**:
```c
fprintf(stderr, "Plugin: %p, callback: %p\n",
        g_symfit_plugin,
        g_symfit_plugin->on_memory_write_fn);
```

### Issue: Performance degradation

**Solutions**:
1. Reduce callback frequency (sample every N calls)
2. Cache JavaScript values
3. Use simpler plugin logic
4. Profile with `perf`

---

## Example: Full Integration Test

```bash
#!/bin/bash
# Full end-to-end test

cd /home/heng/git/symfit

# 1. Build SymFit with plugin support
meson setup builddir -Dplugin_system=enabled
meson compile -C builddir

# 2. Create test plugin
cat > /tmp/test_plugin.js << 'EOF'
globalThis.plugin = {
    state: { writes: 0 },
    onMemoryWrite() { this.state.writes++; },
    scoreExecution() { return this.state.writes; },
    getStateHash() { return BigInt(this.state.writes); }
};
EOF

# 3. Run campaign
./builddir/symfit-qemu-x86_64 \
    --plugin /tmp/test_plugin.js \
    --corpus /tmp/test-corpus \
    --max-rounds 3 \
    /tmp/maze_test/maze-nosleep

# 4. Verify
if grep -q "Plugin loaded successfully" symfit.log; then
    echo "✅ Integration successful!"
else
    echo "❌ Integration failed"
    exit 1
fi
```

---

## Next Steps After Integration

1. **Create Plugin Library**: Collection of useful plugins for common patterns
2. **LLM Integration**: Direct API for Claude to write/test plugins
3. **Plugin Marketplace**: Share plugins with community
4. **Visual Plugin Editor**: Web UI for plugin development
5. **Plugin Composition**: Combine multiple simple plugins

---

## Support

For questions or issues:
- Check `PLUGIN_API.md` for API details
- Review `plugins-prototype/` for working examples
- Test with standalone `test/test_plugin` first
- Enable debug logging: `SYMFIT_DEBUG=1`

**Estimated Total Integration Time**: 3-4 weeks
**Risk Level**: Medium (QEMU internals required)
**Reward**: High (LLM-guided symbolic execution)
