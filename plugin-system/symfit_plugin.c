/**
 * SymFit JavaScript Plugin Implementation
 * Using QuickJS for lightweight embedding
 */

#include "symfit_plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// QuickJS headers (will be available after submodule is added)
// For prototype, we'll include a minimal shim
#ifdef HAVE_QUICKJS
#include "quickjs.h"
#include "quickjs-libc.h"
#else
// Minimal QuickJS shim for compilation without QuickJS
typedef struct JSRuntime JSRuntime;
typedef struct JSContext JSContext;
typedef struct JSValue { uint64_t tag; union { int32_t i; double d; void *p; } u; } JSValue;
#define JS_TAG_INT 0
#define JS_TAG_BOOL 1
#define JS_TAG_FLOAT64 7
#define JS_TAG_OBJECT 8
#define JS_TAG_EXCEPTION 6
#define JS_TAG_UNDEFINED 3
#define JS_UNDEFINED ((JSValue){JS_TAG_UNDEFINED, {.i = 0}})
#define JS_NewRuntime() NULL
#define JS_NewContext(rt) NULL
#define JS_FreeContext(ctx) do {} while(0)
#define JS_FreeRuntime(rt) do {} while(0)
#define JS_FreeValue(ctx, v) do {} while(0)
#define JS_IsException(v) (v.tag == JS_TAG_EXCEPTION)
#define JS_IsFunction(ctx, v) (v.tag == JS_TAG_OBJECT)
#define JS_NewObject(ctx) JS_UNDEFINED
#define JS_NewBigUint64(ctx, val) JS_UNDEFINED
#define JS_NewUint32(ctx, val) JS_UNDEFINED
#define JS_NewFloat64(ctx, val) JS_UNDEFINED
#define JS_ToBigUint64(ctx, ptr, val) 0
#define JS_ToFloat64(ctx, ptr, val) 0
#define JS_NewCFunction(ctx, func, name, len) JS_UNDEFINED
#define JS_GetGlobalObject(ctx) JS_UNDEFINED
#define JS_GetPropertyStr(ctx, obj, name) JS_UNDEFINED
#define JS_SetPropertyStr(ctx, obj, name, val) 0
#define JS_Call(ctx, func, this_val, argc, argv) JS_UNDEFINED
#define JS_Eval(ctx, code, len, filename, flags) JS_UNDEFINED
#define JS_EVAL_TYPE_MODULE 1
static void js_std_dump_error(JSContext *ctx) { fprintf(stderr, "JS Error\n"); }
#endif

// Plugin structure
struct SymFitPlugin {
    JSRuntime *rt;
    JSContext *ctx;
    JSValue plugin_obj;

    // Cached callback functions
    JSValue on_memory_write_fn;
    JSValue on_memory_read_fn;
    JSValue on_syscall_fn;
    JSValue on_syscall_return_fn;
    JSValue get_state_hash_fn;
    JSValue score_execution_fn;
    JSValue is_goal_reached_fn;

    // Context
    uint64_t current_pc;
    void *cpu_state;

    // Statistics
    uint64_t callback_count;
};

// Global (for simplicity in prototype)
static SymFitPlugin *g_plugin = NULL;

// === JavaScript Native Functions ===

/**
 * ctx.readMemory(addr, size)
 * Read memory at address
 */
static JSValue js_read_memory(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    if (argc < 2) {
        fprintf(stderr, "[Plugin] readMemory requires 2 arguments\n");
        return JS_UNDEFINED;
    }

    int64_t addr_signed = 0;
    int32_t size_int = 0;

    JS_ToBigInt64(ctx, &addr_signed, argv[0]);
    JS_ToInt32(ctx, &size_int, argv[1]);

    uint64_t addr = (uint64_t)addr_signed;
    uint32_t size = (uint32_t)size_int;

    // TODO: Actually read from QEMU memory
    // For prototype, return dummy value
    uint64_t value = 0x42;

    printf("[Plugin Native] readMemory(0x%lx, %u) = 0x%lx\n", addr, size, value);

    return JS_NewBigUint64(ctx, value);
}

/**
 * console.log(...)
 */
static JSValue js_console_log(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)this_val; // Suppress warning
    printf("[Plugin] ");
    for (int i = 0; i < argc; i++) {
        if (i > 0) printf(" ");
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            printf("%s", str);
            JS_FreeCString(ctx, str);
        } else {
            printf("[?]");
        }
    }
    printf("\n");
    return JS_UNDEFINED;
}

// === Helper: Create Context Object ===

static JSValue create_context_object(JSContext *ctx, SymFitPlugin *plugin) {
    JSValue obj = JS_NewObject(ctx);

    // Add PC
    JS_SetPropertyStr(ctx, obj, "pc", JS_NewBigUint64(ctx, plugin->current_pc));

    // Add instruction count (mock for prototype)
    JS_SetPropertyStr(ctx, obj, "instructionCount", JS_NewBigUint64(ctx, 12345));

    // Add readMemory function
    JSValue read_mem_fn = JS_NewCFunction(ctx, (void*)js_read_memory, "readMemory", 2);
    JS_SetPropertyStr(ctx, obj, "readMemory", read_mem_fn);

    return obj;
}

// === Plugin Loading ===

void symfit_plugin_init(void) {
    printf("[SymFit] Plugin system initialized\n");
}

SymFitPlugin* symfit_plugin_load(const char *plugin_path) {
    printf("[SymFit] Loading plugin: %s\n", plugin_path);

    SymFitPlugin *plugin = calloc(1, sizeof(SymFitPlugin));
    if (!plugin) {
        fprintf(stderr, "Failed to allocate plugin structure\n");
        return NULL;
    }

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

    // Setup console.log
    JSValue global = JS_GetGlobalObject(plugin->ctx);
    JSValue console = JS_NewObject(plugin->ctx);
    JS_SetPropertyStr(plugin->ctx, console, "log",
                     JS_NewCFunction(plugin->ctx, (void*)js_console_log, "log", 1));
    JS_SetPropertyStr(plugin->ctx, global, "console", console);
    JS_FreeValue(plugin->ctx, global);

    // Read plugin file
    FILE *f = fopen(plugin_path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open plugin file: %s\n", plugin_path);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *code = malloc(size + 1);
    if (!code) {
        fprintf(stderr, "Failed to allocate memory for plugin code\n");
        fclose(f);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    fread(code, 1, size, f);
    code[size] = '\0';
    fclose(f);

    printf("[SymFit] Plugin code loaded (%zu bytes)\n", size);

    // Evaluate plugin code as global script (not module)
    JSValue result = JS_Eval(plugin->ctx, code, size, plugin_path,
                            JS_EVAL_TYPE_GLOBAL);
    free(code);

    if (JS_IsException(result)) {
        fprintf(stderr, "Failed to evaluate plugin:\n");
        js_std_dump_error(plugin->ctx);
        JS_FreeValue(plugin->ctx, result);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    JS_FreeValue(plugin->ctx, result);

    // Get plugin object from global scope
    global = JS_GetGlobalObject(plugin->ctx);
    plugin->plugin_obj = JS_GetPropertyStr(plugin->ctx, global, "plugin");
    JS_FreeValue(plugin->ctx, global);

    // Check if plugin object exists and is valid
    if (JS_IsUndefined(plugin->plugin_obj) || JS_IsException(plugin->plugin_obj)) {
        fprintf(stderr, "Plugin must define 'globalThis.plugin' object\n");
        JS_FreeValue(plugin->ctx, plugin->plugin_obj);
        JS_FreeContext(plugin->ctx);
        JS_FreeRuntime(plugin->rt);
        free(plugin);
        return NULL;
    }

    // Cache callback functions
    plugin->on_memory_write_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onMemoryWrite");
    plugin->on_memory_read_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onMemoryRead");
    plugin->on_syscall_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onSyscall");
    plugin->on_syscall_return_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onSyscallReturn");
    plugin->get_state_hash_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "getStateHash");
    plugin->score_execution_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "scoreExecution");
    plugin->is_goal_reached_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "isGoalReached");

    // Call onInit if present
    JSValue on_init = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onInit");
    if (JS_IsFunction(plugin->ctx, on_init)) {
        printf("[SymFit] Calling plugin.onInit()\n");
        JSValue init_result = JS_Call(plugin->ctx, on_init, plugin->plugin_obj, 0, NULL);
        if (JS_IsException(init_result)) {
            js_std_dump_error(plugin->ctx);
        }
        JS_FreeValue(plugin->ctx, init_result);
    }
    JS_FreeValue(plugin->ctx, on_init);

    g_plugin = plugin;
    printf("[SymFit] Plugin loaded successfully\n");

    return plugin;
}

void symfit_plugin_unload(SymFitPlugin *plugin) {
    if (!plugin) return;

    printf("[SymFit] Unloading plugin (callbacks: %lu)\n", plugin->callback_count);

    // Call onFini if present
    JSValue on_fini = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onFini");
    if (JS_IsFunction(plugin->ctx, on_fini)) {
        printf("[SymFit] Calling plugin.onFini()\n");
        JSValue result = JS_Call(plugin->ctx, on_fini, plugin->plugin_obj, 0, NULL);
        JS_FreeValue(plugin->ctx, result);
    }
    JS_FreeValue(plugin->ctx, on_fini);

    // Free cached functions
    JS_FreeValue(plugin->ctx, plugin->on_memory_write_fn);
    JS_FreeValue(plugin->ctx, plugin->on_memory_read_fn);
    JS_FreeValue(plugin->ctx, plugin->on_syscall_fn);
    JS_FreeValue(plugin->ctx, plugin->on_syscall_return_fn);
    JS_FreeValue(plugin->ctx, plugin->get_state_hash_fn);
    JS_FreeValue(plugin->ctx, plugin->score_execution_fn);
    JS_FreeValue(plugin->ctx, plugin->is_goal_reached_fn);

    JS_FreeValue(plugin->ctx, plugin->plugin_obj);
    JS_FreeContext(plugin->ctx);
    JS_FreeRuntime(plugin->rt);
    free(plugin);

    if (g_plugin == plugin) {
        g_plugin = NULL;
    }
}

void symfit_plugin_shutdown(void) {
    printf("[SymFit] Plugin system shutdown\n");
}

// === Instrumentation Callbacks ===

void symfit_plugin_on_memory_write(SymFitPlugin *plugin,
                                    uint64_t addr,
                                    uint32_t size,
                                    uint64_t value) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->on_memory_write_fn)) {
        return;
    }

    plugin->callback_count++;

    JSValue args[3] = {
        JS_NewBigUint64(plugin->ctx, addr),
        JS_NewUint32(plugin->ctx, size),
        JS_NewBigUint64(plugin->ctx, value)
    };

    JSValue result = JS_Call(plugin->ctx, plugin->on_memory_write_fn,
                             plugin->plugin_obj, 3, args);

    if (JS_IsException(result)) {
        fprintf(stderr, "[SymFit] Error in onMemoryWrite:\n");
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, args[0]);
    JS_FreeValue(plugin->ctx, args[1]);
    JS_FreeValue(plugin->ctx, args[2]);
}

void symfit_plugin_on_syscall_return(SymFitPlugin *plugin,
                                      int syscall_num,
                                      uint64_t args[6],
                                      int64_t ret_val,
                                      const uint8_t *buffer,
                                      size_t buffer_len) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->on_syscall_return_fn)) {
        return;
    }

    plugin->callback_count++;

    // Build arguments array
    JSValue js_args[4];
    js_args[0] = JS_NewUint32(plugin->ctx, syscall_num);

    // Args array (simplified for prototype)
    JSValue args_array = JS_NewObject(plugin->ctx);
    js_args[1] = args_array;

    js_args[2] = JS_NewBigUint64(plugin->ctx, ret_val);

    // Data object with buffer
    JSValue data_obj = JS_NewObject(plugin->ctx);
    if (buffer && buffer_len > 0) {
        // Create a string from buffer (assuming UTF-8 text)
        JSValue buffer_str = JS_NewStringLen(plugin->ctx, (const char*)buffer, buffer_len);
        JS_SetPropertyStr(plugin->ctx, data_obj, "buffer", buffer_str);
    }
    js_args[3] = data_obj;

    JSValue result = JS_Call(plugin->ctx, plugin->on_syscall_return_fn,
                             plugin->plugin_obj, 4, js_args);

    if (JS_IsException(result)) {
        fprintf(stderr, "[SymFit] Error in onSyscallReturn:\n");
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, js_args[0]);
    JS_FreeValue(plugin->ctx, js_args[1]);
    JS_FreeValue(plugin->ctx, js_args[2]);
    JS_FreeValue(plugin->ctx, js_args[3]);
}

// === Decision Callbacks ===

uint64_t symfit_plugin_get_state_hash(SymFitPlugin *plugin) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->get_state_hash_fn)) {
        return 0;
    }

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue args[1] = { ctx_obj };

    JSValue result = JS_Call(plugin->ctx, plugin->get_state_hash_fn,
                             plugin->plugin_obj, 1, args);

    uint64_t hash = 0;
    if (!JS_IsException(result)) {
        int64_t hash_signed = 0;
        JS_ToBigInt64(plugin->ctx, &hash_signed, result);
        hash = (uint64_t)hash_signed;
    } else {
        fprintf(stderr, "[SymFit] Error in getStateHash:\n");
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);

    return hash;
}

double symfit_plugin_score_execution(SymFitPlugin *plugin) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->score_execution_fn)) {
        return 1.0;
    }

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue args[1] = { ctx_obj };

    JSValue result = JS_Call(plugin->ctx, plugin->score_execution_fn,
                             plugin->plugin_obj, 1, args);

    double score = 1.0;
    if (!JS_IsException(result)) {
        JS_ToFloat64(plugin->ctx, &score, result);
    } else {
        fprintf(stderr, "[SymFit] Error in scoreExecution:\n");
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);

    return score;
}

bool symfit_plugin_is_goal_reached(SymFitPlugin *plugin) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->is_goal_reached_fn)) {
        return false;
    }

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue args[1] = { ctx_obj };

    JSValue result = JS_Call(plugin->ctx, plugin->is_goal_reached_fn,
                             plugin->plugin_obj, 1, args);

    bool reached = false;
    // TODO: JS_ToBool

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);

    return reached;
}

void symfit_plugin_set_context(SymFitPlugin *plugin,
                               uint64_t pc,
                               void *cpu_state) {
    if (!plugin) return;
    plugin->current_pc = pc;
    plugin->cpu_state = cpu_state;
}
