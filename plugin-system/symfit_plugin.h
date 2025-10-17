/**
 * SymFit JavaScript Plugin Interface
 *
 * Minimal prototype for JavaScript plugin system using QuickJS
 */

#ifndef SYMFIT_PLUGIN_H
#define SYMFIT_PLUGIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque plugin handle
typedef struct SymFitPlugin SymFitPlugin;

// === Plugin Lifecycle ===

/**
 * Initialize plugin system
 * Call once at program startup
 */
void symfit_plugin_init(void);

/**
 * Load JavaScript plugin from file
 * @param plugin_path Path to .js file
 * @return Plugin handle or NULL on error
 */
SymFitPlugin* symfit_plugin_load(const char *plugin_path);

/**
 * Unload plugin and free resources
 */
void symfit_plugin_unload(SymFitPlugin *plugin);

/**
 * Shutdown plugin system
 * Call once at program exit
 */
void symfit_plugin_shutdown(void);

// === Instrumentation Hooks ===

/**
 * Called on memory write
 * @param addr Memory address
 * @param size Write size (1, 2, 4, 8 bytes)
 * @param value Value written
 */
void symfit_plugin_on_memory_write(SymFitPlugin *plugin,
                                    void *env,
                                    uint64_t addr,
                                    uint32_t size,
                                    uint64_t value);

/**
 * Called on memory read
 */
void symfit_plugin_on_memory_read(SymFitPlugin *plugin,
                                   uint64_t addr,
                                   uint32_t size,
                                   uint64_t value);

/**
 * Called before syscall execution
 * @param syscall_num Syscall number
 * @param args Array of 6 syscall arguments
 */
void symfit_plugin_on_syscall(SymFitPlugin *plugin,
                               int syscall_num,
                               uint64_t args[6]);

/**
 * Called after syscall execution
 * @param syscall_num Syscall number
 * @param args Original arguments
 * @param ret_val Return value
 * @param buffer Optional data buffer (for read/write syscalls)
 * @param buffer_len Length of buffer
 */
void symfit_plugin_on_syscall_return(SymFitPlugin *plugin,
                                      void * cpu_env,
                                      int syscall_num,
                                      uint64_t args[6],
                                      int64_t ret_val,
                                      const uint8_t *buffer,
                                      size_t buffer_len);

// === Context for Memory Access ===

/**
 * Set CPU state for memory access
 * Call before invoking plugin hooks that may need memory access
 */
void symfit_plugin_set_context(SymFitPlugin *plugin,
                               uint64_t pc,
                               void *cpu_state);

#ifdef __cplusplus
}
#endif

#endif // SYMFIT_PLUGIN_H
