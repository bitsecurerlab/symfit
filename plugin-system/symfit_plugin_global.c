/*
 * SymFit Plugin System - Global State Implementation
 */

#include "qemu/osdep.h"
#include "symfit-plugin-global.h"
#include <stdio.h>

/* Global plugin instance */
SymFitPlugin *g_symfit_plugin = NULL;

void symfit_plugin_global_init(const char *plugin_path)
{
    if (!plugin_path) {
        return;
    }

    fprintf(stderr, "[SymFit] Initializing plugin system\n");
    symfit_plugin_init();

    fprintf(stderr, "[SymFit] Loading plugin: %s\n", plugin_path);
    g_symfit_plugin = symfit_plugin_load(plugin_path);

    if (!g_symfit_plugin) {
        fprintf(stderr, "[SymFit] ERROR: Failed to load plugin\n");
    } else {
        fprintf(stderr, "[SymFit] Plugin loaded successfully\n");
    }
}

void symfit_plugin_global_shutdown(void)
{
    if (g_symfit_plugin) {
        fprintf(stderr, "[SymFit] Shutting down plugin system\n");

        // Write plugin results to file for MCP server to read
        const char *output_dir = getenv("SYMCC_OUTPUT_DIR");
        if (output_dir) {
            char plugin_results_path[1024];
            snprintf(plugin_results_path, sizeof(plugin_results_path),
                     "%s/plugin_results.json", output_dir);

            FILE *f = fopen(plugin_results_path, "w");
            if (f) {
                double score = symfit_plugin_score_execution(g_symfit_plugin);
                bool goal_reached = symfit_plugin_is_goal_reached(g_symfit_plugin);
                uint64_t state_hash = symfit_plugin_get_state_hash(g_symfit_plugin);

                fprintf(f, "{\n");
                fprintf(f, "  \"score\": %.2f,\n", score);
                fprintf(f, "  \"goal_reached\": %s,\n", goal_reached ? "true" : "false");
                fprintf(f, "  \"state_hash\": \"%016lx\"\n", state_hash);
                fprintf(f, "}\n");
                fclose(f);

                fprintf(stderr, "[SymFit] Plugin results: score=%.2f, goal_reached=%s, state_hash=%016lx\n",
                        score, goal_reached ? "true" : "false", state_hash);
            }
        }

        symfit_plugin_unload(g_symfit_plugin);
        g_symfit_plugin = NULL;
    }
    symfit_plugin_shutdown();
}
