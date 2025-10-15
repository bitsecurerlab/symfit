/*
 * SymFit Plugin System - Global State
 *
 * Global plugin instance and initialization functions
 */

#ifndef SYMFIT_PLUGIN_GLOBAL_H
#define SYMFIT_PLUGIN_GLOBAL_H

#include "plugin-system/symfit_plugin.h"

/* Global plugin instance (NULL if no plugin loaded) */
extern SymFitPlugin *g_symfit_plugin;

/* Initialize plugin system with a plugin file */
void symfit_plugin_global_init(const char *plugin_path);

/* Shutdown and cleanup plugin system */
void symfit_plugin_global_shutdown(void);

#endif /* SYMFIT_PLUGIN_GLOBAL_H */
