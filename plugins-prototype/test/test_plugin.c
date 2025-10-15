/**
 * Test program for SymFit plugin system
 *
 * Simulates a simple maze-like program and demonstrates plugin hooks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "symfit_plugin.h"

// Simulated program state
typedef struct {
    int player_x;
    int player_y;
    int goal_x;
    int goal_y;
    int moves;
} GameState;

static GameState g_state = {0, 0, 5, 5, 0};

// Simulate memory writes (would be QEMU hooks in real implementation)
void update_position(SymFitPlugin *plugin, int *var, int value) {
    uint64_t addr = (uint64_t)var;
    *var = value;

    // Call plugin hook
    if (plugin) {
        symfit_plugin_on_memory_write(plugin, addr, 4, value);
    }
}

// Simulate program output
void print_state(SymFitPlugin *plugin) {
    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer),
                      "Position: (%d, %d) | Goal: (%d, %d) | Moves: %d\n",
                      g_state.player_x, g_state.player_y,
                      g_state.goal_x, g_state.goal_y,
                      g_state.moves);

    // Simulate write syscall
    if (plugin) {
        uint64_t args[6] = {1, (uint64_t)buffer, len, 0, 0, 0};  // write(1, buffer, len)
        symfit_plugin_on_syscall_return(plugin, 1, args, len,
                                        (uint8_t*)buffer, len);
    }

    printf("%s", buffer);
}

// Simulate win condition
bool check_win(SymFitPlugin *plugin) {
    if (g_state.player_x == g_state.goal_x &&
        g_state.player_y == g_state.goal_y) {

        const char *msg = "You win!\n";
        printf("%s", msg);

        // Simulate write syscall with win message
        if (plugin) {
            uint64_t args[6] = {1, (uint64_t)msg, strlen(msg), 0, 0, 0};
            symfit_plugin_on_syscall_return(plugin, 1, args, strlen(msg),
                                            (uint8_t*)msg, strlen(msg));
        }

        return true;
    }
    return false;
}

// Simulate game moves
void process_input(SymFitPlugin *plugin, char move) {
    g_state.moves++;

    switch (move) {
        case 'w': // up
            update_position(plugin, &g_state.player_y, g_state.player_y - 1);
            break;
        case 's': // down
            update_position(plugin, &g_state.player_y, g_state.player_y + 1);
            break;
        case 'a': // left
            update_position(plugin, &g_state.player_x, g_state.player_x - 1);
            break;
        case 'd': // right
            update_position(plugin, &g_state.player_x, g_state.player_x + 1);
            break;
        default:
            printf("Invalid move: %c\n", move);
    }

    // Clamp to 0-10 range
    if (g_state.player_x < 0) g_state.player_x = 0;
    if (g_state.player_y < 0) g_state.player_y = 0;
    if (g_state.player_x > 10) g_state.player_x = 10;
    if (g_state.player_y > 10) g_state.player_y = 10;
}

int main(int argc, char **argv) {
    printf("=== SymFit Plugin System Prototype ===\n\n");

    // Parse arguments
    const char *plugin_path = NULL;
    const char *moves = "ddssd";  // Default move sequence

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--plugin") == 0 && i + 1 < argc) {
            plugin_path = argv[++i];
        } else if (strcmp(argv[i], "--moves") == 0 && i + 1 < argc) {
            moves = argv[++i];
        }
    }

    // Initialize plugin system
    symfit_plugin_init();

    SymFitPlugin *plugin = NULL;
    if (plugin_path) {
        plugin = symfit_plugin_load(plugin_path);
        if (!plugin) {
            fprintf(stderr, "Failed to load plugin\n");
            return 1;
        }
    } else {
        printf("No plugin specified (use --plugin <file.js>)\n");
    }

    printf("\n=== Simulating Game ===\n");
    printf("Goal: Reach position (5, 5)\n");
    printf("Moves: %s\n\n", moves);

    // Simulate game execution
    print_state(plugin);

    for (const char *m = moves; *m; m++) {
        printf("\nMove: %c\n", *m);
        process_input(plugin, *m);
        print_state(plugin);

        if (check_win(plugin)) {
            break;
        }

        // Check plugin goal
        if (plugin && symfit_plugin_is_goal_reached(plugin)) {
            printf("[Plugin] Goal reached signal!\n");
            break;
        }
    }

    // Get plugin score and state hash
    if (plugin) {
        printf("\n=== Plugin Results ===\n");

        double score = symfit_plugin_score_execution(plugin);
        printf("Execution score: %.2f\n", score);

        uint64_t state_hash = symfit_plugin_get_state_hash(plugin);
        printf("State hash: 0x%lx\n", state_hash);

        symfit_plugin_unload(plugin);
    }

    symfit_plugin_shutdown();

    printf("\n=== Test Complete ===\n");
    return 0;
}
