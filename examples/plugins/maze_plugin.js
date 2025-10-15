/**
 * Maze Navigation Plugin for SymFit
 *
 * This plugin tracks player position in maze-style games by:
 * 1. Auto-detecting position variables in memory
 * 2. Tracking visited positions for deduplication
 * 3. Scoring executions based on exploration
 * 4. Detecting win conditions
 *
 * Usage:
 *   symqemu-x86_64 --plugin maze_plugin.js /tmp/maze_test/maze-nosleep
 */

const plugin = {
    name: "Maze Navigator",
    version: "1.0.0",

    state: {
        // Auto-detected memory addresses
        playerXAddr: null,
        playerYAddr: null,

        // Track visited positions for deduplication
        visitedPositions: new Set(),

        // Goal detection
        goalReached: false,
        goalPosition: null,

        // Statistics
        executionCount: 0,
        uniquePositions: 0
    },

    /**
     * Initialize plugin
     */
    onInit() {
        console.log("[Maze] Plugin initialized");
        console.log("[Maze] Will auto-detect player position in memory");
    },

    /**
     * Called at start of each execution
     */
    onExecutionStart(inputData) {
        this.state.executionCount++;
        this.state.goalReached = false;
    },

    /**
     * Monitor memory writes to detect position variables
     *
     * Heuristic: Position variables are typically:
     * - 4 bytes (int32)
     * - Small values (< 100 for typical mazes)
     * - Written frequently
     */
    onMemoryWrite(addr, size, value) {
        // Only track 4-byte integers
        if (size !== 4) return;

        // Position values are typically small
        if (value >= 100n) return;

        // First small int we see is probably X coordinate
        if (!this.state.playerXAddr) {
            console.log(`[Maze] Detected player X at ${addr.toString(16)} = ${value}`);
            this.state.playerXAddr = addr;
            return;
        }

        // Second different address is probably Y coordinate
        if (!this.state.playerYAddr && addr !== this.state.playerXAddr) {
            console.log(`[Maze] Detected player Y at ${addr.toString(16)} = ${value}`);
            this.state.playerYAddr = addr;
            return;
        }
    },

    /**
     * Monitor syscalls for win condition
     */
    onSyscallReturn(syscallNum, args, returnValue, data) {
        // Syscall 1 = write (program output)
        if (syscallNum === 1 && data.buffer) {
            const output = data.buffer.toString();

            // Check for win condition
            if (output.includes("You win") ||
                output.includes("WIN") ||
                output.includes("Success")) {

                console.log("[Maze] 🎉 WIN CONDITION DETECTED!");
                this.state.goalReached = true;

                // Signal to stop campaign
                return { stopCampaign: true };
            }

            // Extract goal position if visible in output (e.g., "Goal: 5,8")
            const goalMatch = output.match(/[Gg]oal.*?(\d+).*?(\d+)/);
            if (goalMatch && !this.state.goalPosition) {
                const x = parseInt(goalMatch[1]);
                const y = parseInt(goalMatch[2]);
                this.state.goalPosition = { x, y };
                console.log(`[Maze] Goal position detected: (${x}, ${y})`);
            }
        }
    },

    /**
     * Get unique state hash for deduplication
     *
     * Returns hash based on player position.
     * SymFit will only keep one test case per unique hash.
     */
    getStateHash(ctx) {
        if (!this.state.playerXAddr || !this.state.playerYAddr) {
            return 0n;  // No position detected yet
        }

        // Read current position
        const x = ctx.readMemory(this.state.playerXAddr, 4);
        const y = ctx.readMemory(this.state.playerYAddr, 4);

        // Hash = (x << 32) | y
        return (x << 32n) | y;
    },

    /**
     * Score execution (higher = more interesting)
     *
     * Scoring strategy:
     * - Winning: 10,000 points (top priority)
     * - New position: 100 points
     * - Closer to goal: bonus points
     * - Longer execution: small bonus (exploring deeper)
     */
    scoreExecution(ctx) {
        let score = 0.0;

        // Massive bonus for winning
        if (this.state.goalReached) {
            return 10000.0;
        }

        // Get current position
        if (this.state.playerXAddr && this.state.playerYAddr) {
            const x = ctx.readMemory(this.state.playerXAddr, 4);
            const y = ctx.readMemory(this.state.playerYAddr, 4);
            const posKey = `${x},${y}`;

            // Big bonus for discovering new position
            if (!this.state.visitedPositions.has(posKey)) {
                this.state.visitedPositions.add(posKey);
                this.state.uniquePositions++;
                score += 100.0;

                console.log(`[Maze] New position: (${x}, ${y}) - Total unique: ${this.state.uniquePositions}`);
            }

            // Bonus for getting closer to goal (if known)
            if (this.state.goalPosition) {
                const dist = Math.abs(Number(x) - this.state.goalPosition.x) +
                           Math.abs(Number(y) - this.state.goalPosition.y);

                // Closer = higher score (inverse of distance)
                score += (100 - dist) * 2.0;
            }
        }

        // Small bonus for longer executions (exploring deeper)
        score += Number(ctx.instructionCount) * 0.0001;

        return score;
    },

    /**
     * Check if we've reached the goal
     */
    isGoalReached(ctx) {
        return this.state.goalReached;
    },

    /**
     * Suggest next inputs to try
     *
     * For mazes, we extend current input with each direction (w/a/s/d)
     */
    suggestInputs(currentInput, ctx) {
        const suggestions = [];

        // Try each direction
        for (const direction of ['w', 'a', 's', 'd']) {
            const newInput = new Uint8Array(currentInput.length + 1);
            newInput.set(currentInput);
            newInput[currentInput.length] = direction.charCodeAt(0);
            suggestions.push(newInput);
        }

        return suggestions;
    },

    /**
     * Cleanup when plugin is unloaded
     */
    onFini() {
        console.log("\n[Maze] Plugin Statistics:");
        console.log(`  Total executions: ${this.state.executionCount}`);
        console.log(`  Unique positions found: ${this.state.uniquePositions}`);
        console.log(`  Goal reached: ${this.state.goalReached ? "YES ✓" : "NO"}`);
    }
};

// Export plugin to global scope
globalThis.plugin = plugin;
