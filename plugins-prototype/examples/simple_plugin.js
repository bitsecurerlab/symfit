/**
 * Simple test plugin for prototype
 *
 * Demonstrates basic plugin functionality:
 * - Tracking memory writes
 * - Detecting win conditions
 * - Scoring executions
 * - State hashing
 */

globalThis.plugin = {
    name: "Simple Test Plugin",

    // Plugin state
    state: {
        playerXAddr: null,
        playerYAddr: null,
        visitedPositions: new Set(),
        winDetected: false,
        memoryWrites: 0
    },

    /**
     * Initialize plugin
     */
    onInit() {
        console.log("[Plugin] Simple test plugin initialized");
    },

    /**
     * Track memory writes to detect position variables
     */
    onMemoryWrite(addr, size, value) {
        this.state.memoryWrites++;

        console.log(`[Plugin] Memory write: addr=0x${addr.toString(16)}, size=${size}, value=${value}`);

        // Auto-detect X coordinate (first write)
        if (!this.state.playerXAddr && size === 4) {
            this.state.playerXAddr = addr;
            console.log(`[Plugin] Detected player X at ${addr.toString(16)}`);
        }
        // Auto-detect Y coordinate (second write)
        else if (!this.state.playerYAddr && size === 4 && addr !== this.state.playerXAddr) {
            this.state.playerYAddr = addr;
            console.log(`[Plugin] Detected player Y at ${addr.toString(16)}`);
        }
    },

    /**
     * Monitor syscalls for win condition
     */
    onSyscallReturn(syscallNum, args, returnValue, data) {
        // Syscall 1 = write
        if (syscallNum === 1 && data.buffer) {
            const output = data.buffer.toString();
            console.log(`[Plugin] Program output: ${output.trim()}`);

            // Check for win
            if (output.includes("You win")) {
                console.log("[Plugin] 🎉 WIN DETECTED!");
                this.state.winDetected = true;
            }
        }
    },

    /**
     * Get state hash (for deduplication)
     * Hash based on player position
     */
    getStateHash(ctx) {
        if (!this.state.playerXAddr || !this.state.playerYAddr) {
            console.log("[Plugin] State hash: positions not detected yet");
            return 0n;
        }

        // Read current position
        const x = ctx.readMemory(this.state.playerXAddr, 4);
        const y = ctx.readMemory(this.state.playerYAddr, 4);

        const hash = (x << 32n) | y;
        console.log(`[Plugin] State hash: 0x${hash.toString(16)} (pos: ${x},${y})`);

        return hash;
    },

    /**
     * Score this execution
     */
    scoreExecution(ctx) {
        let score = 0.0;

        console.log("[Plugin] Scoring execution...");

        // Huge bonus for winning
        if (this.state.winDetected) {
            console.log("[Plugin] Score: 10000.0 (WIN!)");
            return 10000.0;
        }

        // Bonus for exploring (based on memory writes)
        score += this.state.memoryWrites * 0.1;

        // Check if we've seen this position before
        if (this.state.playerXAddr && this.state.playerYAddr) {
            const x = ctx.readMemory(this.state.playerXAddr, 4);
            const y = ctx.readMemory(this.state.playerYAddr, 4);
            const posKey = `${x},${y}`;

            if (!this.state.visitedPositions.has(posKey)) {
                this.state.visitedPositions.add(posKey);
                score += 100.0;
                console.log(`[Plugin] New position (${x},${y})! Score bonus: +100`);
            }
        }

        console.log(`[Plugin] Final score: ${score.toFixed(2)}`);
        return score;
    },

    /**
     * Check if goal reached
     */
    isGoalReached(ctx) {
        const reached = this.state.winDetected;
        console.log(`[Plugin] Goal reached: ${reached}`);
        return reached;
    },

    /**
     * Cleanup
     */
    onFini() {
        console.log("[Plugin] Shutting down");
        console.log(`[Plugin] Total memory writes tracked: ${this.state.memoryWrites}`);
        console.log(`[Plugin] Unique positions visited: ${this.state.visitedPositions.size}`);
    }
};
