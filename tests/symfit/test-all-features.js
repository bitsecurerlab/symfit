/**
 * Comprehensive Plugin Test
 *
 * Tests all available plugin callbacks and functions:
 * - onStartExecution: called once before execution starts
 * - Instruction hooks: addInstructionHook, removeInstructionHook (both global and address-specific)
 * - Register access: readRegister, writeRegister
 * - Memory access: readMemory, writeMemory
 * - onSyscallReturn: syscall monitoring
 * - onFini: cleanup callback
 */

const plugin = {
    name: "Comprehensive Feature Test",
    version: "1.0.0",

    state: {
        // Test tracking
        onStartExecutionCalled: false,
        onFiniCalled: false,

        // Instruction hooks
        globalHookCount: 0,
        addressHookCount: 0,
        firstPC: null,
        maxGlobalHooks: 5,
        globalHookHandle: null,  // Store hook handle for removal

        // Register tests
        registerReadSuccess: false,
        registerWriteSuccess: false,
        initialRAX: null,
        modifiedRAX: null,

        // Memory tests
        memoryReadSuccess: false,
        memoryWriteSuccess: false,
        stackValue: null,

        // Syscall tests
        syscallCount: 0,
        writeSyscallSeen: false,

        // Hook removal test
        hookRemoved: false,
    },

    onStartExecution() {
        console.log("╔════════════════════════════════════════════════════════╗");
        console.log("║     COMPREHENSIVE PLUGIN FEATURE TEST                  ║");
        console.log("╚════════════════════════════════════════════════════════╝");
        console.log("");

        this.state.onStartExecutionCalled = true;
        console.log("✓ onStartExecution() called successfully");
        console.log("");

        // Test 1: Global instruction hook
        console.log("━━━ Test 1: Global Instruction Hooks ━━━");
        this.state.globalHookHandle = addInstructionHook(-1n, () => {
            this.state.globalHookCount++;

            if (this.state.globalHookCount === 1) {
                const pc = readRegister(Registers.RIP);
                this.state.firstPC = pc;
                console.log(`  First instruction at: 0x${pc.toString(16)}`);

                // Test 2: Register read
                console.log("");
                console.log("━━━ Test 2: Register Read ━━━");
                try {
                    const rax = readRegister(Registers.RAX);
                    this.state.initialRAX = rax;
                    this.state.registerReadSuccess = true;
                    console.log(`  ✓ Read RAX: 0x${rax.toString(16)}`);
                } catch (e) {
                    console.log(`  ✗ Failed to read RAX: ${e}`);
                }

                // Test 3: Register write
                console.log("");
                console.log("━━━ Test 3: Register Write ━━━");
                try {
                    const testValue = 0x1234567890abcdefn;
                    writeRegister(Registers.R15, testValue);
                    const r15 = readRegister(Registers.R15);
                    if (r15 === testValue) {
                        this.state.registerWriteSuccess = true;
                        console.log(`  ✓ Write R15: 0x${testValue.toString(16)}`);
                        console.log(`  ✓ Verify R15: 0x${r15.toString(16)}`);
                    } else {
                        console.log(`  ✗ R15 mismatch: expected 0x${testValue.toString(16)}, got 0x${r15.toString(16)}`);
                    }
                } catch (e) {
                    console.log(`  ✗ Failed to write register: ${e}`);
                }

                // Test 4: Memory read (try to read from stack)
                console.log("");
                console.log("━━━ Test 4: Memory Read ━━━");
                try {
                    const rsp = readRegister(Registers.RSP);
                    console.log(`  Stack pointer: 0x${rsp.toString(16)}`);
                    const stackVal = readMemory(rsp, 8);
                    this.state.stackValue = stackVal;
                    this.state.memoryReadSuccess = true;
                    console.log(`  ✓ Read from stack: 0x${stackVal.toString(16)}`);
                } catch (e) {
                    console.log(`  ✗ Failed to read memory: ${e}`);
                }

                // Test 5: Memory write (read-modify-restore to avoid corruption)
                console.log("");
                console.log("━━━ Test 5: Memory Write ━━━");
                try {
                    const rsp = readRegister(Registers.RSP);
                    // Save original value
                    const originalVal = readMemory(rsp, 8);
                    // Write test value
                    const testValue = 0xdeadbeefcafebaben;
                    writeMemory(rsp, 8, testValue);
                    // Verify write
                    const verifyVal = readMemory(rsp, 8);
                    if (verifyVal === testValue) {
                        this.state.memoryWriteSuccess = true;
                        console.log(`  ✓ Write to stack: 0x${testValue.toString(16)}`);
                        console.log(`  ✓ Verify read: 0x${verifyVal.toString(16)}`);
                    } else {
                        console.log(`  ✗ Memory mismatch: expected 0x${testValue.toString(16)}, got 0x${verifyVal.toString(16)}`);
                    }
                    // Restore original value to avoid corruption
                    writeMemory(rsp, 8, originalVal);
                    console.log(`  ✓ Restored original value: 0x${originalVal.toString(16)}`);
                } catch (e) {
                    console.log(`  ✗ Failed to write memory: ${e}`);
                }

                // Test 6: Address-specific hook
                console.log("");
                console.log("━━━ Test 6: Address-Specific Hook ━━━");
                const hookAddr = pc;
                console.log(`  Registering hook at: 0x${hookAddr.toString(16)}`);

                addInstructionHook(hookAddr, () => {
                    this.state.addressHookCount++;
                    if (this.state.addressHookCount === 1) {
                        const addrPC = readRegister(Registers.RIP);
                        console.log(`  ✓ Address-specific hook triggered at: 0x${addrPC.toString(16)}`);
                    }
                });
            }

            // Test 7: Hook removal
            if (this.state.globalHookCount === this.state.maxGlobalHooks) {
                console.log("");
                console.log("━━━ Test 7: Hook Removal ━━━");
                console.log(`  Removing global hook after ${this.state.maxGlobalHooks} triggers...`);
                const removed = removeInstructionHook(this.state.globalHookHandle);
                this.state.hookRemoved = removed;
                if (removed) {
                    console.log("  ✓ Global hook removed successfully (using handle)");
                } else {
                    console.log("  ✗ Failed to remove global hook");
                }
            }
        });

        console.log("✓ Global instruction hook registered");
        console.log("");
    },

    onSyscallReturn(syscallNum, args, retVal, data) {
        this.state.syscallCount++;

        // Only log the first syscall to avoid spam
        if (this.state.syscallCount === 1) {
            console.log("");
            console.log("━━━ Test 8: Syscall Monitoring ━━━");
            console.log(`  Syscall #${syscallNum} returned: ${retVal}`);
        }

        // Check for write syscall (syscall number 1 on x86-64)
        if (syscallNum === 1) {
            this.state.writeSyscallSeen = true;
            if (this.state.syscallCount === 1) {
                console.log(`  ✓ Write syscall detected (fd=${args[0]}, count=${args[2]})`);
                if (data && data.buffer) {
                    console.log(`  ✓ Data captured: "${data.buffer}"`);
                }
            }
        }
    },

    onFini() {
        this.state.onFiniCalled = true;

        console.log("");
        console.log("╔════════════════════════════════════════════════════════╗");
        console.log("║                    TEST RESULTS                        ║");
        console.log("╚════════════════════════════════════════════════════════╝");
        console.log("");

        // Lifecycle callbacks
        console.log("┌─ Lifecycle Callbacks ─────────────────────────────────┐");
        this.logResult("onStartExecution called", this.state.onStartExecutionCalled);
        this.logResult("onFini called", this.state.onFiniCalled);
        console.log("└───────────────────────────────────────────────────────┘");
        console.log("");

        // Instruction hooks
        console.log("┌─ Instruction Hooks ───────────────────────────────────┐");
        this.logResult(`Global hooks fired (${this.state.globalHookCount}/${this.state.maxGlobalHooks})`,
                      this.state.globalHookCount === this.state.maxGlobalHooks);
        this.logResult("Address-specific hook fired", this.state.addressHookCount > 0);
        this.logResult("Hook removal worked", this.state.hookRemoved);
        console.log("└───────────────────────────────────────────────────────┘");
        console.log("");

        // Register access
        console.log("┌─ Register Access ─────────────────────────────────────┐");
        this.logResult("Register read", this.state.registerReadSuccess);
        this.logResult("Register write", this.state.registerWriteSuccess);
        if (this.state.initialRAX !== null) {
            console.log(`  Initial RAX: 0x${this.state.initialRAX.toString(16)}`);
        }
        console.log("└───────────────────────────────────────────────────────┘");
        console.log("");

        // Memory access
        console.log("┌─ Memory Access ───────────────────────────────────────┐");
        this.logResult("Memory read", this.state.memoryReadSuccess);
        this.logResult("Memory write", this.state.memoryWriteSuccess);
        if (this.state.stackValue !== null) {
            console.log(`  Stack value: 0x${this.state.stackValue.toString(16)}`);
        }
        console.log("└───────────────────────────────────────────────────────┘");
        console.log("");

        // Syscall monitoring
        console.log("┌─ Syscall Monitoring ──────────────────────────────────┐");
        this.logResult("Syscalls detected", this.state.syscallCount > 0);
        this.logResult("Write syscall seen", this.state.writeSyscallSeen);
        console.log(`  Total syscalls: ${this.state.syscallCount}`);
        console.log("└───────────────────────────────────────────────────────┘");
        console.log("");

        // Overall result
        const allPassed = this.state.onStartExecutionCalled &&
                         this.state.onFiniCalled &&
                         this.state.globalHookCount === this.state.maxGlobalHooks &&
                         this.state.addressHookCount > 0 &&
                         this.state.hookRemoved &&
                         this.state.registerReadSuccess &&
                         this.state.registerWriteSuccess &&
                         this.state.memoryReadSuccess &&
                         this.state.memoryWriteSuccess &&
                         this.state.syscallCount > 0 &&
                         this.state.writeSyscallSeen;

        console.log("╔════════════════════════════════════════════════════════╗");
        if (allPassed) {
            console.log("║              ✅ ALL TESTS PASSED ✅                    ║");
        } else {
            console.log("║              ❌ SOME TESTS FAILED ❌                   ║");
        }
        console.log("╚════════════════════════════════════════════════════════╝");
        console.log("");
    },

    logResult(name, passed) {
        const status = passed ? "✅" : "❌";
        const paddedName = name.padEnd(45);
        console.log(`  ${status} ${paddedName}`);
    }
};

// Export plugin
globalThis.plugin = plugin;
