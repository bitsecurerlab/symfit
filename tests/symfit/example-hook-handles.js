/**
 * Example: Hook Handle Management
 *
 * Demonstrates the new hook handle API where addInstructionHook returns
 * a handle that can be used to precisely remove individual hooks.
 */

const plugin = {
    name: "Hook Handle Example",
    version: "1.0.0",

    state: {
        hook1: null,
        hook2: null,
        hook3: null,
        hook1Count: 0,
        hook2Count: 0,
        hook3Count: 0,
    },

    onStartExecution() {
        console.log("=== Hook Handle Management Example ===");
        console.log("");

        // Register multiple hooks at the same address
        console.log("Registering 3 hooks at the same global address (-1n):");

        this.state.hook1 = addInstructionHook(-1n, () => {
            this.state.hook1Count++;
            if (this.state.hook1Count <= 2) {
                console.log(`  Hook 1 fired (count: ${this.state.hook1Count})`);
            }

            // Remove hook 2 after 3 instructions
            if (this.state.hook1Count === 3 && this.state.hook2 !== null) {
                console.log("  → Hook 1: Removing hook 2...");
                removeInstructionHook(this.state.hook2);
                this.state.hook2 = null;
            }
        });

        this.state.hook2 = addInstructionHook(-1n, () => {
            this.state.hook2Count++;
            if (this.state.hook2Count <= 2) {
                console.log(`  Hook 2 fired (count: ${this.state.hook2Count})`);
            }
        });

        this.state.hook3 = addInstructionHook(-1n, () => {
            this.state.hook3Count++;
            if (this.state.hook3Count <= 2) {
                console.log(`  Hook 3 fired (count: ${this.state.hook3Count})`);
            }

            // Remove all hooks after 5 instructions
            if (this.state.hook3Count === 5) {
                console.log("  → Hook 3: Removing all remaining hooks...");
                // Save handles before nullifying
                const handle1 = this.state.hook1;
                const handle3 = this.state.hook3;

                // Remove hooks (check for null, not falsy, since 0n is a valid handle!)
                if (handle1 !== null) {
                    console.log(`    Removing hook 1 (handle ${handle1})...`);
                    removeInstructionHook(handle1);
                    this.state.hook1 = null;
                }
                if (handle3 !== null) {
                    console.log(`    Removing hook 3 (handle ${handle3})...`);
                    removeInstructionHook(handle3);
                    this.state.hook3 = null;
                }
            }
        });

        console.log(`  Handle 1: ${this.state.hook1}`);
        console.log(`  Handle 2: ${this.state.hook2}`);
        console.log(`  Handle 3: ${this.state.hook3}`);
        console.log("");
        console.log("All 3 hooks are global and will fire on every instruction.");
        console.log("Hook 2 will be removed after 3 instructions.");
        console.log("All remaining hooks will be removed after 5 instructions.");
        console.log("");
    },

    onFini() {
        console.log("");
        console.log("=== Final Results ===");
        console.log(`Hook 1 count: ${this.state.hook1Count}`);
        console.log(`Hook 2 count: ${this.state.hook2Count}`);
        console.log(`Hook 3 count: ${this.state.hook3Count}`);
        console.log("");

        // Hooks are called in LIFO order (Hook 3, Hook 2, Hook 1)
        // Hook 2 is removed on instruction 3 (after firing 3 times)
        // Hook 3 fires on instruction 5 and removes both Hook 3 and Hook 1
        // Since Hook 3 fires before Hook 1, Hook 1 only fires 4 times (instructions 1-4)
        const hook2RemovedCorrectly = this.state.hook2Count === 3;
        const hook1RemovedCorrectly = this.state.hook1Count === 4; // Removed before it could fire on instruction 5
        const hook3RemovedCorrectly = this.state.hook3Count === 5;

        console.log("Expected behavior:");
        console.log(`  Hook 2: 3 fires (removed after instruction 3) - ${hook2RemovedCorrectly ? '✅' : '❌'}`);
        console.log(`  Hook 1: 4 fires (removed before instruction 5) - ${hook1RemovedCorrectly ? '✅' : '❌'}`);
        console.log(`  Hook 3: 5 fires (removes itself on instruction 5) - ${hook3RemovedCorrectly ? '✅' : '❌'}`);
        console.log("");
        console.log("Note: Hooks execute in LIFO order (most recently added first)");
        console.log("");

        if (hook2RemovedCorrectly && hook1RemovedCorrectly && hook3RemovedCorrectly) {
            console.log("✅ Hook handles work correctly!");
            console.log("   - Individual hook removal works");
            console.log("   - Multiple hooks at same address work independently");
            console.log("   - Hooks can safely remove themselves or other hooks");
        } else {
            console.log("❌ Test failed - hooks didn't behave as expected");
        }
    }
};

globalThis.plugin = plugin;
