# SymFit Plugin System Tests

This directory contains the comprehensive test suite for the SymFit plugin system.

## Test Files

### `test-all-features.js`
A comprehensive test plugin that validates all plugin system features:

#### Tested Features:

1. **Lifecycle Callbacks**
   - `onStartExecution()` - Called once before CPU execution starts
   - `onFini()` - Called when plugin is unloaded

2. **Instruction Hooks**
   - Global hooks (`addInstructionHook(-1n)`) - Fires for all instructions
   - Address-specific hooks - Fires only at specific PC addresses
   - Hook removal (`removeInstructionHook()`) - Dynamic hook management

3. **Register Access**
   - `readRegister()` - Read CPU register values
   - `writeRegister()` - Modify CPU register values
   - Architecture-specific register constants (x86-64, ARM64, RISC-V)

4. **Memory Access**
   - `readMemory()` - Read from guest memory
   - `writeMemory()` - Write to guest memory
   - Safe read-modify-restore pattern

5. **Syscall Monitoring**
   - `onSyscallReturn()` - Monitor system call returns
   - Capture syscall arguments and data buffers

## Running Tests

### Run the comprehensive test:
```bash
../../build/symfit-symsan/x86_64-linux-user/symqemu-x86_64 -plugin test-all-features.js ./test
```

### Expected Output:
The test will display:
- ✅ All features tested with visual checkmarks
- Detailed results for each category
- Final pass/fail status

## Test Binary

### `test` (test.c)
A simple test program that:
- Reads from a file called "testfile"
- Performs basic string operations
- Writes output to stdout
- Used as the target binary for plugin testing

### Building the test binary:
```bash
gcc -o test test.c
```

## Plugin API Reference

### Callbacks

- **`onStartExecution(ctx)`** - Called once before execution, receives context object
- **`onFini()`** - Called on plugin unload
- **`onSyscallReturn(syscallNum, args, retVal, data)`** - Called after syscalls

### Context Object Methods

- **`handle = ctx.addInstructionHook(address, callback)`** - Register instruction hook
  - Use `-1n` for global hooks (all instructions)
  - Use specific address for selective hooks
  - **Returns a hook handle (BigInt)** that must be used to remove the hook

- **`ctx.removeInstructionHook(handle)`** - Remove instruction hook by handle
  - Takes the handle returned by `addInstructionHook`
  - Returns `true` on success, `false` if not found
  - **Important**: Use the handle, not the address!

- **`ctx.readRegister(regName)`** - Read CPU register
  - Use `Registers.RAX`, `Registers.RBX`, etc.
  - Returns BigInt value

- **`ctx.writeRegister(regName, value)`** - Write CPU register
  - Value can be Number or BigInt

- **`ctx.readMemory(address, size)`** - Read guest memory
  - Size must be 1, 2, 4, or 8 bytes
  - Returns BigInt value

- **`ctx.writeMemory(address, size, value)`** - Write guest memory
  - Size must be 1, 2, 4, or 8 bytes
  - Value can be Number or BigInt

- **`ctx.pc`** - Current program counter (BigInt)

### Register Constants

Available via `Registers` object:
- **x86-64**: `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RSP`, `RBP`, `R8-R15`, `RIP`
- **ARM64**: `X0-X30`, `SP`, `PC`
- **RISC-V**: `ZERO`, `RA`, `SP`, `GP`, `TP`, `T0-T6`, `S0-S11`, `A0-A7`, `PC`

## Architecture Support

The plugin system supports:
- **x86-64** (primary testing architecture)
- **ARM64** (AArch64)
- **RISC-V**

Architecture detection is automatic at compile time.
