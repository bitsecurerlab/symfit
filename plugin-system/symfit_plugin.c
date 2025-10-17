/**
 * SymFit JavaScript Plugin Implementation
 * Using QuickJS for lightweight embedding
 */

#include "symfit_plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// QEMU includes for memory access
#include "qemu/osdep.h"
#include "qom/cpu.h"
#include "exec/cpu-all.h"
#include "qemu/bswap.h"

  #ifdef TARGET_X86_64
    #include "target/i386/cpu.h"
  #elif defined(TARGET_AARCH64)
    #include "target/arm/cpu.h"
  #elif defined(TARGET_RISCV64)
    #include "target/riscv/cpu.h"
  #endif


// No need for forward declarations - headers provide everything

// Architecture detection at compile time
// When built in Makefile.target context, TARGET_* macros are available
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    #define PLUGIN_ARCH "x86-64"
    #define SYMFIT_ARCH_X86
#elif defined(TARGET_AARCH64)
    #define PLUGIN_ARCH "ARM64"
    #define SYMFIT_ARCH_ARM64
#elif defined(TARGET_RISCV64) || defined(TARGET_RISCV)
    #define PLUGIN_ARCH "RISC-V"
    #define SYMFIT_ARCH_RISCV
#else
    #define PLUGIN_ARCH "unknown"
#endif

// Architecture-specific CPU state types
//typedef struct CPUX86State CPUX86State;
//typedef struct CPUARMState CPUARMState;
//typedef struct CPURISCVState CPURISCVState;

// Architecture-specific register indices
// x86-64
enum X86Register {
    X86_RAX = 0, X86_RCX = 1, X86_RDX = 2, X86_RBX = 3,
    X86_RSP = 4, X86_RBP = 5, X86_RSI = 6, X86_RDI = 7,
    X86_R8  = 8, X86_R9  = 9, X86_R10 = 10, X86_R11 = 11,
    X86_R12 = 12, X86_R13 = 13, X86_R14 = 14, X86_R15 = 15,
};

// ARM64 (AArch64)
enum ARM64Register {
    ARM64_X0  = 0,  ARM64_X1  = 1,  ARM64_X2  = 2,  ARM64_X3  = 3,
    ARM64_X4  = 4,  ARM64_X5  = 5,  ARM64_X6  = 6,  ARM64_X7  = 7,
    ARM64_X8  = 8,  ARM64_X9  = 9,  ARM64_X10 = 10, ARM64_X11 = 11,
    ARM64_X12 = 12, ARM64_X13 = 13, ARM64_X14 = 14, ARM64_X15 = 15,
    ARM64_X16 = 16, ARM64_X17 = 17, ARM64_X18 = 18, ARM64_X19 = 19,
    ARM64_X20 = 20, ARM64_X21 = 21, ARM64_X22 = 22, ARM64_X23 = 23,
    ARM64_X24 = 24, ARM64_X25 = 25, ARM64_X26 = 26, ARM64_X27 = 27,
    ARM64_X28 = 28, ARM64_X29 = 29, ARM64_X30 = 30, ARM64_SP  = 31,
};

// RISC-V
enum RISCVRegister {
    RISCV_ZERO = 0,  RISCV_RA = 1,   RISCV_SP = 2,   RISCV_GP = 3,
    RISCV_TP   = 4,  RISCV_T0 = 5,   RISCV_T1 = 6,   RISCV_T2 = 7,
    RISCV_S0   = 8,  RISCV_S1 = 9,   RISCV_A0 = 10,  RISCV_A1 = 11,
    RISCV_A2   = 12, RISCV_A3 = 13,  RISCV_A4 = 14,  RISCV_A5 = 15,
    RISCV_A6   = 16, RISCV_A7 = 17,  RISCV_S2 = 18,  RISCV_S3 = 19,
    RISCV_S4   = 20, RISCV_S5 = 21,  RISCV_S6 = 22,  RISCV_S7 = 23,
    RISCV_S8   = 24, RISCV_S9 = 25,  RISCV_S10 = 26, RISCV_S11 = 27,
    RISCV_T3   = 28, RISCV_T4 = 29,  RISCV_T5 = 30,  RISCV_T6 = 31,
};

// QuickJS headers
#include "quickjs.h"
#include "quickjs-libc.h"

// === Instruction Hook Hash Table ===

#define HOOK_TABLE_SIZE 1024
#define GLOBAL_HOOK_PC 0xFFFFFFFFFFFFFFFFULL  // Special value for global hooks

typedef struct InstructionHookEntry {
    uint64_t pc;
    JSValue callback;
    uint64_t hook_id;  // Unique identifier for this hook
    struct InstructionHookEntry *next;
} InstructionHookEntry;

typedef struct {
    InstructionHookEntry *buckets[HOOK_TABLE_SIZE];
    InstructionHookEntry *global_hook;  // Separate storage for global hook
} InstructionHookTable;

static uint32_t hash_pc(uint64_t pc) {
    return (uint32_t)(pc % HOOK_TABLE_SIZE);
}

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
    JSValue on_start_execution_fn;

    // Execution state
    int execution_started;

    // Context
    uint64_t current_pc;
    void *cpu_env; // Pointer to CPUArchState

    // Instruction hooks
    InstructionHookTable *instruction_hooks;
    uint64_t next_hook_id;  // Counter for generating unique hook IDs

    // Statistics
    uint64_t callback_count;
};

// Global (for simplicity in prototype)
static SymFitPlugin *g_plugin = NULL;

// === JavaScript Native Functions ===

/**
 * ctx.readMemory(addr, size)
 * Read memory at address
 * Returns the value as a BigInt, or undefined on error
 */
static JSValue js_read_memory(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    if (argc < 2) {
        fprintf(stderr, "[Plugin] readMemory requires 2 arguments (addr, size)\n");
        return JS_UNDEFINED;
    }

    // Get address (can be Number or BigInt)
    int64_t addr_signed = 0;
    if (JS_IsBigInt(ctx, argv[0])) {
        JS_ToBigInt64(ctx, &addr_signed, argv[0]);
    } else {
        int32_t addr_int = 0;
        JS_ToInt32(ctx, &addr_int, argv[0]);
        addr_signed = addr_int;
    }
    uint64_t addr = (uint64_t)addr_signed;

    // Get size (must be 1, 2, 4, or 8)
    int32_t size = 0;
    JS_ToInt32(ctx, &size, argv[1]);

    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "[Plugin] readMemory: size must be 1, 2, 4, or 8 (got %d)\n", size);
        return JS_UNDEFINED;
    }

    // Get CPU state from global plugin
    if (!g_plugin || !g_plugin->cpu_env) {
        fprintf(stderr, "[Plugin] readMemory: no CPU state available\n");
        return JS_UNDEFINED;
    }

    // Convert cpu_env to CPUState for memory operations
    CPUState *cpu = env_cpu((CPUArchState *)g_plugin->cpu_env);
    uint8_t buffer[8] = {0};

    // Read from QEMU memory using cpu_memory_rw_debug
    int result = cpu_memory_rw_debug(cpu, addr, buffer, size, 0);
    if (result != 0) {
        fprintf(stderr, "[Plugin] readMemory: failed to read from address 0x%lx\n", addr);
        return JS_UNDEFINED;
    }

    // Convert buffer to uint64_t based on size (little-endian)
    uint64_t value = 0;
    switch (size) {
        case 1:
            value = buffer[0];
            break;
        case 2:
            value = buffer[0] | (buffer[1] << 8);
            break;
        case 4:
            value = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
            break;
        case 8:
            value = (uint64_t)buffer[0] | ((uint64_t)buffer[1] << 8) |
                    ((uint64_t)buffer[2] << 16) | ((uint64_t)buffer[3] << 24) |
                    ((uint64_t)buffer[4] << 32) | ((uint64_t)buffer[5] << 40) |
                    ((uint64_t)buffer[6] << 48) | ((uint64_t)buffer[7] << 56);
            break;
    }

    printf("[Plugin Native] readMemory(0x%lx, %d) = 0x%lx\n", addr, size, value);
    return JS_NewBigUint64(ctx, value);
}

/**
 * ctx.writeMemory(addr, size, value)
 * Write memory at address
 * Returns true on success, false on error
 */
static JSValue js_write_memory(JSContext *ctx, JSValue this_val,
                               int argc, JSValue *argv) {
    if (argc < 3) {
        fprintf(stderr, "[Plugin] writeMemory requires 3 arguments (addr, size, value)\n");
        return JS_FALSE;
    }

    // Get address (can be Number or BigInt)
    int64_t addr_signed = 0;
    if (JS_IsBigInt(ctx, argv[0])) {
        JS_ToBigInt64(ctx, &addr_signed, argv[0]);
    } else {
        int32_t addr_int = 0;
        JS_ToInt32(ctx, &addr_int, argv[0]);
        addr_signed = addr_int;
    }
    uint64_t addr = (uint64_t)addr_signed;

    // Get size (must be 1, 2, 4, or 8)
    int32_t size = 0;
    JS_ToInt32(ctx, &size, argv[1]);

    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "[Plugin] writeMemory: size must be 1, 2, 4, or 8 (got %d)\n", size);
        return JS_FALSE;
    }

    // Get value (can be Number or BigInt)
    int64_t value_signed = 0;
    if (JS_IsBigInt(ctx, argv[2])) {
        JS_ToBigInt64(ctx, &value_signed, argv[2]);
    } else {
        int32_t value_int = 0;
        JS_ToInt32(ctx, &value_int, argv[2]);
        value_signed = value_int;
    }
    uint64_t value = (uint64_t)value_signed;

    // Get CPU state from global plugin
    if (!g_plugin || !g_plugin->cpu_env) {
        fprintf(stderr, "[Plugin] writeMemory: no CPU state available\n");
        return JS_FALSE;
    }

    // Convert cpu_env to CPUState for memory operations
    CPUState *cpu = env_cpu((CPUArchState *)g_plugin->cpu_env);
    uint8_t buffer[8] = {0};

    // Convert value to bytes (little-endian)
    switch (size) {
        case 1:
            buffer[0] = value & 0xFF;
            break;
        case 2:
            buffer[0] = value & 0xFF;
            buffer[1] = (value >> 8) & 0xFF;
            break;
        case 4:
            buffer[0] = value & 0xFF;
            buffer[1] = (value >> 8) & 0xFF;
            buffer[2] = (value >> 16) & 0xFF;
            buffer[3] = (value >> 24) & 0xFF;
            break;
        case 8:
            buffer[0] = value & 0xFF;
            buffer[1] = (value >> 8) & 0xFF;
            buffer[2] = (value >> 16) & 0xFF;
            buffer[3] = (value >> 24) & 0xFF;
            buffer[4] = (value >> 32) & 0xFF;
            buffer[5] = (value >> 40) & 0xFF;
            buffer[6] = (value >> 48) & 0xFF;
            buffer[7] = (value >> 56) & 0xFF;
            break;
    }

    // Write to QEMU memory using cpu_memory_rw_debug
    int result = cpu_memory_rw_debug(cpu, addr, buffer, size, 1);  // 1 = write
    if (result != 0) {
        fprintf(stderr, "[Plugin] writeMemory: failed to write to address 0x%lx\n", addr);
        return JS_FALSE;
    }

    printf("[Plugin Native] writeMemory(0x%lx, %d, 0x%lx)\n", addr, size, value);
    return JS_TRUE;
}

#ifdef SYMFIT_ARCH_X86
// Helper: Read register for x86-64
static int read_register_x86(const char *reg_name, CPUX86State *env, uint64_t *out_value) {
    uint64_t *regs = (uint64_t*)env->regs;

    // 64-bit registers (RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8-R15)
    if (strcmp(reg_name, "rax") == 0) *out_value = regs[X86_RAX];
    else if (strcmp(reg_name, "rcx") == 0) *out_value = regs[X86_RCX];
    else if (strcmp(reg_name, "rdx") == 0) *out_value = regs[X86_RDX];
    else if (strcmp(reg_name, "rbx") == 0) *out_value = regs[X86_RBX];
    else if (strcmp(reg_name, "rsp") == 0) *out_value = regs[X86_RSP];
    else if (strcmp(reg_name, "rbp") == 0) *out_value = regs[X86_RBP];
    else if (strcmp(reg_name, "rsi") == 0) *out_value = regs[X86_RSI];
    else if (strcmp(reg_name, "rdi") == 0) *out_value = regs[X86_RDI];
    else if (strcmp(reg_name, "r8") == 0) *out_value = regs[X86_R8];
    else if (strcmp(reg_name, "r9") == 0) *out_value = regs[X86_R9];
    else if (strcmp(reg_name, "r10") == 0) *out_value = regs[X86_R10];
    else if (strcmp(reg_name, "r11") == 0) *out_value = regs[X86_R11];
    else if (strcmp(reg_name, "r12") == 0) *out_value = regs[X86_R12];
    else if (strcmp(reg_name, "r13") == 0) *out_value = regs[X86_R13];
    else if (strcmp(reg_name, "r14") == 0) *out_value = regs[X86_R14];
    else if (strcmp(reg_name, "r15") == 0) *out_value = regs[X86_R15];
    else if (strcmp(reg_name, "rip") == 0) *out_value = g_plugin->current_pc;

    // 32-bit registers (EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, R8D-R15D)
    else if (strcmp(reg_name, "eax") == 0) *out_value = regs[X86_RAX] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ecx") == 0) *out_value = regs[X86_RCX] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "edx") == 0) *out_value = regs[X86_RDX] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ebx") == 0) *out_value = regs[X86_RBX] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "esp") == 0) *out_value = regs[X86_RSP] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ebp") == 0) *out_value = regs[X86_RBP] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "esi") == 0) *out_value = regs[X86_RSI] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "edi") == 0) *out_value = regs[X86_RDI] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r8d") == 0) *out_value = regs[X86_R8] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r9d") == 0) *out_value = regs[X86_R9] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r10d") == 0) *out_value = regs[X86_R10] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r11d") == 0) *out_value = regs[X86_R11] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r12d") == 0) *out_value = regs[X86_R12] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r13d") == 0) *out_value = regs[X86_R13] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r14d") == 0) *out_value = regs[X86_R14] & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r15d") == 0) *out_value = regs[X86_R15] & 0xFFFFFFFF;

    // 16-bit registers (AX, BX, CX, DX, SI, DI, SP, BP, R8W-R15W)
    else if (strcmp(reg_name, "ax") == 0) *out_value = regs[X86_RAX] & 0xFFFF;
    else if (strcmp(reg_name, "cx") == 0) *out_value = regs[X86_RCX] & 0xFFFF;
    else if (strcmp(reg_name, "dx") == 0) *out_value = regs[X86_RDX] & 0xFFFF;
    else if (strcmp(reg_name, "bx") == 0) *out_value = regs[X86_RBX] & 0xFFFF;
    else if (strcmp(reg_name, "sp") == 0) *out_value = regs[X86_RSP] & 0xFFFF;
    else if (strcmp(reg_name, "bp") == 0) *out_value = regs[X86_RBP] & 0xFFFF;
    else if (strcmp(reg_name, "si") == 0) *out_value = regs[X86_RSI] & 0xFFFF;
    else if (strcmp(reg_name, "di") == 0) *out_value = regs[X86_RDI] & 0xFFFF;
    else if (strcmp(reg_name, "r8w") == 0) *out_value = regs[X86_R8] & 0xFFFF;
    else if (strcmp(reg_name, "r9w") == 0) *out_value = regs[X86_R9] & 0xFFFF;
    else if (strcmp(reg_name, "r10w") == 0) *out_value = regs[X86_R10] & 0xFFFF;
    else if (strcmp(reg_name, "r11w") == 0) *out_value = regs[X86_R11] & 0xFFFF;
    else if (strcmp(reg_name, "r12w") == 0) *out_value = regs[X86_R12] & 0xFFFF;
    else if (strcmp(reg_name, "r13w") == 0) *out_value = regs[X86_R13] & 0xFFFF;
    else if (strcmp(reg_name, "r14w") == 0) *out_value = regs[X86_R14] & 0xFFFF;
    else if (strcmp(reg_name, "r15w") == 0) *out_value = regs[X86_R15] & 0xFFFF;

    // 8-bit registers - low byte (AL, BL, CL, DL, SIL, DIL, SPL, BPL, R8B-R15B)
    else if (strcmp(reg_name, "al") == 0) *out_value = regs[X86_RAX] & 0xFF;
    else if (strcmp(reg_name, "cl") == 0) *out_value = regs[X86_RCX] & 0xFF;
    else if (strcmp(reg_name, "dl") == 0) *out_value = regs[X86_RDX] & 0xFF;
    else if (strcmp(reg_name, "bl") == 0) *out_value = regs[X86_RBX] & 0xFF;
    else if (strcmp(reg_name, "sil") == 0) *out_value = regs[X86_RSI] & 0xFF;
    else if (strcmp(reg_name, "dil") == 0) *out_value = regs[X86_RDI] & 0xFF;
    else if (strcmp(reg_name, "spl") == 0) *out_value = regs[X86_RSP] & 0xFF;
    else if (strcmp(reg_name, "bpl") == 0) *out_value = regs[X86_RBP] & 0xFF;
    else if (strcmp(reg_name, "r8b") == 0) *out_value = regs[X86_R8] & 0xFF;
    else if (strcmp(reg_name, "r9b") == 0) *out_value = regs[X86_R9] & 0xFF;
    else if (strcmp(reg_name, "r10b") == 0) *out_value = regs[X86_R10] & 0xFF;
    else if (strcmp(reg_name, "r11b") == 0) *out_value = regs[X86_R11] & 0xFF;
    else if (strcmp(reg_name, "r12b") == 0) *out_value = regs[X86_R12] & 0xFF;
    else if (strcmp(reg_name, "r13b") == 0) *out_value = regs[X86_R13] & 0xFF;
    else if (strcmp(reg_name, "r14b") == 0) *out_value = regs[X86_R14] & 0xFF;
    else if (strcmp(reg_name, "r15b") == 0) *out_value = regs[X86_R15] & 0xFF;

    // 8-bit registers - high byte (AH, BH, CH, DH)
    else if (strcmp(reg_name, "ah") == 0) *out_value = (regs[X86_RAX] >> 8) & 0xFF;
    else if (strcmp(reg_name, "ch") == 0) *out_value = (regs[X86_RCX] >> 8) & 0xFF;
    else if (strcmp(reg_name, "dh") == 0) *out_value = (regs[X86_RDX] >> 8) & 0xFF;
    else if (strcmp(reg_name, "bh") == 0) *out_value = (regs[X86_RBX] >> 8) & 0xFF;

    else return 0;  // Not found
    return 1;
}

#elif defined(SYMFIT_ARCH_ARM64)
// Helper: Read register for ARM64
static int read_register_arm64(const char *reg_name, CPUARMState *env, uint64_t *out_value) {
    uint64_t *regs = (uint64_t*)env->regs;

    // ARM64 uses x0-x30, sp, pc
    if (reg_name[0] == 'x' && reg_name[1] >= '0' && reg_name[1] <= '9') {
        int reg_num = atoi(&reg_name[1]);
        if (reg_num >= 0 && reg_num <= 30) {
            *out_value = regs[reg_num];
            return 1;
        }
    }
    else if (strcmp(reg_name, "sp") == 0) *out_value = regs[ARM64_SP];
    else if (strcmp(reg_name, "pc") == 0) *out_value = g_plugin->current_pc;
    else return 0;
    return 1;
}

#elif defined(SYMFIT_ARCH_RISCV)

// Helper: Read register for RISC-V
static int read_register_riscv(const char *reg_name, CPURISCVState *env, uint64_t *out_value) {
    uint64_t *regs = (uint64_t*)env->regs;

    // RISC-V registers: zero, ra, sp, gp, tp, t0-t6, s0-s11, a0-a7
    if (strcmp(reg_name, "zero") == 0) *out_value = regs[RISCV_ZERO];
    else if (strcmp(reg_name, "ra") == 0) *out_value = regs[RISCV_RA];
    else if (strcmp(reg_name, "sp") == 0) *out_value = regs[RISCV_SP];
    else if (strcmp(reg_name, "gp") == 0) *out_value = regs[RISCV_GP];
    else if (strcmp(reg_name, "tp") == 0) *out_value = regs[RISCV_TP];
    else if (strncmp(reg_name, "t", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 2) *out_value = regs[RISCV_T0 + num];
        else if (num >= 3 && num <= 6) *out_value = regs[RISCV_T3 + (num - 3)];
        else return 0;
    }
    else if (strncmp(reg_name, "s", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 1) *out_value = regs[RISCV_S0 + num];
        else if (num >= 2 && num <= 11) *out_value = regs[RISCV_S2 + (num - 2)];
        else return 0;
    }
    else if (strncmp(reg_name, "a", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 7) *out_value = regs[RISCV_A0 + num];
        else return 0;
    }
    else if (strcmp(reg_name, "pc") == 0) *out_value = g_plugin->current_pc;
    else return 0;
    return 1;
}
#endif

/**
 * ctx.readRegister(regName)
 * Read CPU register value (architecture-specific at compile time)
 * Returns the value as a BigInt, or undefined on error
 */
static JSValue js_read_register(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    if (argc < 1) {
        fprintf(stderr, "[Plugin] readRegister requires 1 argument (register name)\n");
        return JS_UNDEFINED;
    }

    if (!g_plugin || !g_plugin->cpu_env) {
        fprintf(stderr, "[Plugin] readRegister: no CPU state available\n");
        return JS_UNDEFINED;
    }

    const char *reg_name = JS_ToCString(ctx, argv[0]);
    if (!reg_name) {
        return JS_UNDEFINED;
    }

    // For register access, use cpu_env directly (architecture-specific state)
    void *env = g_plugin->cpu_env;
    uint64_t value = 0;
    int found = 0;

    // Use compile-time architecture selection
#ifdef SYMFIT_ARCH_X86
    CPUX86State *x86 = (CPUX86State *)env;
    found = read_register_x86(reg_name, x86, &value);
#elif defined(SYMFIT_ARCH_ARM64)
    CPUARMState *arm64 = (CPUARMState *)env;
    found = read_register_arm64(reg_name, arm64, &value);
#elif defined(SYMFIT_ARCH_RISCV)
    CPURISCVState *riscv = (CPURISCVState *)env;
    found = read_register_riscv(reg_name, riscv, &value);
#else
    fprintf(stderr, "[Plugin] readRegister: unsupported architecture\n");
#endif

    JS_FreeCString(ctx, reg_name);

    if (!found) {
        fprintf(stderr, "[Plugin] readRegister: unsupported register '%s'\n", reg_name);
        return JS_UNDEFINED;
    }

    printf("[Plugin Native] readRegister(%s) = 0x%lx\n", JS_ToCString(ctx, argv[0]), value);
    return JS_NewBigUint64(ctx, value);
}

#ifdef SYMFIT_ARCH_X86
// Helper: Write register for x86-64
static int write_register_x86(const char *reg_name, CPUX86State *env, uint64_t value) {
    uint64_t *regs = (uint64_t*)env->regs;

    // 64-bit registers (RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8-R15)
    if (strcmp(reg_name, "rax") == 0) regs[X86_RAX] = value;
    else if (strcmp(reg_name, "rcx") == 0) regs[X86_RCX] = value;
    else if (strcmp(reg_name, "rdx") == 0) regs[X86_RDX] = value;
    else if (strcmp(reg_name, "rbx") == 0) regs[X86_RBX] = value;
    else if (strcmp(reg_name, "rsp") == 0) regs[X86_RSP] = value;
    else if (strcmp(reg_name, "rbp") == 0) regs[X86_RBP] = value;
    else if (strcmp(reg_name, "rsi") == 0) regs[X86_RSI] = value;
    else if (strcmp(reg_name, "rdi") == 0) regs[X86_RDI] = value;
    else if (strcmp(reg_name, "r8") == 0) regs[X86_R8] = value;
    else if (strcmp(reg_name, "r9") == 0) regs[X86_R9] = value;
    else if (strcmp(reg_name, "r10") == 0) regs[X86_R10] = value;
    else if (strcmp(reg_name, "r11") == 0) regs[X86_R11] = value;
    else if (strcmp(reg_name, "r12") == 0) regs[X86_R12] = value;
    else if (strcmp(reg_name, "r13") == 0) regs[X86_R13] = value;
    else if (strcmp(reg_name, "r14") == 0) regs[X86_R14] = value;
    else if (strcmp(reg_name, "r15") == 0) regs[X86_R15] = value;
    else if (strcmp(reg_name, "rip") == 0) {
        fprintf(stderr, "[Plugin] writeRegister: cannot write to RIP\n");
        return 0;
    }

    // 32-bit registers (EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, R8D-R15D)
    // Writing to 32-bit register zero-extends to 64-bit
    else if (strcmp(reg_name, "eax") == 0) regs[X86_RAX] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ecx") == 0) regs[X86_RCX] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "edx") == 0) regs[X86_RDX] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ebx") == 0) regs[X86_RBX] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "esp") == 0) regs[X86_RSP] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "ebp") == 0) regs[X86_RBP] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "esi") == 0) regs[X86_RSI] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "edi") == 0) regs[X86_RDI] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r8d") == 0) regs[X86_R8] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r9d") == 0) regs[X86_R9] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r10d") == 0) regs[X86_R10] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r11d") == 0) regs[X86_R11] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r12d") == 0) regs[X86_R12] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r13d") == 0) regs[X86_R13] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r14d") == 0) regs[X86_R14] = value & 0xFFFFFFFF;
    else if (strcmp(reg_name, "r15d") == 0) regs[X86_R15] = value & 0xFFFFFFFF;

    // 16-bit registers (AX, BX, CX, DX, SI, DI, SP, BP, R8W-R15W)
    // Writing to 16-bit register preserves upper 48 bits
    else if (strcmp(reg_name, "ax") == 0) regs[X86_RAX] = (regs[X86_RAX] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "cx") == 0) regs[X86_RCX] = (regs[X86_RCX] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "dx") == 0) regs[X86_RDX] = (regs[X86_RDX] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "bx") == 0) regs[X86_RBX] = (regs[X86_RBX] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "sp") == 0) regs[X86_RSP] = (regs[X86_RSP] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "bp") == 0) regs[X86_RBP] = (regs[X86_RBP] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "si") == 0) regs[X86_RSI] = (regs[X86_RSI] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "di") == 0) regs[X86_RDI] = (regs[X86_RDI] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r8w") == 0) regs[X86_R8] = (regs[X86_R8] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r9w") == 0) regs[X86_R9] = (regs[X86_R9] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r10w") == 0) regs[X86_R10] = (regs[X86_R10] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r11w") == 0) regs[X86_R11] = (regs[X86_R11] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r12w") == 0) regs[X86_R12] = (regs[X86_R12] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r13w") == 0) regs[X86_R13] = (regs[X86_R13] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r14w") == 0) regs[X86_R14] = (regs[X86_R14] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);
    else if (strcmp(reg_name, "r15w") == 0) regs[X86_R15] = (regs[X86_R15] & 0xFFFFFFFFFFFF0000ULL) | (value & 0xFFFF);

    // 8-bit registers - low byte (AL, BL, CL, DL, SIL, DIL, SPL, BPL, R8B-R15B)
    // Writing to low byte preserves upper 56 bits
    else if (strcmp(reg_name, "al") == 0) regs[X86_RAX] = (regs[X86_RAX] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "cl") == 0) regs[X86_RCX] = (regs[X86_RCX] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "dl") == 0) regs[X86_RDX] = (regs[X86_RDX] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "bl") == 0) regs[X86_RBX] = (regs[X86_RBX] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "sil") == 0) regs[X86_RSI] = (regs[X86_RSI] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "dil") == 0) regs[X86_RDI] = (regs[X86_RDI] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "spl") == 0) regs[X86_RSP] = (regs[X86_RSP] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "bpl") == 0) regs[X86_RBP] = (regs[X86_RBP] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r8b") == 0) regs[X86_R8] = (regs[X86_R8] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r9b") == 0) regs[X86_R9] = (regs[X86_R9] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r10b") == 0) regs[X86_R10] = (regs[X86_R10] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r11b") == 0) regs[X86_R11] = (regs[X86_R11] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r12b") == 0) regs[X86_R12] = (regs[X86_R12] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r13b") == 0) regs[X86_R13] = (regs[X86_R13] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r14b") == 0) regs[X86_R14] = (regs[X86_R14] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);
    else if (strcmp(reg_name, "r15b") == 0) regs[X86_R15] = (regs[X86_R15] & 0xFFFFFFFFFFFFFF00ULL) | (value & 0xFF);

    // 8-bit registers - high byte (AH, BH, CH, DH)
    // Writing to high byte preserves bits [63:16] and [7:0]
    else if (strcmp(reg_name, "ah") == 0) regs[X86_RAX] = (regs[X86_RAX] & 0xFFFFFFFFFFFF00FFULL) | ((value & 0xFF) << 8);
    else if (strcmp(reg_name, "ch") == 0) regs[X86_RCX] = (regs[X86_RCX] & 0xFFFFFFFFFFFF00FFULL) | ((value & 0xFF) << 8);
    else if (strcmp(reg_name, "dh") == 0) regs[X86_RDX] = (regs[X86_RDX] & 0xFFFFFFFFFFFF00FFULL) | ((value & 0xFF) << 8);
    else if (strcmp(reg_name, "bh") == 0) regs[X86_RBX] = (regs[X86_RBX] & 0xFFFFFFFFFFFF00FFULL) | ((value & 0xFF) << 8);

    else return 0;
    return 1;
}

#elif defined(SYMFIT_ARCH_ARM64)
// Helper: Write register for ARM64
static int write_register_arm64(const char *reg_name, CPUARMState *env, uint64_t value) {
    uint64_t *regs = (uint64_t*)env->regs;

    if (reg_name[0] == 'x' && reg_name[1] >= '0' && reg_name[1] <= '9') {
        int reg_num = atoi(&reg_name[1]);
        if (reg_num >= 0 && reg_num <= 30) {
            regs[reg_num] = value;
            return 1;
        }
    }
    else if (strcmp(reg_name, "sp") == 0) regs[ARM64_SP] = value;
    else if (strcmp(reg_name, "pc") == 0) {
        fprintf(stderr, "[Plugin] writeRegister: cannot write to PC\n");
        return 0;
    }
    else return 0;
    return 1;
}

#elif defined(SYMFIT_ARCH_RISCV)
// Helper: Write register for RISC-V
static int write_register_riscv(const char *reg_name, CPURISCVState *env, uint64_t value) {
    uint64_t *regs = (uint64_t*)env->regs;

    if (strcmp(reg_name, "zero") == 0) {
        fprintf(stderr, "[Plugin] writeRegister: cannot write to zero register\n");
        return 0;
    }
    else if (strcmp(reg_name, "ra") == 0) regs[RISCV_RA] = value;
    else if (strcmp(reg_name, "sp") == 0) regs[RISCV_SP] = value;
    else if (strcmp(reg_name, "gp") == 0) regs[RISCV_GP] = value;
    else if (strcmp(reg_name, "tp") == 0) regs[RISCV_TP] = value;
    else if (strncmp(reg_name, "t", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 2) regs[RISCV_T0 + num] = value;
        else if (num >= 3 && num <= 6) regs[RISCV_T3 + (num - 3)] = value;
        else return 0;
    }
    else if (strncmp(reg_name, "s", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 1) regs[RISCV_S0 + num] = value;
        else if (num >= 2 && num <= 11) regs[RISCV_S2 + (num - 2)] = value;
        else return 0;
    }
    else if (strncmp(reg_name, "a", 1) == 0) {
        int num = atoi(&reg_name[1]);
        if (num >= 0 && num <= 7) regs[RISCV_A0 + num] = value;
        else return 0;
    }
    else if (strcmp(reg_name, "pc") == 0) {
        fprintf(stderr, "[Plugin] writeRegister: cannot write to PC\n");
        return 0;
    }
    else return 0;
    return 1;
}
#endif

/**
 * ctx.writeRegister(regName, value)
 * Write CPU register value (architecture-specific at compile time)
 * Returns true on success, false on error
 */
static JSValue js_write_register(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv) {
    if (argc < 2) {
        fprintf(stderr, "[Plugin] writeRegister requires 2 arguments (register name, value)\n");
        return JS_FALSE;
    }

    if (!g_plugin || !g_plugin->cpu_env) {
        fprintf(stderr, "[Plugin] writeRegister: no CPU state available\n");
        return JS_FALSE;
    }

    const char *reg_name = JS_ToCString(ctx, argv[0]);
    if (!reg_name) {
        return JS_FALSE;
    }

    // Get value (can be Number or BigInt)
    int64_t value_signed = 0;
    if (JS_IsBigInt(ctx, argv[1])) {
        JS_ToBigInt64(ctx, &value_signed, argv[1]);
    } else {
        int32_t value_int = 0;
        JS_ToInt32(ctx, &value_int, argv[1]);
        value_signed = value_int;
    }
    uint64_t value = (uint64_t)value_signed;

    // For register access, use cpu_env directly (architecture-specific state)
    void *env = g_plugin->cpu_env;
    int found = 0;

    // Use compile-time architecture selection
#ifdef SYMFIT_ARCH_X86
    CPUX86State *x86 = (CPUX86State *)env;
    found = write_register_x86(reg_name, x86, value);
#elif defined(SYMFIT_ARCH_ARM64)
    CPUARMState *arm64 = (CPUARMState *)env;
    found = write_register_arm64(reg_name, arm64, value);
#elif defined(SYMFIT_ARCH_RISCV)
    CPURISCVState *riscv = (CPURISCVState *)env;
    found = write_register_riscv(reg_name, riscv, value);
#else
    fprintf(stderr, "[Plugin] writeRegister: unsupported architecture\n");
#endif

    printf("[Plugin Native] writeRegister(%s, 0x%lx)\n", reg_name, value);
    JS_FreeCString(ctx, reg_name);

    return found ? JS_TRUE : JS_FALSE;
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
    fflush(stdout);  // Ensure output is displayed immediately
    return JS_UNDEFINED;
}

/**
 * ctx.addInstructionHook(address, callback)
 * Register a callback for a specific instruction address
 * Special value: 0xFFFFFFFFFFFFFFFF (-1n) = global hook for all instructions
 * Returns a hook handle (BigInt) that can be used to remove the hook
 */
static JSValue js_add_instruction_hook(JSContext *ctx, JSValue this_val,
                                        int argc, JSValue *argv) {
    if (argc < 2) {
        fprintf(stderr, "[Plugin] addInstructionHook requires 2 arguments (address, callback)\n");
        return JS_UNDEFINED;
    }

    if (!g_plugin || !g_plugin->instruction_hooks) {
        fprintf(stderr, "[Plugin] addInstructionHook: plugin not initialized\n");
        return JS_UNDEFINED;
    }

    // Get address (can be Number or BigInt)
    int64_t addr_signed = 0;
    if (JS_IsBigInt(ctx, argv[0])) {
        JS_ToBigInt64(ctx, &addr_signed, argv[0]);
    } else {
        int32_t addr_int = 0;
        JS_ToInt32(ctx, &addr_int, argv[0]);
        addr_signed = addr_int;
    }
    uint64_t pc = (uint64_t)addr_signed;

    // Check that second argument is a function
    if (!JS_IsFunction(ctx, argv[1])) {
        fprintf(stderr, "[Plugin] addInstructionHook: second argument must be a function\n");
        return JS_UNDEFINED;
    }

    InstructionHookEntry *entry = malloc(sizeof(InstructionHookEntry));
    if (!entry) {
        fprintf(stderr, "[Plugin] addInstructionHook: failed to allocate entry\n");
        return JS_UNDEFINED;
    }

    entry->pc = pc;
    entry->callback = JS_DupValue(ctx, argv[1]);
    entry->hook_id = g_plugin->next_hook_id++;

    // Check if this is a global hook (special value 0xFFFFFFFFFFFFFFFF)
    if (pc == GLOBAL_HOOK_PC) {
        // Add to global hook list
        entry->next = g_plugin->instruction_hooks->global_hook;
        g_plugin->instruction_hooks->global_hook = entry;

        printf("[Plugin Native] addInstructionHook(GLOBAL) -> handle %lu\n", entry->hook_id);
        return JS_NewBigUint64(ctx, entry->hook_id);
    }

    // Add to hook table for specific address
    uint32_t bucket = hash_pc(pc);
    entry->next = g_plugin->instruction_hooks->buckets[bucket];
    g_plugin->instruction_hooks->buckets[bucket] = entry;

    printf("[Plugin Native] addInstructionHook(0x%lx) -> handle %lu\n", pc, entry->hook_id);
    return JS_NewBigUint64(ctx, entry->hook_id);
}

/**
 * ctx.removeInstructionHook(handle)
 * Remove a specific hook using its handle (returned by addInstructionHook)
 * Returns true if the hook was found and removed, false otherwise
 */
static JSValue js_remove_instruction_hook(JSContext *ctx, JSValue this_val,
                                           int argc, JSValue *argv) {
    if (argc < 1) {
        fprintf(stderr, "[Plugin] removeInstructionHook requires 1 argument (hook handle)\n");
        return JS_FALSE;
    }

    if (!g_plugin || !g_plugin->instruction_hooks) {
        fprintf(stderr, "[Plugin] removeInstructionHook: plugin not initialized\n");
        return JS_FALSE;
    }

    // Get hook handle (must be BigInt)
    int64_t hook_id_signed = 0;
    if (JS_IsBigInt(ctx, argv[0])) {
        JS_ToBigInt64(ctx, &hook_id_signed, argv[0]);
    } else {
        int32_t hook_id_int = 0;
        JS_ToInt32(ctx, &hook_id_int, argv[0]);
        hook_id_signed = hook_id_int;
    }
    uint64_t hook_id = (uint64_t)hook_id_signed;

    // Search in global hooks
    InstructionHookEntry *entry = g_plugin->instruction_hooks->global_hook;
    InstructionHookEntry *prev = NULL;

    while (entry) {
        if (entry->hook_id == hook_id) {
            if (prev) {
                prev->next = entry->next;
            } else {
                g_plugin->instruction_hooks->global_hook = entry->next;
            }
            JS_FreeValue(ctx, entry->callback);
            free(entry);
            printf("[Plugin Native] removeInstructionHook(handle %lu) - global hook removed\n", hook_id);
            return JS_TRUE;
        }
        prev = entry;
        entry = entry->next;
    }

    // Search in all buckets for address-specific hooks
    for (int i = 0; i < HOOK_TABLE_SIZE; i++) {
        entry = g_plugin->instruction_hooks->buckets[i];
        prev = NULL;

        while (entry) {
            if (entry->hook_id == hook_id) {
                if (prev) {
                    prev->next = entry->next;
                } else {
                    g_plugin->instruction_hooks->buckets[i] = entry->next;
                }
                uint64_t pc = entry->pc;
                JS_FreeValue(ctx, entry->callback);
                free(entry);
                printf("[Plugin Native] removeInstructionHook(handle %lu) - removed hook at 0x%lx\n", hook_id, pc);
                return JS_TRUE;
            }
            prev = entry;
            entry = entry->next;
        }
    }

    printf("[Plugin Native] removeInstructionHook(handle %lu) - not found\n", hook_id);
    return JS_FALSE;
}

// === Helper: Create Context Object ===

static JSValue create_context_object(JSContext *ctx, SymFitPlugin *plugin) {
    JSValue obj = JS_NewObject(ctx);

    // Add PC
    JS_SetPropertyStr(ctx, obj, "pc", JS_NewBigUint64(ctx, plugin->current_pc));

    // Add readMemory function
    JSValue read_mem_fn = JS_NewCFunction(ctx, (void*)js_read_memory, "readMemory", 2);
    JS_SetPropertyStr(ctx, obj, "readMemory", read_mem_fn);

    // Add writeMemory function
    JSValue write_mem_fn = JS_NewCFunction(ctx, (void*)js_write_memory, "writeMemory", 3);
    JS_SetPropertyStr(ctx, obj, "writeMemory", write_mem_fn);

    // Add readRegister function
    JSValue read_reg_fn = JS_NewCFunction(ctx, (void*)js_read_register, "readRegister", 1);
    JS_SetPropertyStr(ctx, obj, "readRegister", read_reg_fn);

    // Add writeRegister function
    JSValue write_reg_fn = JS_NewCFunction(ctx, (void*)js_write_register, "writeRegister", 2);
    JS_SetPropertyStr(ctx, obj, "writeRegister", write_reg_fn);

    // Add addInstructionHook function
    JSValue add_hook_fn = JS_NewCFunction(ctx, (void*)js_add_instruction_hook, "addInstructionHook", 2);
    JS_SetPropertyStr(ctx, obj, "addInstructionHook", add_hook_fn);

    // Add removeInstructionHook function
    JSValue remove_hook_fn = JS_NewCFunction(ctx, (void*)js_remove_instruction_hook, "removeInstructionHook", 1);
    JS_SetPropertyStr(ctx, obj, "removeInstructionHook", remove_hook_fn);

    return obj;
}

// === Plugin Loading ===

void symfit_plugin_init(void) {
    printf("[SymFit] Plugin system initialized for architecture: %s\n", PLUGIN_ARCH);
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

    // Initialize instruction hooks table
    plugin->instruction_hooks = calloc(1, sizeof(InstructionHookTable));
    if (!plugin->instruction_hooks) {
        fprintf(stderr, "Failed to allocate instruction hooks table\n");
        JS_FreeContext(plugin->ctx);
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

    // Setup register name constants based on compile-time architecture
    JSValue registers = JS_NewObject(plugin->ctx);

#ifdef SYMFIT_ARCH_X86
            // x86-64 64-bit registers
            JS_SetPropertyStr(plugin->ctx, registers, "RAX", JS_NewString(plugin->ctx, "rax"));
            JS_SetPropertyStr(plugin->ctx, registers, "RBX", JS_NewString(plugin->ctx, "rbx"));
            JS_SetPropertyStr(plugin->ctx, registers, "RCX", JS_NewString(plugin->ctx, "rcx"));
            JS_SetPropertyStr(plugin->ctx, registers, "RDX", JS_NewString(plugin->ctx, "rdx"));
            JS_SetPropertyStr(plugin->ctx, registers, "RSI", JS_NewString(plugin->ctx, "rsi"));
            JS_SetPropertyStr(plugin->ctx, registers, "RDI", JS_NewString(plugin->ctx, "rdi"));
            JS_SetPropertyStr(plugin->ctx, registers, "RSP", JS_NewString(plugin->ctx, "rsp"));
            JS_SetPropertyStr(plugin->ctx, registers, "RBP", JS_NewString(plugin->ctx, "rbp"));
            JS_SetPropertyStr(plugin->ctx, registers, "R8", JS_NewString(plugin->ctx, "r8"));
            JS_SetPropertyStr(plugin->ctx, registers, "R9", JS_NewString(plugin->ctx, "r9"));
            JS_SetPropertyStr(plugin->ctx, registers, "R10", JS_NewString(plugin->ctx, "r10"));
            JS_SetPropertyStr(plugin->ctx, registers, "R11", JS_NewString(plugin->ctx, "r11"));
            JS_SetPropertyStr(plugin->ctx, registers, "R12", JS_NewString(plugin->ctx, "r12"));
            JS_SetPropertyStr(plugin->ctx, registers, "R13", JS_NewString(plugin->ctx, "r13"));
            JS_SetPropertyStr(plugin->ctx, registers, "R14", JS_NewString(plugin->ctx, "r14"));
            JS_SetPropertyStr(plugin->ctx, registers, "R15", JS_NewString(plugin->ctx, "r15"));
            JS_SetPropertyStr(plugin->ctx, registers, "RIP", JS_NewString(plugin->ctx, "rip"));

            // 32-bit registers
            JS_SetPropertyStr(plugin->ctx, registers, "EAX", JS_NewString(plugin->ctx, "eax"));
            JS_SetPropertyStr(plugin->ctx, registers, "EBX", JS_NewString(plugin->ctx, "ebx"));
            JS_SetPropertyStr(plugin->ctx, registers, "ECX", JS_NewString(plugin->ctx, "ecx"));
            JS_SetPropertyStr(plugin->ctx, registers, "EDX", JS_NewString(plugin->ctx, "edx"));
            JS_SetPropertyStr(plugin->ctx, registers, "ESI", JS_NewString(plugin->ctx, "esi"));
            JS_SetPropertyStr(plugin->ctx, registers, "EDI", JS_NewString(plugin->ctx, "edi"));
            JS_SetPropertyStr(plugin->ctx, registers, "ESP", JS_NewString(plugin->ctx, "esp"));
            JS_SetPropertyStr(plugin->ctx, registers, "EBP", JS_NewString(plugin->ctx, "ebp"));
            JS_SetPropertyStr(plugin->ctx, registers, "R8D", JS_NewString(plugin->ctx, "r8d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R9D", JS_NewString(plugin->ctx, "r9d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R10D", JS_NewString(plugin->ctx, "r10d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R11D", JS_NewString(plugin->ctx, "r11d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R12D", JS_NewString(plugin->ctx, "r12d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R13D", JS_NewString(plugin->ctx, "r13d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R14D", JS_NewString(plugin->ctx, "r14d"));
            JS_SetPropertyStr(plugin->ctx, registers, "R15D", JS_NewString(plugin->ctx, "r15d"));

            // 16-bit registers
            JS_SetPropertyStr(plugin->ctx, registers, "AX", JS_NewString(plugin->ctx, "ax"));
            JS_SetPropertyStr(plugin->ctx, registers, "BX", JS_NewString(plugin->ctx, "bx"));
            JS_SetPropertyStr(plugin->ctx, registers, "CX", JS_NewString(plugin->ctx, "cx"));
            JS_SetPropertyStr(plugin->ctx, registers, "DX", JS_NewString(plugin->ctx, "dx"));
            JS_SetPropertyStr(plugin->ctx, registers, "SI", JS_NewString(plugin->ctx, "si"));
            JS_SetPropertyStr(plugin->ctx, registers, "DI", JS_NewString(plugin->ctx, "di"));
            JS_SetPropertyStr(plugin->ctx, registers, "SP", JS_NewString(plugin->ctx, "sp"));
            JS_SetPropertyStr(plugin->ctx, registers, "BP", JS_NewString(plugin->ctx, "bp"));
            JS_SetPropertyStr(plugin->ctx, registers, "R8W", JS_NewString(plugin->ctx, "r8w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R9W", JS_NewString(plugin->ctx, "r9w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R10W", JS_NewString(plugin->ctx, "r10w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R11W", JS_NewString(plugin->ctx, "r11w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R12W", JS_NewString(plugin->ctx, "r12w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R13W", JS_NewString(plugin->ctx, "r13w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R14W", JS_NewString(plugin->ctx, "r14w"));
            JS_SetPropertyStr(plugin->ctx, registers, "R15W", JS_NewString(plugin->ctx, "r15w"));

            // 8-bit registers - low byte
            JS_SetPropertyStr(plugin->ctx, registers, "AL", JS_NewString(plugin->ctx, "al"));
            JS_SetPropertyStr(plugin->ctx, registers, "BL", JS_NewString(plugin->ctx, "bl"));
            JS_SetPropertyStr(plugin->ctx, registers, "CL", JS_NewString(plugin->ctx, "cl"));
            JS_SetPropertyStr(plugin->ctx, registers, "DL", JS_NewString(plugin->ctx, "dl"));
            JS_SetPropertyStr(plugin->ctx, registers, "SIL", JS_NewString(plugin->ctx, "sil"));
            JS_SetPropertyStr(plugin->ctx, registers, "DIL", JS_NewString(plugin->ctx, "dil"));
            JS_SetPropertyStr(plugin->ctx, registers, "SPL", JS_NewString(plugin->ctx, "spl"));
            JS_SetPropertyStr(plugin->ctx, registers, "BPL", JS_NewString(plugin->ctx, "bpl"));
            JS_SetPropertyStr(plugin->ctx, registers, "R8B", JS_NewString(plugin->ctx, "r8b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R9B", JS_NewString(plugin->ctx, "r9b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R10B", JS_NewString(plugin->ctx, "r10b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R11B", JS_NewString(plugin->ctx, "r11b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R12B", JS_NewString(plugin->ctx, "r12b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R13B", JS_NewString(plugin->ctx, "r13b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R14B", JS_NewString(plugin->ctx, "r14b"));
            JS_SetPropertyStr(plugin->ctx, registers, "R15B", JS_NewString(plugin->ctx, "r15b"));

            // 8-bit registers - high byte
            JS_SetPropertyStr(plugin->ctx, registers, "AH", JS_NewString(plugin->ctx, "ah"));
            JS_SetPropertyStr(plugin->ctx, registers, "BH", JS_NewString(plugin->ctx, "bh"));
            JS_SetPropertyStr(plugin->ctx, registers, "CH", JS_NewString(plugin->ctx, "ch"));
            JS_SetPropertyStr(plugin->ctx, registers, "DH", JS_NewString(plugin->ctx, "dh"));

#elif defined(SYMFIT_ARCH_ARM64)
            // ARM64 registers (x0-x30, sp, pc)
            for (int i = 0; i <= 30; i++) {
                char key[8], val[8];
                snprintf(key, sizeof(key), "X%d", i);
                snprintf(val, sizeof(val), "x%d", i);
                JS_SetPropertyStr(plugin->ctx, registers, key, JS_NewString(plugin->ctx, val));
            }
            JS_SetPropertyStr(plugin->ctx, registers, "SP", JS_NewString(plugin->ctx, "sp"));
            JS_SetPropertyStr(plugin->ctx, registers, "PC", JS_NewString(plugin->ctx, "pc"));

#elif defined(SYMFIT_ARCH_RISCV)
            // RISC-V registers
            JS_SetPropertyStr(plugin->ctx, registers, "ZERO", JS_NewString(plugin->ctx, "zero"));
            JS_SetPropertyStr(plugin->ctx, registers, "RA", JS_NewString(plugin->ctx, "ra"));
            JS_SetPropertyStr(plugin->ctx, registers, "SP", JS_NewString(plugin->ctx, "sp"));
            JS_SetPropertyStr(plugin->ctx, registers, "GP", JS_NewString(plugin->ctx, "gp"));
            JS_SetPropertyStr(plugin->ctx, registers, "TP", JS_NewString(plugin->ctx, "tp"));

            // Temporary registers t0-t6
            for (int i = 0; i <= 6; i++) {
                char key[8], val[8];
                snprintf(key, sizeof(key), "T%d", i);
                snprintf(val, sizeof(val), "t%d", i);
                JS_SetPropertyStr(plugin->ctx, registers, key, JS_NewString(plugin->ctx, val));
            }

            // Saved registers s0-s11
            for (int i = 0; i <= 11; i++) {
                char key[8], val[8];
                snprintf(key, sizeof(key), "S%d", i);
                snprintf(val, sizeof(val), "s%d", i);
                JS_SetPropertyStr(plugin->ctx, registers, key, JS_NewString(plugin->ctx, val));
            }

            // Argument registers a0-a7
            for (int i = 0; i <= 7; i++) {
                char key[8], val[8];
                snprintf(key, sizeof(key), "A%d", i);
                snprintf(val, sizeof(val), "a%d", i);
                JS_SetPropertyStr(plugin->ctx, registers, key, JS_NewString(plugin->ctx, val));
            }

            JS_SetPropertyStr(plugin->ctx, registers, "PC", JS_NewString(plugin->ctx, "pc"));

#else
            fprintf(stderr, "[SymFit] Warning: Unknown architecture, register constants not set\n");
#endif

    JS_SetPropertyStr(plugin->ctx, global, "Registers", registers);

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
    plugin->on_start_execution_fn = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onStartExecution");

    // Set g_plugin before calling onInit so that addInstructionHook can work
    g_plugin = plugin;

    // Call onInit if present (with context object so plugins can register hooks)
    JSValue on_init = JS_GetPropertyStr(plugin->ctx, plugin->plugin_obj, "onInit");
    if (JS_IsFunction(plugin->ctx, on_init)) {
        printf("[SymFit] Calling plugin.onInit()\n");

        // Create a context object for onInit
        JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
        JSValue init_result = JS_Call(plugin->ctx, on_init, plugin->plugin_obj, 1, &ctx_obj);
        if (JS_IsException(init_result)) {
            js_std_dump_error(plugin->ctx);
        }
        JS_FreeValue(plugin->ctx, init_result);
        JS_FreeValue(plugin->ctx, ctx_obj);
    }
    JS_FreeValue(plugin->ctx, on_init);

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
    JS_FreeValue(plugin->ctx, plugin->on_start_execution_fn);

    // Free instruction hooks
    if (plugin->instruction_hooks) {
        // Free address-specific hooks
        for (int i = 0; i < HOOK_TABLE_SIZE; i++) {
            InstructionHookEntry *entry = plugin->instruction_hooks->buckets[i];
            while (entry) {
                InstructionHookEntry *next = entry->next;
                JS_FreeValue(plugin->ctx, entry->callback);
                free(entry);
                entry = next;
            }
        }
        // Free global hooks
        InstructionHookEntry *entry = plugin->instruction_hooks->global_hook;
        while (entry) {
            InstructionHookEntry *next = entry->next;
            JS_FreeValue(plugin->ctx, entry->callback);
            free(entry);
            entry = next;
        }
        free(plugin->instruction_hooks);
    }

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
                                    void *env,
                                    uint64_t addr,
                                    uint32_t size,
                                    uint64_t value) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->on_memory_write_fn)) {
        return;
    }
    plugin->cpu_env = env;

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
                                      void *cpu_env,
                                      int syscall_num,
                                      uint64_t args[6],
                                      int64_t ret_val,
                                      const uint8_t *buffer,
                                      size_t buffer_len) {
    if (!plugin || !JS_IsFunction(plugin->ctx, plugin->on_syscall_return_fn)) {
        return;
    }

    plugin->cpu_env = cpu_env;

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

void symfit_plugin_on_instruction(SymFitPlugin *plugin,
                                    void *cpu_env,
                                    uint64_t pc) {
    if (!plugin) {
        return;
    }

    plugin->cpu_env = cpu_env;
    plugin->current_pc = pc;

    if (plugin->instruction_hooks) {
        // Call ALL global hooks first
        InstructionHookEntry *global_entry = plugin->instruction_hooks->global_hook;
        while (global_entry) {
            plugin->callback_count++;

            // Duplicate the callback before calling it, in case the callback removes the hook
            JSValue callback = JS_DupValue(plugin->ctx, global_entry->callback);
            JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
            JSValue result = JS_Call(plugin->ctx, callback,
                                   JS_UNDEFINED, 1, &ctx_obj);
            if (JS_IsException(result)) {
                fprintf(stderr, "[SymFit] Error in global instruction hook at 0x%lx:\n", pc);
                js_std_dump_error(plugin->ctx);
            }
            JS_FreeValue(plugin->ctx, result);
            JS_FreeValue(plugin->ctx, ctx_obj);
            JS_FreeValue(plugin->ctx, callback);

            global_entry = global_entry->next;
        }

        // Call ALL address-specific hooks for this PC
        uint32_t bucket = hash_pc(pc);
        InstructionHookEntry *entry = plugin->instruction_hooks->buckets[bucket];

        while (entry) {
            if (entry->pc == pc) {
                // Found a selective hook for this PC
                plugin->callback_count++;

                // Duplicate the callback before calling it, in case the callback removes the hook
                JSValue callback = JS_DupValue(plugin->ctx, entry->callback);
                JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
                JSValue result = JS_Call(plugin->ctx, callback,
                                       JS_UNDEFINED, 1, &ctx_obj);
                if (JS_IsException(result)) {
                    fprintf(stderr, "[SymFit] Error in selective instruction hook at 0x%lx:\n", pc);
                    js_std_dump_error(plugin->ctx);
                }
                JS_FreeValue(plugin->ctx, result);
                JS_FreeValue(plugin->ctx, ctx_obj);
                JS_FreeValue(plugin->ctx, callback);
            }
            entry = entry->next;
        }
    }
}

void symfit_plugin_on_start_execution(SymFitPlugin *plugin,
                                       void *cpu_env) {
    if (!plugin || plugin->execution_started) {
        return;
    }

    plugin->execution_started = 1;
    plugin->cpu_env = cpu_env;

    if (!JS_IsFunction(plugin->ctx, plugin->on_start_execution_fn)) {
        return;
    }

    printf("[SymFit] Calling plugin.onStartExecution()\n");
    plugin->callback_count++;

    JSValue ctx_obj = create_context_object(plugin->ctx, plugin);
    JSValue result = JS_Call(plugin->ctx, plugin->on_start_execution_fn,
                             plugin->plugin_obj, 1, &ctx_obj);

    if (JS_IsException(result)) {
        fprintf(stderr, "[SymFit] Error in onStartExecution:\n");
        js_std_dump_error(plugin->ctx);
    }

    JS_FreeValue(plugin->ctx, result);
    JS_FreeValue(plugin->ctx, ctx_obj);
}


