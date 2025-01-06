#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/cpu_ldst.h"
#include "exec/cputlb.h"
#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "tcg/tcg.h"
#include "qemu/error-report.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "qemu/atomic.h"
#include "qemu/atomic128.h"
#include "exec/cpu_ldst.h"
#include "qemu/cutils.h"
extern CPUArchState *global_env;

#define SAVE_ALL_REGS     \
        asm("push %rax");  \
        asm("push %rbx");  \
        asm("push %rcx");  \
        asm("push %rdx");  \
        asm("push %rsi");  \
        asm("push %rdi");  \
        asm("push %rbp");  \
        asm("push %rsp");  \
        asm("push %r8");  \
        asm("push %r9");  \
        asm("push %r10"); \
        asm("push %r11"); \
        asm("push %r12"); \
        asm("push %r13"); \
        asm("push %r14"); \
        asm("push %r15");

#define POP_ALL_REGS       \
        asm("pop %r15");  \
        asm("pop %r14");  \
        asm("pop %r13");  \
        asm("pop %r12");  \
        asm("pop %r11");  \
        asm("pop %r10");  \
        asm("pop %r9");  \
        asm("pop %r8");  \
        asm("pop %rsp");  \
        asm("pop %rbp");  \
        asm("pop %rdi");  \
        asm("pop %rsi");  \
        asm("pop %rdx");  \
        asm("pop %rcx");  \
        asm("pop %rbx");  \
        asm("pop %rax");

#define TEST_SAVE
        asm("push %rax");  \
        asm("push %rbx");  \
        asm("push %rcx");  \
        asm("push %rdx");  \
        asm("push %rsi");  \
        asm("push %rdi");  \
        asm("push %rbp");  \
        asm("push %rsp");  \
        asm("push %r8");  \
        asm("push %r9");  \
        asm("push %r10"); \
        asm("push %r11"); \
        asm("push %r12"); \
        asm("push %r13"); \
        asm("push %r14"); \
        asm("push %r15");

#define TEST_POP
        asm("pop %r15");  \
        asm("pop %r14");  \
        asm("pop %r13");  \
        asm("pop %r12");  \
        asm("pop %r11");  \
        asm("pop %r10");  \
        asm("pop %r9");  \
        asm("pop %r8");  \
        asm("pop %rsp");  \
        asm("pop %rbp");  \
        asm("pop %rdi");  \
        asm("pop %rsi");  \
        asm("pop %rdx");  \
        asm("pop %rcx");  \
        asm("pop %rbx");  \
        asm("pop %rax");

#define SAVE_REGS         \
        asm("push %r10"); \
        asm("push %r11"); 
#define POP_REGS          \
        asm("pop %r11");  \
        asm("pop %r10");
#define TARGET_1024_SIZE (1 << TARGET_1024_BITS)

#define TARGET_1024_MASK ~(TARGET_1024_SIZE - 1)
#include "dfsan_interface.h"
// shadow mask for x86_64.
static const uint64_t kShadowMask = ~0x700000000000;
static inline void *shadow_for_pg_start(void *ptr) {
  return (void *) (((((uint64_t) ptr) & kShadowMask) << 2) & TARGET_PAGE_MASK);
}
static inline void *shadow_for(uint64_t ptr) {
  return (void *) (((ptr) & kShadowMask) << 2);
}
#define PAGE_START(addr) ((uint64_t)(addr) & TARGET_1024_MASK)
// #define PAGE_END(addr) PAGE_START(addr) + TARGET_PAGE_SIZE
static inline size_t sizeof_tlb(CPUArchState *env, uintptr_t mmu_idx)
{
    return env_tlb(env)->f[mmu_idx].mask + (1 << CPU_TLB_ENTRY_BITS);
}

// static bool cross_page_access(target_ulong addr, uint64_t size) {
//     if (((addr + size) & TARGET_1024_MASK) == (addr & TARGET_1024_MASK)) {
//         return false;
//     } else {
//         return true;
//     }
// }

static inline void __attribute__((always_inline))
sym_ld_helper(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    uint64_t load_length = 1 << ((oi >> 4) & MO_SIZE);
    int mmu_idx = 1;
    CPUTLBEntry *te;

    void *host_addr = g2h(addr);
    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, load_length);

    env->val_expr = res_label;
    // if (res_label) {
    //     fprintf(stderr, "sym load 0x%lx size 0x%lx\n", env->eip, load_length);
    // }
    // fprintf(stderr, "load addr: %p memory expr: %ld, env->val_expr: 0x%lx, load_length %ld\n",
                //    host_addr, res_label, env->val_expr, load_length);
    target_ulong vaddr_page = addr & TARGET_1024_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_1024_SIZE*4)) {
        // fprintf(stderr, "load addr_read 0x%p vaddr_page: 0x%lx addr_read: 0x%lx\n", te, vaddr_page, te->addr_read);
        // if (!cross_page_access(addr, load_length))
            // assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }

}

static inline void __attribute__((always_inline))
check_ld_helper(CPUArchState *env, target_ulong addr, uint32_t oi, uintptr_t retaddr)
{
    uint64_t length = 1 << ((oi >> 4) & MO_SIZE);
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    void *host_addr = g2h(addr);
    // assert((uintptr_t)host_addr >= 0x700000040000);

    //printf("host addr %lx %p %p\n", addr, (uint8_t*)host_addr, host_addr);
    //void *memory_expr = _sym_read_memory((uint8_t*)host_addr, length, true);
    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, length);

    vaddr_page = addr & TARGET_1024_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);
    if (res_label) {
        /* Set flag and raise exception */
        // fprintf(stderr, "switch to symbolic mode 0x%lx\n", addr);
        second_ccache_flag = 1;
        //memset(env_tlb(env)->f[mmu_idx].table, -1, sizeof_tlb(env, mmu_idx));
        te->addr_read = -1;
        POP_REGS;
        raise_exception_err_ra(env, EXCP_SWITCH, 0, retaddr);
        assert(0);
    }
    // fprintf(stderr, "check_load_guest\n");
    
    // Pass for corss-page access.
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_1024_SIZE*4)) {
            // fprintf(stderr, "load addr_read 0x%lx vaddr_page: 0x%lx addr: 0x%lx\n", te->addr_read, vaddr_page, addr);
    // if (dfsan_concrete_page(host_addr)) {
        // if (!cross_page_access(addr, length))
            // assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }
}

// Avoid compiler optimization.
static void dummy_ld_helper(CPUArchState *env, target_ulong addr, uint32_t oi,
                                       uintptr_t retaddr)
{
    if (retaddr == 0)
        sym_ld_helper(env, addr, oi);
    else
        check_ld_helper(env, addr, oi, retaddr);
}

void helper_sym_load(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    SAVE_REGS;
    dummy_ld_helper(env, addr, oi, 0);
    POP_REGS;
}

void
helper_check_sym_load(CPUArchState *env, target_ulong addr, uint32_t oi,
                                       uintptr_t retaddr)
{
    SAVE_REGS;
    // fprintf(stderr, "helper_check_sym_load 0x%lx\n", addr);
    dummy_ld_helper(env, addr, oi, retaddr);
    POP_REGS;
}
// Set optimization level to O0 to avoid compiler optimizing the inlined function call.
static inline void __attribute__((always_inline))
sym_st_helper(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    uint64_t length = 1 << (get_memop(oi) & MO_SIZE);
    // fprintf(stderr, "symbolic store miss 0x%lx val_expr %ld\n", addr, env->val_expr);

    void *host_addr = g2h(addr);
    dfsan_store_label(env->val_expr, (uint8_t*)host_addr, length);

    vaddr_page = addr & TARGET_1024_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);

    if (env->val_expr) {
        // fprintf(stderr, "memop 0x%x\n", oi);
        // fprintf(stderr, "sym write guest 0x%lx size 0x%lx\n", env->eip, length);
        te->addr_read = -1;
    } else {
        // fprintf(stderr, "null write guest 0x%lx\n", global_env->eip);
        if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_1024_SIZE*4)) {
        // if (dfsan_concrete_page(host_addr)) {
            // Should not enable this assert since we nullify the target address.
            // if (!cross_page_access(addr, length) && env->val_expr == 0)
                // assert(te->addr_read!=vaddr_page);
            te->addr_read = vaddr_page;
        } else {
            te->addr_read = -1;
        }
    }
}
static inline void __attribute__((always_inline))
check_st_helper(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    
    uint64_t length = 1 << ((oi >> 4) & MO_SIZE);
    //fprintf(stderr, "concrete store miss 0x%lx, length 0x%lx\n", addr, length);
    void *host_addr = g2h(addr);
    /* nullify the target address */
    dfsan_store_label(0, (uint8_t*)host_addr, length);

    // assert(env->val_expr == 0);

    vaddr_page = addr & TARGET_1024_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);
    // Pass for corss-page access.
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_1024_SIZE*4)) {
    // if (dfsan_concrete_page(host_addr)) {
        // Should not enable this assert since we nullify the target address.
        // fprintf(stderr, "store addr_read 0x%p vaddr_page: 0x%lx addr: 0x%lx\n", te, vaddr_page, addr);
        // if (!cross_page_access(addr, length))
            // assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }
    // fprintf(stderr, "check_store_guest\n");
}

static void dummy_st_helper(CPUArchState *env, target_ulong addr, uint32_t oi, int symbolic)
{
    if (symbolic) {
        sym_st_helper(env, addr, oi);
    } else {
        check_st_helper(env, addr, oi);
    }
}

void helper_check_sym_store(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    SAVE_REGS;
    dummy_st_helper(env, addr, oi, 0);
    POP_REGS;
}

void helper_sym_store(CPUArchState *env, target_ulong addr, uint32_t oi) {
    SAVE_REGS;
    dummy_st_helper(env, addr, oi, 1);
    POP_REGS;
}

tcg_target_ulong helperdebug(target_ulong addr, target_ulong addr2)
{
    // if ((addr & 0xfff) == 0x5f8) {
        // fprintf(stderr, "tlb hit 0x%lx\n", addr);
        // uint64_t *te = (uint64_t *)addr;
        fprintf(stderr, "addr read 0x%lx vaddr 0x%lx\n", addr, addr2);
    // }
    /*FILE *log = fopen("output", "a");
    fprintf(log, "tlb hit 0x%lx\n", addr);
    fclose(log);*/
    return 0;

}
tcg_target_ulong helper_test(void) {
    // SAVE_REGS;
    //asm("nop");
    fprintf(stderr, "clb hit\n");
    // POP_REGS;
    return 0;
}
