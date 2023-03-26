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
        asm("push %r8");  \
        asm("push %r9");  \
        asm("push %r10"); \
        asm("push %r11"); 
#define POP_REGS          \
        asm("pop %r11");  \
        asm("pop %r10");  \
        asm("pop %r9");   \
        asm("pop %r8");
#include "dfsan_interface.h"
// shadow mask for x86_64.
static const uint64_t kShadowMask = ~0x700000000000;
static inline void *shadow_for_pg_start(void *ptr) {
  return (void *) (((((uint64_t) ptr) & kShadowMask) << 2) & TARGET_PAGE_MASK);
}
static inline void *shadow_for(uint64_t ptr) {
  return (void *) (((ptr) & kShadowMask) << 2);
}
#define PAGE_START(addr) ((uint64_t)(addr) & TARGET_PAGE_MASK)
#define PAGE_END(addr) PAGE_START(addr) + TARGET_PAGE_SIZE
static inline size_t sizeof_tlb(CPUArchState *env, uintptr_t mmu_idx)
{
    return env_tlb(env)->f[mmu_idx].mask + (1 << CPU_TLB_ENTRY_BITS);
}

// Set optimization level to O0 to avoid compiler optimizing the inlined function call.
void __attribute__((optimize("O0"))) helper_sym_load(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    SAVE_REGS;
    // void *addr_expr = (void *)env->addr_expr;
    uint64_t load_length = 1 << ((oi >> 4) & MO_SIZE);
    int mmu_idx = 1;
    CPUTLBEntry *te;

    void *host_addr = g2h(addr);
    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, load_length);

    env->val_expr = res_label;
    // fprintf(stderr, "load addr: %p memory expr: %ld, env->val_expr: 0x%lx, load_length %ld\n",
    //                host_addr, res_label, env->val_expr, load_length);
    target_ulong vaddr_page = addr & TARGET_PAGE_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_PAGE_SIZE*4)) {
    // if (dfsan_concrete_page(host_addr)) {
        assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }
    POP_REGS;
}

/* TODO: for the load and store function, we can directly pass paddr as an argument to avoid compute the paddr */
//void __attribute__((optimize("O0"))) helper_check_sym_load(CPUArchState *env, target_ulong addr, uint32_t oi,
void __attribute__((optimize("O0"))) helper_check_sym_load(CPUArchState *env, target_ulong addr, uint32_t oi,
                                       uintptr_t retaddr)
{
    /* The last two arguments are never used */
    SAVE_REGS;
    
    uint64_t length = 1 << ((oi >> 4) & MO_SIZE);
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);

    //printf("host addr %lx %p %p\n", addr, (uint8_t*)host_addr, host_addr);
    //void *memory_expr = _sym_read_memory((uint8_t*)host_addr, length, true);
    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, length);

    vaddr_page = addr & TARGET_PAGE_MASK;
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
    if (res_label != 0)
    fprintf(stderr, "concrete load miss %p memory expr %ld\n", 
                host_addr, res_label);
    
    // Pass for corss-page access.
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_PAGE_SIZE*4)) {
    // if (dfsan_concrete_page(host_addr)) {
        if ((addr&0xfff)+length <= 0x1000)
            assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }

    
    POP_REGS;
    /*
        TODO: handle symbolic mode so that symbolic mode can benefit from concrete tlb
        but it's not easy to do that here because:
        - it needs to pass shadow temps as arguments
        - it needs to access and modify shadow temps, which is in the translation frontend. 
    */
}

void __attribute__((optimize("O0"))) helper_sym_store(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    SAVE_REGS;
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    uint64_t length = 1 << ((oi >> 4) & MO_SIZE);
    // fprintf(stderr, "symbolic store miss 0x%lx val_expr %ld\n", addr, env->val_expr);

    void *host_addr = g2h(addr);
    dfsan_store_label(env->val_expr, (uint8_t*)host_addr, length);

    vaddr_page = addr & TARGET_PAGE_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);

    if (env->val_expr) {
        te->addr_read = -1;
    } else {
        if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_PAGE_SIZE*4)) {
        // if (dfsan_concrete_page(host_addr)) {
            // Should not enable this assert since we nullify the target address.
            if ((addr&0xfff)+length <= 0x1000 && env->val_expr == 0)
                assert(te->addr_read!=vaddr_page);
            te->addr_read = vaddr_page;
        } else {
            te->addr_read = -1;
        }
    }
    
    POP_REGS;
}

void __attribute__((optimize("O0"))) helper_check_sym_store(CPUArchState *env, target_ulong addr, uint32_t oi)
{
    SAVE_REGS;
    /* set mmu_idx to one, we only need one type of access */
    int mmu_idx = 1;
    CPUTLBEntry *te;
    target_ulong vaddr_page;
    
    uint64_t length = 1 << ((oi >> 4) & MO_SIZE);
    //fprintf(stderr, "concrete store miss 0x%lx, length 0x%lx\n", addr, length);
    void *host_addr = g2h(addr);
    /* nullify the target address */
    dfsan_store_label(0, (uint8_t*)host_addr, length);

    vaddr_page = addr & TARGET_PAGE_MASK;
    te = tlb_entry(env, mmu_idx, vaddr_page);
    // Pass for corss-page access.
    if (buffer_is_zero(shadow_for(PAGE_START(host_addr)), TARGET_PAGE_SIZE*4)) {
    // if (dfsan_concrete_page(host_addr)) {
        // Should not enable this assert since we nullify the target address.
        if ((addr&0xfff)+length <= 0x1000)
            assert(te->addr_read!=vaddr_page);
        te->addr_read = vaddr_page;
    } else {
        te->addr_read = -1;
    }

    POP_REGS;
}
tcg_target_ulong helperdebug(target_ulong addr)
{
    //if (addr == 0x4000804dd0)
    printf("tlb hit 0x%lx\n", addr);
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
