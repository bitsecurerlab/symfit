#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg.h"

#include "dfsan_interface.h"
#define CONST_LABEL 0

#define UNIMPLEMENTED_HELPER(opcode)                \
        char op[] = opcode;                         \
        dfsan_unimplemented(op);                    \
        return 0;

#define BINARY_HELPER_ENSURE_EXPRESSIONS                                            \
    if (arg1_label == 0 && arg2_label == 0) {                                       \
        return 0;                                                                   \
    }

#define DECL_HELPER_BINARY(name, bit)                                                 \
    uint64_t HELPER(symsan_##name##_i##bit)(uint##bit##_t arg1, uint64_t arg1_label,  \
                                            uint##bit##_t arg2, uint64_t arg2_label)

#define DEF_HELPER_BINARY(qemu_name, symsan_name, bit)                              \
    DECL_HELPER_BINARY(qemu_name, bit) {                                            \
        BINARY_HELPER_ENSURE_EXPRESSIONS;                                           \
        return dfsan_union(arg1_label, arg2_label, symsan_name, bit, arg1, arg2);   \
    }

/* The binary helpers */
DEF_HELPER_BINARY(add, Add, 32)
DEF_HELPER_BINARY(sub, Sub, 32)
DEF_HELPER_BINARY(mul, Mul, 32)
DEF_HELPER_BINARY(div, SDiv, 32)
DEF_HELPER_BINARY(divu, UDiv, 32)
DEF_HELPER_BINARY(rem, SRem, 32)
DEF_HELPER_BINARY(remu, URem, 32)
DEF_HELPER_BINARY(and, And, 32)
DEF_HELPER_BINARY(or, Or, 32)
DEF_HELPER_BINARY(xor, Xor, 32)
DEF_HELPER_BINARY(shift_right, LShr, 32)
DEF_HELPER_BINARY(arithmetic_shift_right, AShr, 32)
DEF_HELPER_BINARY(shift_left, Shl, 32)

DEF_HELPER_BINARY(add, Add, 64)
DEF_HELPER_BINARY(sub, Sub, 64)
DEF_HELPER_BINARY(mul, Mul, 64)
DEF_HELPER_BINARY(div, SDiv, 64)
DEF_HELPER_BINARY(divu, UDiv, 64)
DEF_HELPER_BINARY(rem, SRem, 64)
DEF_HELPER_BINARY(remu, URem, 64)
DEF_HELPER_BINARY(and, And, 64)
DEF_HELPER_BINARY(or, Or, 64)
DEF_HELPER_BINARY(xor, Xor, 64)
DEF_HELPER_BINARY(shift_right, LShr, 64)
DEF_HELPER_BINARY(arithmetic_shift_right, AShr, 64)
DEF_HELPER_BINARY(shift_left, Shl, 64)

DECL_HELPER_BINARY(rotate_left, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("rotate_left32")
}
DECL_HELPER_BINARY(rotate_left, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("rotate_left64")
}
DECL_HELPER_BINARY(rotate_right, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("rotate_right32")
}
DECL_HELPER_BINARY(rotate_right, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("rotate_right64")
}

DECL_HELPER_BINARY(nand, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("nand32")
}
DECL_HELPER_BINARY(nand, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("nand64")
}

DECL_HELPER_BINARY(nor, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("nor32")
}
DECL_HELPER_BINARY(nor, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("nor64")
}

DECL_HELPER_BINARY(orc, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("orc32")
}
DECL_HELPER_BINARY(orc, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("orc64")
}

/* andc support */
DECL_HELPER_BINARY(andc, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("andc32")
    uint64_t arg2_new_label = 
        dfsan_union(arg2_label, CONST_LABEL, Not, 32, arg2, 0);

    return dfsan_union(arg1_label, arg2_new_label, And, 32, arg1, arg2);
}
DECL_HELPER_BINARY(andc, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("andc64")
    uint64_t arg2_new_label = 
        dfsan_union(arg2_label, CONST_LABEL, Not, 64, arg2, 0);

    return dfsan_union(arg1_label, arg2_new_label, And, 64, arg1, arg2);
}
/* eqv support */
DECL_HELPER_BINARY(eqv, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("eqv32")
    uint64_t new_label = dfsan_union(arg1_label, arg2_label, Xor, 32, arg1, arg2);
    return dfsan_union(new_label, CONST_LABEL, Not, 32, 0, 0);
}

DECL_HELPER_BINARY(eqv, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("eqv64")
    uint64_t new_label = dfsan_union(arg1_label, arg2_label, Xor, 64, arg1, arg2);
    return dfsan_union(new_label, CONST_LABEL, Not, 64, 0, 0);
}

uint64_t HELPER(symsan_neg_i32)(uint32_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    /* for unary operator Neg/Not, leave the first op as 0 */
    uint64_t res = dfsan_union(CONST_LABEL, label, Neg, 32, 0, op1);
    return res;
}
uint64_t HELPER(symsan_neg_i64)(uint64_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    uint64_t res = dfsan_union(CONST_LABEL, label, Neg, 64, 0, op1);
    return res;
}

uint64_t HELPER(symsan_not_i32)(uint32_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    uint64_t res = dfsan_union(CONST_LABEL, label, Not, 32, 0, op1);
    return res;
}
uint64_t HELPER(symsan_not_i64)(uint64_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    uint64_t res = dfsan_union(CONST_LABEL, label, Not, 64, 0, op1);
    return res;
}

uint64_t HELPER(symsan_muluh_i64)(uint64_t arg1, uint64_t arg1_label,
                                  uint64_t arg2, uint64_t arg2_label)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    UNIMPLEMENTED_HELPER("muluh32")
}

/* z/sext_i32/64 is not real ext operation. */
uint64_t HELPER(symsan_sext_i32)(uint32_t op1, uint64_t op1_label, uint64_t ext_bit)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    size_t bits_to_keep = 32 - ext_bit;
    uint64_t tmp = dfsan_union(op1_label, CONST_LABEL, Shl, 32, op1, bits_to_keep);
    return dfsan_union(tmp, CONST_LABEL, AShr, 32, op1 << bits_to_keep, bits_to_keep);
}
uint64_t HELPER(symsan_sext_i64)(uint64_t op1, uint64_t op1_label, uint64_t ext_bit)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    size_t bits_to_keep = 64 - ext_bit;
    uint64_t tmp = dfsan_union(op1_label, CONST_LABEL, Shl, 64, op1, bits_to_keep);
    return dfsan_union(tmp, CONST_LABEL, AShr, 64, op1 << bits_to_keep, bits_to_keep);
}

uint64_t HELPER(symsan_zext_i32)(uint32_t op1, uint64_t op1_label, uint64_t ext_bit)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    return dfsan_union(op1_label, CONST_LABEL, And, 32, op1, (1ull << ext_bit) - 1);
}
uint64_t HELPER(symsan_zext_i64)(uint64_t op1, uint64_t op1_label, uint64_t ext_bit)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    return dfsan_union(op1_label, CONST_LABEL, And, 64, op1, (1ull << ext_bit) - 1);
}

/* *ext_i32_i64 equals to the ext operation in z3 */
uint64_t HELPER(symsan_zext_i32_i64)(uint32_t op1, uint64_t op1_label)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    return dfsan_union(op1_label, CONST_LABEL, ZExt, 64, op1, 32); // extend by 32 bits.
}
uint64_t HELPER(symsan_sext_i32_i64)(uint32_t op1, uint64_t op1_label)
{
    if (op1_label == 0) return 0; /* op2 label is alway zero */
    return dfsan_union(op1_label, CONST_LABEL, SExt, 64, op1, 32); // extend by 32 bits.
}

/* Truncate a 64-bit value to 32-bit */
uint64_t HELPER(symsan_trunc_i64_i32)(uint64_t op1, uint64_t op1_label)
{
    if (op1_label == 0) return 0;
    // UNIMPLEMENTED_HELPER("trunc_i64_i32")
    return dfsan_union(op1_label, CONST_LABEL, Trunc, 32, op1, 32);
}

uint64_t HELPER(symsan_bswap_i32)(uint32_t op1, uint64_t op1_label, uint64_t length)
{
    if (op1_label == 0) return 0;
    UNIMPLEMENTED_HELPER("bswap32")
}
uint64_t HELPER(symsan_bswap_i64)(uint64_t op1, uint64_t op1_label, uint64_t length)
{
    if (op1_label == 0) return 0;
    UNIMPLEMENTED_HELPER("bswap64")
}
/* Extract syntax
    dfsan_union(label, CONST_LABEL, Extract, 8, 0, i * 8);
    size = 8
    op2 = offset (bit-wise)
    Extract one byte (8-bit) from a 8-byte value
    extract2_i32/i64 can be handled by extract_i32/i64, the len is fixed (32 or 64).
    sextract_i32/i64 is also handled by extract_i32/i64 now. Maybe need a FIXME.
 */
uint64_t HELPER(symsan_extract_i32)(uint32_t arg, uint64_t arg_label, uint32_t ofs, uint32_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, len, arg, ofs);
    return dfsan_union(out, CONST_LABEL, ZExt, 32, 0, 32 - len);
}
uint64_t HELPER(symsan_extract_i64)(uint64_t arg, uint64_t arg_label, uint64_t ofs, uint64_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, len, arg, ofs);
    return dfsan_union(out, CONST_LABEL, ZExt, 64, 0, 64 - len);
}

uint64_t HELPER(symsan_sextract_i32)(uint32_t arg, uint64_t arg_label, uint32_t ofs, uint32_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, len, arg, ofs);
    return dfsan_union(out, CONST_LABEL, SExt, 32, 0, 32 - len);
}
uint64_t HELPER(symsan_sextract_i64)(uint64_t arg, uint64_t arg_label, uint64_t ofs, uint64_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, len, arg, ofs);
    return dfsan_union(out, CONST_LABEL, SExt, 64, 0, 64 - len);
}

uint64_t HELPER(symsan_deposit_i32)(uint32_t arg1, uint64_t arg1_label,
                              uint32_t arg2, uint64_t arg2_label,
                              uint32_t ofs, uint32_t len)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS

    /* The symbolic implementation follows the alternative concrete
     * implementation of tcg_gen_deposit_i64 in tcg-op.c (which handles
     * architectures that don't support deposit directly). */

    uint64_t mask = (1ull << len) - 1;
    uint64_t arg1_new_label = dfsan_union(arg1_label, CONST_LABEL, And, 32, arg1, ~(mask << ofs));
    uint64_t arg2_new_label = dfsan_union(arg2_label, CONST_LABEL, And, 32, arg2, mask);
    arg2_new_label = dfsan_union(arg2_new_label, CONST_LABEL, Shl, 32, arg2, ofs);
    return dfsan_union(arg1_new_label, arg2_new_label, Or, 32, arg1, arg2);
}

uint64_t HELPER(symsan_deposit_i64)(uint64_t arg1, uint64_t arg1_label,
                              uint64_t arg2, uint64_t arg2_label,
                              uint64_t ofs, uint64_t len)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS

    /* The symbolic implementation follows the alternative concrete
     * implementation of tcg_gen_deposit_i64 in tcg-op.c (which handles
     * architectures that don't support deposit directly). */

    uint64_t mask = (1ull << len) - 1;
    uint64_t arg1_new_label = dfsan_union(arg1_label, CONST_LABEL, And, 64, arg1, ~(mask << ofs));
    uint64_t arg2_new_label = dfsan_union(arg2_label, CONST_LABEL, And, 64, arg2, mask);
    arg2_new_label = dfsan_union(arg2_new_label, CONST_LABEL, Shl, 64, arg2, ofs);
    return dfsan_union(arg1_new_label, arg2_new_label, Or, 64, arg1, arg2);
}

uint64_t HELPER(symsan_extract2_i32)(uint32_t ah, uint64_t ah_label,
                                     uint32_t al, uint64_t al_label,
                                     uint64_t ofs)
{
    if (ah_label == 0 && al_label == 0)
        return 0;

    /* The implementation follows the alternative implementation of
     * tcg_gen_extract2_i32 in tcg-op.c (which handles architectures that don't
     * support extract2 directly). */

    if (ofs == 0)
        return al_label;
    if (ofs == 32)
        return ah_label;
    uint64_t al_new = dfsan_union(al_label, CONST_LABEL, LShr, 32, al, ofs);
    return HELPER(symsan_deposit_i32)(al >> ofs, al_new, ah, ah_label, 32-ofs, ofs);
}

uint64_t HELPER(symsan_extract2_i64)(uint64_t ah, uint64_t ah_label,
                                     uint64_t al, uint64_t al_label,
                                     uint64_t ofs)
{
    if (ah_label == 0 && al_label == 0)
        return 0;

    /* The implementation follows the alternative implementation of
     * tcg_gen_extract2_i64 in tcg-op.c (which handles architectures that don't
     * support extract2 directly). */

    if (ofs == 0)
        return al_label;
    if (ofs == 64)
        return ah_label;
    uint64_t al_new = dfsan_union(al_label, CONST_LABEL, LShr, 64, al, ofs);
    return HELPER(symsan_deposit_i64)(al >> ofs, al_new, ah, ah_label, 64-ofs, ofs);
}

static uint64_t symsan_setcond_internal(CPUArchState *env, uint64_t arg1, uint64_t arg1_label,
                                  uint64_t arg2, uint64_t arg2_label,
                                  int32_t cond, uint8_t result_bits)
{
    // if (!noSymbolicData)
    // fprintf(stderr, "setcond_i%d push constraint eip: 0x%lx %s arg1: 0x%ld arg2: 0x%ld\n",
    //          result_bits, env->eip, (arg1_label == 0 && arg2_label == 0) ? "Concrete" : "Symbolic",
    //          arg1, arg2);

    BINARY_HELPER_ENSURE_EXPRESSIONS;

    uint32_t predicate = 0;
    switch (cond) {
    case TCG_COND_EQ:
        predicate = bveq;
        break;
    case TCG_COND_NE:
        predicate = bvneq;
        break;
    case TCG_COND_LT:
        predicate = bvslt;
        break;
    case TCG_COND_GE:
        predicate = bvsge;
        break;
    case TCG_COND_LE:
        predicate = bvsle;
        break;
    case TCG_COND_GT:
        predicate = bvsgt;
        break;
    case TCG_COND_LTU:
        predicate = bvult;
        break;
    case TCG_COND_GEU:
        predicate = bvuge;
        break;
    case TCG_COND_LEU:
        predicate = bvule;
        break;
    case TCG_COND_GTU:
        predicate = bvugt;
        break;
    default:
        g_assert_not_reached();
    }
    
    // _sym_notify_basic_block(env->eip);
    // void *condition = handler(arg1_expr, arg2_expr);
    //_sym_push_path_constraint(condition, result, get_pc(env));
    //_sym_notify_basic_block(cur_eip);
    // _sym_push_path_constraint(condition, result, env->eip);
    return __taint_trace_cmp(arg1_label, arg2_label, result_bits, predicate, arg1, arg2, env->eip);
}

uint64_t HELPER(symsan_setcond_i32)(CPUArchState *env, uint32_t arg1, uint64_t arg1_label,
                              uint32_t arg2, uint64_t arg2_label,
                              int32_t cond)
{
    return symsan_setcond_internal(env, arg1, arg1_label, arg2, arg2_label, cond, 32);
}

uint64_t HELPER(symsan_setcond_i64)(CPUArchState *env, uint64_t arg1, uint64_t arg1_label,
                              uint64_t arg2, uint64_t arg2_label,
                              int32_t cond)
{
    return symsan_setcond_internal(env, arg1, arg1_label, arg2, arg2_label, cond, 64);
}

/* Guest memory opreation */
static uint64_t symsan_load_guest_internal(target_ulong addr,
                                     uint64_t load_length, uint8_t result_length)
{
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);
    
    /*if (addr == 0x6552e1 && load_length==8) {
        char *p1 = (char*)(addr+7);
        fprintf(stderr, "load host 0x%ld %s\n", addr+7, p1);
        p1 = (char*)g2h(addr+7);
        fprintf(stderr, "load guest %p %d\n", p1, (int)*p1);
    }*/
    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, load_length);
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_GUEST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic]op: load_guest_i%d addr: 0x%lx host_addr: %p size: %ld memory_expr: %ld\n",
                     result_length*8, addr, host_addr, load_length, res_label);
    }
    return res_label;
}

uint64_t HELPER(symsan_load_guest_i32)(target_ulong addr,
                                 uint64_t length)
{
    return symsan_load_guest_internal(addr, length, 4);
}

uint64_t HELPER(symsan_load_guest_i64)(target_ulong addr,
                                 uint64_t length)
{
    return symsan_load_guest_internal(addr, length, 8);
}


static uint64_t symsan_load_host_internal(void *addr, uint64_t offset,
                                    uint64_t load_length, uint64_t result_length)
{
    assert((uintptr_t)addr+offset >= 0x700000040000);
    uint64_t res_label = dfsan_read_label((uint8_t*)addr + offset, load_length);
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_HOST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic]op: load_host_i%ld addr: %p size: %ld memory_expr: %ld\n",
                     result_length*8, addr+offset, load_length, res_label);
    }
    return res_label;
}

uint64_t HELPER(symsan_load_host_i32)(void *addr, uint64_t offset, uint64_t length)
{
    return symsan_load_host_internal(addr, offset, length, 4);
}

uint64_t HELPER(symsan_load_host_i64)(void *addr, uint64_t offset, uint64_t length)
{
    return symsan_load_host_internal(addr, offset, length, 8);
}

static void symsan_store_guest_internal(uint64_t value_label,
                                     target_ulong addr, uint64_t length)
{
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_GUEST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic]op: store_guest_i%ld addr: 0x%lx size: %ld value_expr: %ld\n",
                     length*8, addr, length, value_label);
    }

    //void *host_addr = tlb_vaddr_to_host(env, addr, MMU_DATA_STORE, mmu_idx);
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);
    dfsan_store_label(value_label, (uint8_t*)host_addr, length);
}

void HELPER(symsan_store_guest_i32)(uint64_t value_label,
                                 target_ulong addr, uint64_t length)
{
    symsan_store_guest_internal(value_label, addr, length);
}

void HELPER(symsan_store_guest_i64)(uint64_t value_label,
                                 target_ulong addr, uint64_t length)
{
    symsan_store_guest_internal(value_label, addr, length);
}

void HELPER(symsan_store_host_i32)(uint64_t value_label,
                                void *addr,
                                uint64_t offset, uint64_t length)
{
    assert((uintptr_t)addr+offset >= 0x700000040000);
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_HOST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic] op: store_host_i32 addr: %p value_label: %ld length %ld\n",
                        addr+offset, value_label, length);
    }
    dfsan_store_label(value_label, (uint8_t*)addr + offset, length);
}

void HELPER(symsan_store_host_i64)(uint64_t value_label,
                                void *addr,
                                uint64_t offset, uint64_t length)
{
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_HOST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic] op: store_host_i64 addr: %p value_label: %ld length %ld\n",
                        addr+offset, value_label, length);
    }
    assert((uintptr_t)addr+offset >= 0x700000040000);
    dfsan_store_label(value_label, (uint8_t*)addr + offset, length);
}


// concrete mode
/* Monitor load in concrete mode, if load symbolic data, switch to symbolic mode
 * currently, we do this in the translation backend.
 */
void HELPER(symsan_check_load_guest)(CPUArchState *env, target_ulong addr, uint64_t length) {
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);
    uint32_t res_label = dfsan_read_label((uint8_t*)host_addr, length);
    if (res_label != 0) {
        if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_GUEST) && !noSymbolicData) {
            // fprintf(stderr, "[memtrace:switch] op: load_guest addr: 0x%lx host_addr %p mode: concrete\n",
            //                         addr, host_addr);
        }
        second_ccache_flag = 1;
        raise_exception_err_ra(env, EXCP_SWITCH, 0, GETPC());
    }
}
void HELPER(symsan_check_store_guest)(target_ulong addr, uint64_t length){
    assert(second_ccache_flag != 1);
    uint32_t value_label = 0;
    //void *host_addr = tlb_vaddr_to_host(env, addr, MMU_DATA_STORE, mmu_idx);
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);
    // if (!noSymbolicData)
    // fprintf(stderr, "[memtrace] op: check_store_guest addr: 0x%lx mode: concrete\n", addr);
    dfsan_store_label(value_label, (uint8_t*)host_addr, length);
}

/* Check the register status at the end of one basic block in symbolic mode
 * if there is no symbolic registers, switch to concrete mode
 */
void HELPER(symsan_check_state_switch)(CPUArchState *env) {
    int symbolic_flag = 0;
    for (int i=0; i<CPU_NB_REGS;i++) {
        if (env->shadow_regs[i]){
            symbolic_flag = 1;
            break;
        }
    }
    if (symbolic_flag) {
        second_ccache_flag = 1;
        //if (!noSymbolicData) fprintf(stderr, "block 0x%lx state symbolic\n", env->eip);
        return;
    }
    if (env->shadow_cc_dst || env->shadow_cc_src || env->shadow_cc_src2) {
        symbolic_flag = 1;
    }
    if (sse_operation) {
        int size = sizeof(env->xmm_regs);
        uintptr_t xmm_reg_addr = (uintptr_t)env->xmm_regs;
        uint64_t xmm_reg = 0;
        for (uintptr_t addr = xmm_reg_addr; addr < xmm_reg_addr + size; addr+=8) {
            xmm_reg = dfsan_read_label((uint8_t *)addr, 8);
            if (xmm_reg != 0) {
                symbolic_flag = 1;
                break;
            }
        }
    }
    second_ccache_flag = symbolic_flag;
    // if (!noSymbolicData) fprintf(stderr, "block 0x%lx state %s\n", env->eip, second_ccache_flag?"symbolic":"concrete");
    if (second_ccache_flag == 0) {
        CPUState *cs = env_cpu(env);
        cpu_loop_exit_noexc(cs);
    }
}
void HELPER(symsan_check_state)(CPUArchState *env) {
    int symbolic_flag = 0;
    for (int i=0; i<CPU_NB_REGS;i++) {
        if (env->shadow_regs[i]) {
            symbolic_flag = 1;
            break;
        }
    }
    if (symbolic_flag) {
        second_ccache_flag = 1;
        return;
    }
    if (env->shadow_cc_dst || env->shadow_cc_src || env->shadow_cc_src2) {
        symbolic_flag = 1;
    }
    if (sse_operation) {
        int size = sizeof(env->xmm_regs);
        uintptr_t xmm_reg_addr = (uintptr_t)env->xmm_regs;
        uint64_t xmm_reg = 0;
        for (uintptr_t addr = xmm_reg_addr; addr < xmm_reg_addr + size; addr+=8) {
            xmm_reg = dfsan_read_label((uint8_t *)addr, 8);
            if (xmm_reg != 0) {
                symbolic_flag = 1;
                break;
            }
        }
    }
    second_ccache_flag = symbolic_flag;
}


void HELPER(symsan_notify_call)(uint64_t func_addr)
{
    addContextRecording(func_addr);
}
