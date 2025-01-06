#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg.h"
#include "qemu/cutils.h"
#include "dfsan_interface.h"
extern CPUArchState *global_env;
#define CONST_LABEL 0

static const uint64_t kShadowMask = ~0x700000000000;
static inline void *shadow_for(uint64_t ptr) {
  return (void *) (((ptr) & kShadowMask) << 2);
}

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
    // UNIMPLEMENTED_HELPER("rotate_left32")
    // arg1 << arg2 | arg1 >> (32 - arg2)
    uint32_t shl = dfsan_union(arg1_label, arg2_label, Shl, 32, arg1, arg2);
    uint32_t tmp = dfsan_union(CONST_LABEL, arg2_label, Sub, 32, 32, arg2);
    uint32_t lshr = dfsan_union(arg1_label, tmp, LShr, 32, arg1, 32-arg2);
    return dfsan_union(shl, lshr, Or, 32, arg1 << arg2, arg1 >> (32 - arg2));
}
DECL_HELPER_BINARY(rotate_left, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    // UNIMPLEMENTED_HELPER("rotate_left64")
    // arg1 << arg2 | arg1 >> (64 - arg2)
    uint32_t shl = dfsan_union(arg1_label, arg2_label, Shl, 64, arg1, arg2);
    uint32_t tmp = dfsan_union(CONST_LABEL, arg2_label, Sub, 64, 64, arg2);
    uint32_t lshr = dfsan_union(arg1_label, tmp, LShr, 64, arg1, 64-arg2);
    return dfsan_union(shl, lshr, Or, 64, arg1 << arg2, arg1 >> (64 - arg2));
}
DECL_HELPER_BINARY(rotate_right, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    // UNIMPLEMENTED_HELPER("rotate_right32")
    // arg1 >> arg2 | arg1 << (32 - arg2)
    uint32_t lshr = dfsan_union(arg1_label, arg2_label, LShr, 32, arg1, arg2);
    uint32_t tmp = dfsan_union(CONST_LABEL, arg2_label, Sub, 32, 32, arg2);
    uint32_t shl = dfsan_union(arg1_label, tmp, Shl, 32, arg1, 32-arg2);
    return dfsan_union(lshr, shl, Or, 32, arg1 >> arg2, arg1 << (32 - arg2));
}
DECL_HELPER_BINARY(rotate_right, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    // UNIMPLEMENTED_HELPER("rotate_right64")
    uint32_t lshr = dfsan_union(arg1_label, arg2_label, LShr, 64, arg1, arg2);
    uint32_t tmp = dfsan_union(CONST_LABEL, arg2_label, Sub, 64, 64, arg2);
    uint32_t shl = dfsan_union(arg1_label, tmp, Shl, 64, arg1, 64-arg2);
    return dfsan_union(lshr, shl, Or, 64, arg1 >> arg2, arg1 << (64 - arg2));
}

DECL_HELPER_BINARY(nand, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(CONST_LABEL,
                        dfsan_union(arg1_label, arg2_label, And, 32, arg1, arg2),
                        Not,
                        32,
                        0, 0);
}
DECL_HELPER_BINARY(nand, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(CONST_LABEL,
                        dfsan_union(arg1_label, arg2_label, And, 64, arg1, arg2),
                        Not,
                        64,
                        0, 0);
}

DECL_HELPER_BINARY(nor, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(CONST_LABEL,
                        dfsan_union(arg1_label, arg2_label, Or, 32, arg1, arg2),
                        Not,
                        32,
                        0, 0);
}
DECL_HELPER_BINARY(nor, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(CONST_LABEL,
                        dfsan_union(arg1_label, arg2_label, Or, 64, arg1, arg2),
                        Not,
                        64,
                        0, 0);
}

DECL_HELPER_BINARY(orc, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(arg1_label,
                       dfsan_union(arg2_label, CONST_LABEL, Not, 32, arg2, 0),
                       Or,
                       32,
                       arg1, arg2);
}
DECL_HELPER_BINARY(orc, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(arg1_label,
                       dfsan_union(arg2_label, CONST_LABEL, Not, 64, arg2, 0),
                       Or,
                       64,
                       arg1, arg2);
}

/* andc support */
DECL_HELPER_BINARY(andc, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(arg1_label,
                       dfsan_union(arg2_label, CONST_LABEL, Not, 32, arg2, 0),
                       And,
                       32,
                       arg1, arg2);
}
DECL_HELPER_BINARY(andc, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(arg1_label,
                       dfsan_union(arg2_label, CONST_LABEL, Not, 64, arg2, 0),
                       And,
                       64,
                       arg1, arg2);
}
/* eqv support */
DECL_HELPER_BINARY(eqv, 32)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(dfsan_union(arg1_label, arg2_label, Xor, 32, arg1, arg2),
                       CONST_LABEL,
                       Not,
                       32,
                       0, 0);
}

DECL_HELPER_BINARY(eqv, 64)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    return dfsan_union(dfsan_union(arg1_label, arg2_label, Xor, 64, arg1, arg2),
                       CONST_LABEL,
                       Not,
                       64,
                       0, 0);
}

uint64_t HELPER(symsan_neg_i32)(uint32_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    /* for unary operator Neg/Not, leave the first op as 0 */
    return dfsan_union(CONST_LABEL, label, Neg, 32, 0, op1);
}
uint64_t HELPER(symsan_neg_i64)(uint64_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    return dfsan_union(CONST_LABEL, label, Neg, 64, 0, op1);
}

uint64_t HELPER(symsan_not_i32)(uint32_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    return dfsan_union(CONST_LABEL, label, Not, 32, 0, op1);
}
uint64_t HELPER(symsan_not_i64)(uint64_t op1, uint64_t label)
{
    if (label == 0)
        return 0;
    return dfsan_union(CONST_LABEL, label, Not, 64, 0, op1);
}

uint64_t HELPER(symsan_muluh_i64)(uint64_t arg1, uint64_t arg1_label,
                                  uint64_t arg2, uint64_t arg2_label)
{
    BINARY_HELPER_ENSURE_EXPRESSIONS
    uint64_t arg1_new = dfsan_union(arg1_label, CONST_LABEL, ZExt, 64, arg1, 64);
    uint64_t arg2_new = dfsan_union(arg2_label, CONST_LABEL, ZExt, 64, arg2, 64);
    uint64_t res = dfsan_union(arg1_new, arg2_new, Mul, 64, arg1, arg2);
    return dfsan_union(res,
                       CONST_LABEL,
                       Extract,
                       64,
                       127,
                       64);
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
    // bitwise and
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
    // Result is 32-bit.
    return dfsan_union(op1_label, CONST_LABEL, Trunc, 32, op1, 32);
}
// https://github.com/chenju2k6/symsan/commit/3392e5b1d33b8ac6e350eeefb37ae861848ba9b2
// bswap support
uint64_t HELPER(symsan_bswap_i32)(uint32_t op1, uint64_t op1_label, uint64_t length)
{
    if (op1_label == 0) return 0;
    uint64_t arg1, arg2, tmp, tmp1, tmp2, first_block, second_block;
    switch (length) {
        case 2:
            arg1 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, ZExt, 64, op1, 1),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8);
            arg2 = dfsan_union(
                op1_label,
                CONST_LABEL,
                LShr,
                64,
                op1,
                8);
            return dfsan_union(arg1, arg2, Or, 64, 0, 0);
        case 4:
            tmp = dfsan_union(op1_label, CONST_LABEL, LShr, 64, op1, 8);
            arg1 = dfsan_union(
                tmp,
                CONST_LABEL,
                And,
                64,
                op1,
                0x00ff00ff
            );
            arg2 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, And, 64, op1, 0x00ff00ff),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8
            );
            first_block = dfsan_union(arg1, arg2, Or, 64, 0, 0);
            tmp1 = dfsan_union(first_block, CONST_LABEL, LShr, 64, op1, 16);
            tmp2 = dfsan_union(first_block, CONST_LABEL, Shl, 64, op1, 16);
            return dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
        case 8:
            tmp1 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, LShr, 64, op1, 8),
                CONST_LABEL,
                And,
                64,
                op1,
                0x00ff00ff00ff00ffull
            );
            tmp2 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, And, 64, op1, 0x00ff00ff00ff00ffull),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8
            );
            first_block = dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
            tmp1 = dfsan_union(
                dfsan_union(first_block, CONST_LABEL, LShr, 64, op1, 16),
                CONST_LABEL,
                And,
                64,
                op1,
                0x0000ffff0000ffffull
            );
            tmp2 = dfsan_union(
                dfsan_union(first_block, CONST_LABEL, And, 64, op1, 0x0000ffff0000ffffull),
                CONST_LABEL,
                Shl,
                64,
                op1,
                16
            );
            second_block = dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
            return dfsan_union(
                dfsan_union(
                    second_block,
                    CONST_LABEL,
                    LShr,
                    64,
                    op1,
                    32
                ),
                dfsan_union(
                    second_block,
                    CONST_LABEL,
                    Shl,
                    64,
                    op1,
                    32
                ),
                Or,
                64,
                0,
                0
            );
        default:
            g_assert_not_reached();
    }
}

uint64_t HELPER(symsan_bswap_i64)(uint64_t op1, uint64_t op1_label, uint64_t length)
{
    if (op1_label == 0) return 0;
    uint64_t arg1, arg2, tmp, tmp1, tmp2, first_block, second_block;
    switch (length) {
        case 2:
            arg1 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, ZExt, 64, op1, 1),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8);
            arg2 = dfsan_union(
                op1_label,
                CONST_LABEL,
                LShr,
                64,
                op1,
                8);
            return dfsan_union(arg1, arg2, Or, 64, 0, 0);
        case 4:
            tmp = dfsan_union(op1_label, CONST_LABEL, LShr, 64, op1, 8);
            arg1 = dfsan_union(
                tmp,
                CONST_LABEL,
                And,
                64,
                op1,
                0x00ff00ff
            );
            arg2 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, And, 64, op1, 0x00ff00ff),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8
            );
            first_block = dfsan_union(arg1, arg2, Or, 64, 0, 0);
            tmp1 = dfsan_union(first_block, CONST_LABEL, LShr, 64, op1, 16);
            tmp2 = dfsan_union(
                dfsan_union(first_block, CONST_LABEL, Shl, 64, op1, 48),
                CONST_LABEL,
                LShr,
                64,
                op1,
                32
            );
            return dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
        case 8:
            tmp1 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, LShr, 64, op1, 8),
                CONST_LABEL,
                And,
                64,
                op1,
                0x00ff00ff00ff00ffull
            );
            tmp2 = dfsan_union(
                dfsan_union(op1_label, CONST_LABEL, And, 64, op1, 0x00ff00ff00ff00ffull),
                CONST_LABEL,
                Shl,
                64,
                op1,
                8
            );
            first_block = dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
            tmp1 = dfsan_union(
                dfsan_union(first_block, CONST_LABEL, LShr, 64, op1, 16),
                CONST_LABEL,
                And,
                64,
                op1,
                0x0000ffff0000ffffull
            );
            tmp2 = dfsan_union(
                dfsan_union(first_block, CONST_LABEL, And, 64, op1, 0x0000ffff0000ffffull),
                CONST_LABEL,
                Shl,
                64,
                op1,
                16
            );
            second_block = dfsan_union(tmp1, tmp2, Or, 64, 0, 0);
            return dfsan_union(
                dfsan_union(
                    second_block,
                    CONST_LABEL,
                    LShr,
                    64,
                    op1,
                    32
                ),
                dfsan_union(
                    second_block,
                    CONST_LABEL,
                    Shl,
                    64,
                    op1,
                    32
                ),
                Or,
                64,
                0,
                0
            );
        default:
            g_assert_not_reached();
    }
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
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, 32, ofs + len - 1, ofs);
    return dfsan_union(out, CONST_LABEL, ZExt, 32, 0, 32 - len);
}
uint64_t HELPER(symsan_extract_i64)(uint64_t arg, uint64_t arg_label, uint64_t ofs, uint64_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, 64, ofs + len - 1, ofs);
    return dfsan_union(out, CONST_LABEL, ZExt, 64, 0, 64 - len);
}

uint64_t HELPER(symsan_sextract_i32)(uint32_t arg, uint64_t arg_label, uint32_t ofs, uint32_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, 32, ofs + len - 1, ofs);
    return dfsan_union(out, CONST_LABEL, SExt, 32, 0, 32 - len);
}
uint64_t HELPER(symsan_sextract_i64)(uint64_t arg, uint64_t arg_label, uint64_t ofs, uint64_t len)
{
    if (arg_label == 0) return 0;
    /* len is the extract length.
       ofs is the offset to start extract.
     */
    uint32_t out = dfsan_union(arg_label, CONST_LABEL, Extract, 64, ofs + len - 1, ofs);
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
    arg2_new_label = dfsan_union(arg2_new_label, CONST_LABEL, Shl, 32, arg2 & mask, ofs);
    return dfsan_union(arg1_new_label, arg2_new_label, Or, 32, arg1 & ~(mask << ofs), (arg2 & mask) << ofs);
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
    arg2_new_label = dfsan_union(arg2_new_label, CONST_LABEL, Shl, 64, arg2 & mask, ofs);
    return dfsan_union(arg1_new_label, arg2_new_label, Or, 64, arg1 & ~(mask << ofs), (arg2 & mask) << ofs);
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
                                  int32_t cond, uint64_t result, uint8_t result_bits)
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
    // fprintf(stderr, "sym branch 0x%lx\n", env->eip);
    return __taint_trace_cmp(arg1_label, arg2_label, result_bits, result, predicate, arg1, arg2, env->eip);
}

uint64_t HELPER(symsan_setcond_i32)(CPUArchState *env, uint32_t arg1, uint64_t arg1_label,
                              uint32_t arg2, uint64_t arg2_label,
                              int32_t cond, uint32_t result)
{
    return symsan_setcond_internal(env, arg1, arg1_label, arg2, arg2_label, cond, result, 32);
}

uint64_t HELPER(symsan_setcond_i64)(CPUArchState *env, uint64_t arg1, uint64_t arg1_label,
                              uint64_t arg2, uint64_t arg2_label,
                              int32_t cond, uint64_t result)
{
    return symsan_setcond_internal(env, arg1, arg1_label, arg2, arg2_label, cond, result, 64);
}

/* Guest memory opreation */
static uint64_t symsan_load_guest_internal(CPUArchState *env, target_ulong addr, uint64_t addr_label,
                                     uint64_t load_length, uint8_t result_length)
{
    void *host_addr = g2h(addr);
    
    if (addr_label) {
        // fprintf(stderr, "sym load addr 0x%lx eip 0x%lx\n", addr, env->eip);
        dfsan_label addr_label_new = \
            dfsan_union(addr_label, CONST_LABEL, Equal, 64, addr, 0);
        __taint_trace_cmp(addr_label_new, CONST_LABEL, 64, true, Equal, 0, 0, env->eip);
    }

    uint64_t res_label = dfsan_read_label((uint8_t*)host_addr, load_length);
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_GUEST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic]op: load_guest_i%d addr: 0x%lx host_addr: %p size: %ld memory_expr: %ld\n",
                     result_length*8, addr, host_addr, load_length, res_label);
    }
    return res_label;
}

uint64_t HELPER(symsan_load_guest_i32)(CPUArchState *env, target_ulong addr, uint64_t addr_label,
                                 uint64_t length)
{
    return symsan_load_guest_internal(env, addr, addr_label, length, 4);
}

uint64_t HELPER(symsan_load_guest_i64)(CPUArchState *env, target_ulong addr, uint64_t addr_label,
                                 uint64_t length)
{
    return symsan_load_guest_internal(env, addr, addr_label, length, 8);
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

static void symsan_store_guest_internal(CPUArchState *env, uint64_t value_label,
                                     target_ulong addr, uint64_t addr_label, uint64_t length)
{
    if (qemu_loglevel_mask(CPU_LOG_SYM_LDST_GUEST) && !noSymbolicData) {
        fprintf(stderr, "[memtrace:symbolic]op: store_guest_i%ld addr: 0x%lx size: %ld value_expr: %ld\n",
                     length*8, addr, length, value_label);
    }
    if (addr_label) {
        // fprintf(stderr, "sym store addr 0x%lx eip 0x%lx\n", addr, env->eip);
        dfsan_label addr_label_new = \
            dfsan_union(addr_label, CONST_LABEL, Equal, 64, addr, 0);
        __taint_trace_cmp(addr_label_new, CONST_LABEL, 64, true, Equal, 0, 0, env->eip);
    }

    //void *host_addr = tlb_vaddr_to_host(env, addr, MMU_DATA_STORE, mmu_idx);
    void *host_addr = g2h(addr);
    assert((uintptr_t)host_addr >= 0x700000040000);
    dfsan_store_label(value_label, (uint8_t*)host_addr, length);
    // g_assert_not_reached();

}

void HELPER(symsan_store_guest_i32)(CPUArchState *env, uint64_t value_label,
                                 target_ulong addr, uint64_t addr_label, uint64_t length)
{
    symsan_store_guest_internal(env, value_label, addr, addr_label, length);
}

void HELPER(symsan_store_guest_i64)(CPUArchState *env, uint64_t value_label,
                                 target_ulong addr, uint64_t addr_label, uint64_t length)
{
    symsan_store_guest_internal(env, value_label, addr, addr_label, length);
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
    if (!symbolic_flag && sse_operation) {
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
    if (!symbolic_flag && sse_operation) {
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

void HELPER(symsan_check_state_no_sse)(CPUArchState *env) {
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
    second_ccache_flag = symbolic_flag;
    // if (!noSymbolicData) fprintf(stderr, "block 0x%lx state %s\n", env->eip, second_ccache_flag?"symbolic":"concrete");
    if (second_ccache_flag == 0) {
        CPUState *cs = env_cpu(env);
        cpu_loop_exit_noexc(cs);
    }
}

// void HELPER(symsan_notify_call)(uint64_t func_addr)
// {
//     addContextRecording(func_addr);
// }

