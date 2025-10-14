#define SYM_HELPER_BINARY(name)                                         \
  DEF_HELPER_FLAGS_4(symsan_##name##_i32, TCG_CALL_NO_RWG_SE, i64,      \
                     i32, i64, i32, i64)                                \
  DEF_HELPER_FLAGS_4(symsan_##name##_i64, TCG_CALL_NO_RWG_SE, i64,      \
                     i64, i64, i64, i64)

/* Arithmetic */
SYM_HELPER_BINARY(add)
SYM_HELPER_BINARY(sub)
SYM_HELPER_BINARY(mul)
SYM_HELPER_BINARY(div)
SYM_HELPER_BINARY(divu)
SYM_HELPER_BINARY(rem)
SYM_HELPER_BINARY(remu)

/* Shifts */
SYM_HELPER_BINARY(shift_right)
SYM_HELPER_BINARY(arithmetic_shift_right)
SYM_HELPER_BINARY(shift_left)
SYM_HELPER_BINARY(rotate_left)
SYM_HELPER_BINARY(rotate_right)

/* Logical operations */
SYM_HELPER_BINARY(and)
SYM_HELPER_BINARY(or)
SYM_HELPER_BINARY(xor)
SYM_HELPER_BINARY(andc)
SYM_HELPER_BINARY(eqv)
SYM_HELPER_BINARY(nand)
SYM_HELPER_BINARY(nor)
SYM_HELPER_BINARY(orc)

#undef SYM_HELPER_BINARY

/* Arithmetic */
DEF_HELPER_FLAGS_2(symsan_neg_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64)
DEF_HELPER_FLAGS_2(symsan_neg_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)
DEF_HELPER_FLAGS_2(symsan_not_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64)
DEF_HELPER_FLAGS_2(symsan_not_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64)

DEF_HELPER_FLAGS_4(symsan_muluh_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64, i64)

/* Extension and truncation */
DEF_HELPER_FLAGS_3(symsan_sext_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i64)
DEF_HELPER_FLAGS_3(symsan_sext_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64)
DEF_HELPER_FLAGS_3(symsan_zext_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i64)
DEF_HELPER_FLAGS_3(symsan_zext_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64)

DEF_HELPER_FLAGS_2(symsan_sext_i32_i64, TCG_CALL_NO_RWG_SE, i64, i32, i64)
DEF_HELPER_FLAGS_2(symsan_zext_i32_i64, TCG_CALL_NO_RWG_SE, i64, i32, i64)

DEF_HELPER_FLAGS_2(symsan_trunc_i64_i32, TCG_CALL_NO_RWG_SE, i64, i64, i64)

/* Byte swapping */
DEF_HELPER_FLAGS_3(symsan_bswap_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i64)
DEF_HELPER_FLAGS_3(symsan_bswap_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64)

/* Bit fields */
DEF_HELPER_FLAGS_4(symsan_extract_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i32, i32)
DEF_HELPER_FLAGS_4(symsan_extract_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64, i64)
DEF_HELPER_FLAGS_4(symsan_sextract_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i32, i32)
DEF_HELPER_FLAGS_4(symsan_sextract_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64, i64)

DEF_HELPER_FLAGS_5(symsan_extract2_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i32, i64, i64)
DEF_HELPER_FLAGS_5(symsan_extract2_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64, i64, i64)
DEF_HELPER_FLAGS_6(symsan_deposit_i32, TCG_CALL_NO_RWG_SE, i64, i32, i64, i32, i64, i32, i32)
DEF_HELPER_FLAGS_6(symsan_deposit_i64, TCG_CALL_NO_RWG_SE, i64, i64, i64, i64, i64, i64, i64)

/* Conditionals */
DEF_HELPER_FLAGS_7(symsan_setcond_i32, TCG_CALL_NO_RWG, i64, env, i32, i64, i32, i64, s32, i32)
DEF_HELPER_FLAGS_7(symsan_setcond_i64, TCG_CALL_NO_RWG, i64, env, i64, i64, i64, i64, s32, i64)

/* Host memory */
DEF_HELPER_FLAGS_3(symsan_load_host_i32, TCG_CALL_NO_RWG_SE, i64, ptr, i64, i64)
DEF_HELPER_FLAGS_3(symsan_load_host_i64, TCG_CALL_NO_RWG_SE, i64, ptr, i64, i64)
DEF_HELPER_FLAGS_4(symsan_store_host_i32, TCG_CALL_NO_RWG, void, i64, ptr,
                   i64, i64)
DEF_HELPER_FLAGS_4(symsan_store_host_i64, TCG_CALL_NO_RWG, void, i64, ptr,
                   i64, i64)
/* Guest memory */
DEF_HELPER_FLAGS_4(symsan_load_guest_i32, TCG_CALL_NO_RWG, i64,
                     env, dh_alias_tl, i64, i64)
DEF_HELPER_FLAGS_4(symsan_load_guest_i64, TCG_CALL_NO_RWG, i64,
                     env, dh_alias_tl, i64, i64)
DEF_HELPER_FLAGS_5(symsan_store_guest_i32, TCG_CALL_NO_RWG, void,
                    env, i64, dh_alias_tl, i64, i64)
DEF_HELPER_FLAGS_5(symsan_store_guest_i64, TCG_CALL_NO_RWG, void,
                    env, i64, dh_alias_tl, i64, i64)


DEF_HELPER_FLAGS_3(symsan_check_load_guest, TCG_CALL_NO_RWG, void,
                    env, dh_alias_tl, i64)
DEF_HELPER_FLAGS_2(symsan_check_store_guest, TCG_CALL_NO_RWG, void,
                    dh_alias_tl, i64)

DEF_HELPER_1(symsan_check_state, void, env)
DEF_HELPER_1(symsan_check_state_switch, void, env)
DEF_HELPER_1(symsan_check_state_no_sse, void, env)

/* Context tracking */
// DEF_HELPER_FLAGS_1(symsan_notify_call, TCG_CALL_NO_RWG, void, i64)
// DEF_HELPER_FLAGS_1(symsan_notify_ret, TCG_CALL_NO_RWG, void, i64)
// DEF_HELPER_FLAGS_1(symsan_notify_basic_block, TCG_CALL_NO_RWG, void, i64)
