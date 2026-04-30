#include "qemu/osdep.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include "qemu.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qstring.h"
#include "disas/capstone.h"
#include "exec/tcg-runtime-symsan-ext.h"
//#include "target/i386/cpu.h"
#include "cpu.h"
#include "ia-rpc.h"
#include "dfsan_interface.h"

typedef union IADfsanData {
    uint64_t i;
    float f;
    double d;
} IADfsanData;

typedef struct IADfsanLabelInfo {
    dfsan_label l1;
    dfsan_label l2;
    IADfsanData op1;
    IADfsanData op2;
    uint16_t op;
    uint16_t size;
    uint32_t hash;
} __attribute__((aligned(8), packed)) IADfsanLabelInfo;

extern IADfsanLabelInfo *dfsan_get_label_info(dfsan_label label);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
extern int __attribute__((weak)) dfsan_is_branch_condition_label(dfsan_label label);
extern int __attribute__((weak)) dfsan_get_branch_direction(dfsan_label label,
                                                            uint8_t *taken);
extern size_t __attribute__((weak)) dfsan_get_nested_constraint_count(dfsan_label label);
extern size_t __attribute__((weak)) dfsan_get_nested_constraints(dfsan_label label,
                                                                 dfsan_label *out,
                                                                 size_t capacity);
extern size_t __attribute__((weak)) dfsan_get_nested_constraint_directions(dfsan_label label,
                                                                           uint8_t *out,
                                                                           size_t capacity);
extern size_t dfsan_get_label_count(void);
extern size_t dfsan_format_simplified_expression(dfsan_label label, char *out,
                                                 size_t capacity);
#pragma GCC diagnostic pop
static bool ia_format_symbolic_expression_inner(GString *out, dfsan_label label, unsigned depth);

#define IA_EXPR_MAX_DEPTH 24
#define IA_EXPR_MAX_CHARS 2048

typedef struct IAState {
    QemuMutex lock;
    QemuCond cond;
    bool enabled;
    bool attached;
    bool shutting_down;
    bool start_paused;
    bool run_requested;
    bool pause_pending;
    IAExecState exec_state;
    int exit_code;
    bool has_exit_code;
    bool pending_termination;
    bool close_requested;
    IATerminationKind termination_kind;
    int termination_signal;
    int termination_si_code;
    uint64_t termination_fault_addr;
    int listen_fd;
    char *socket_path;
    CPUState *current_cpu;
    uint64_t block_budget;
    uint64_t instruction_budget;
    bool stop_address_enabled;
    bool stop_address_set_enabled;
    bool stop_address_matched;
    uint64_t stop_address;
    uint64_t stop_addresses[64];
    size_t stop_address_count;
    uint64_t last_block_pc;
    uint64_t last_insn_pc;
    uint64_t last_matched_pc;
    FILE *trace_file;
    char *trace_path;
    uint64_t trace_seq;
    struct {
        uint64_t pc;
        dfsan_label label;
        bool taken;
    } path_constraints[256];
    size_t path_constraints_head;
    size_t path_constraints_count;
    struct {
        uint64_t stream_offset;
        uint64_t remaining;
        uint64_t chunk_offset;
        bool symbolic;
    } stdin_chunks[256];
    size_t stdin_chunks_head;
    size_t stdin_chunks_count;
    uint64_t stdin_stream_next_offset;
    uint64_t symbolic_value_next_offset;
    uint64_t pending_stdin_bytes;
    uint64_t pending_symbolic_stdin_bytes;
    QemuThread server_thread;
} IAState;

static IAState ia_state = {
    .listen_fd = -1,
};

static QDict *ia_make_error_response(int64_t id, const char *code,
                                     const char *message);
static QDict *ia_make_ok_response(int64_t id, QDict *result);

static target_ulong get_pc(CPUArchState *env)
{
    target_ulong pc, cs_base;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);

    return pc;
}

static bool ia_debug_path_constraints_enabled(void)
{
    static int cached = -1;
    if (cached == -1) {
        const char *env = getenv("IA_DEBUG_PATH_CONSTRAINTS");
        cached = (env && env[0] && strcmp(env, "0") != 0) ? 1 : 0;
    }
    return cached != 0;
}

static void ia_trace_emit_basic_block(CPUState *cpu, vaddr pc)
{
    if (!ia_state.trace_file) {
        return;
    }
    ia_state.trace_seq++;
    fprintf(
        ia_state.trace_file,
        "{\"event_id\":\"e-%" PRIu64 "\",\"seq\":%" PRIu64 ",\"type\":\"basic_block\","
        "\"timestamp\":%.6f,\"pc\":\"0x%" PRIx64 "\",\"thread_id\":\"1\",\"cpu_id\":%d,"
        "\"payload\":{\"start\":\"0x%" PRIx64 "\",\"end\":\"0x%" PRIx64 "\",\"instruction_count\":1}}\n",
        ia_state.trace_seq,
        ia_state.trace_seq,
        (double)g_get_real_time() / 1000000.0,
        (uint64_t)pc,
        cpu ? cpu->cpu_index : 0,
        (uint64_t)pc,
        (uint64_t)pc
    );
    fflush(ia_state.trace_file);
}

static void ia_trace_emit_backend_ready(void)
{
    if (!ia_state.trace_file) {
        return;
    }
    ia_state.trace_seq++;
    fprintf(
        ia_state.trace_file,
        "{\"event_id\":\"e-%" PRIu64 "\",\"seq\":%" PRIu64 ",\"type\":\"backend_ready\","
        "\"timestamp\":%.6f,\"pc\":null,\"thread_id\":null,\"cpu_id\":null,"
        "\"payload\":{\"status\":\"attached\"}}\n",
        ia_state.trace_seq,
        ia_state.trace_seq,
        (double)g_get_real_time() / 1000000.0
    );
    fflush(ia_state.trace_file);
}

static void ia_clear_run_control_locked(void)
{
    ia_state.block_budget = 0;
    ia_state.instruction_budget = 0;
    ia_state.stop_address_enabled = false;
    ia_state.stop_address_set_enabled = false;
    ia_state.stop_address_count = 0;
    ia_state.stop_address_matched = false;
    ia_state.stop_address = 0;
    ia_state.last_matched_pc = 0;
    ia_state.pause_pending = false;
}

static void ia_enter_terminal_pause_locked(void)
{
    ia_clear_run_control_locked();
    ia_state.start_paused = true;
    ia_state.run_requested = false;
    ia_state.close_requested = false;
    ia_state.exec_state = IA_EXEC_PAUSED;
    qemu_cond_broadcast(&ia_state.cond);
}

static const char *ia_label_op_name(uint16_t op)
{
    switch (op & 0xff) {
    case 0: return "Input";
    case Not: return "Not";
    case Neg: return "Neg";
    case Add: return "Add";
    case Sub: return "Sub";
    case Mul: return "Mul";
    case UDiv: return "UDiv";
    case SDiv: return "SDiv";
    case URem: return "URem";
    case SRem: return "SRem";
    case Shl: return "Shl";
    case LShr: return "LShr";
    case AShr: return "AShr";
    case And: return "And";
    case Or: return "Or";
    case Xor: return "Xor";
    case Trunc: return "Trunc";
    case ZExt: return "ZExt";
    case SExt: return "SExt";
    case PtrToInt: return "PtrToInt";
    case IntToPtr: return "IntToPtr";
    case ICmp: return "ICmp";
    case Alloca: return "Alloca";
    case Load: return "Load";
    case Extract: return "Extract";
    case Concat: return "Concat";
    case Arg: return "Arg";
    case fmemcmp: return "fmemcmp";
    case fsize: return "fsize";
    case Ite: return "Ite";
    default: return "Unknown";
    }
}

static bool ia_parse_label_param(QDict *params, const char *name,
                                 dfsan_label *out_label, Error **errp)
{
    const char *label_str;
    uint64_t label_raw;

    label_str = qdict_get_try_str(params, name);
    if (!label_str || qemu_strtou64(label_str, NULL, 0, &label_raw) != 0) {
        error_setg(errp, "%s must be a hex string", name);
        return false;
    }
    if (label_raw > UINT32_MAX) {
        error_setg(errp, "%s is out of range", name);
        return false;
    }

    *out_label = (dfsan_label)label_raw;
    return true;
}

static QDict *ia_make_symbolic_label_entry(dfsan_label label)
{
    IADfsanLabelInfo *info = NULL;
    g_autofree char *label_hex = NULL;
    g_autofree char *simplified = NULL;
    QDict *entry = qdict_new();
    size_t needed;
    size_t max_label = dfsan_get_label_count();

    if (label != 0 && label <= max_label) {
        info = dfsan_get_label_info(label);
    }

    needed = 0;
    if (info != NULL) {
        needed = dfsan_format_simplified_expression(label, NULL, 0);
    }
    if (needed == 0) {
        needed = strlen("<unavailable>");
        simplified = g_strdup("<unavailable>");
    } else {
        simplified = g_malloc(needed + 1);
        if (dfsan_format_simplified_expression(label, simplified, needed + 1) == 0) {
            g_free(simplified);
            simplified = g_strdup("<unavailable>");
        }
    }
    label_hex = g_strdup_printf("0x%x", label);

    qdict_put_str(entry, "label", label_hex);
    qdict_put_str(entry, "expression", simplified);
    qdict_put_str(entry, "op", ia_label_op_name(info ? info->op : 0xffff));
    if (info) {
        qdict_put_int(entry, "size", info->size);
        qdict_put_int(entry, "left_label", info->l1);
        qdict_put_int(entry, "right_label", info->l2);
        qdict_put_int(entry, "op1", info->op1.i);
        qdict_put_int(entry, "op2", info->op2.i);
    }
    return entry;
}

static void ia_append_path_constraint_entry(QList *entries, uint64_t pc,
                                            dfsan_label label, bool taken)
{
    QDict *entry = ia_make_symbolic_label_entry(label);
    g_autofree char *pc_hex = g_strdup_printf("0x%" PRIx64, pc);

    qdict_put_str(entry, "pc", pc_hex);
    qdict_put_bool(entry, "taken", taken);
    qlist_append(entries, entry);
}

static QDict *ia_make_symbolic_label_entry_with_taken(dfsan_label label, bool taken)
{
    QDict *entry = ia_make_symbolic_label_entry(label);

    qdict_put_bool(entry, "taken", taken);
    return entry;
}

static uint64_t ia_mask_for_bits(uint16_t size)
{
    if (size == 0 || size >= 64) {
        return UINT64_MAX;
    }
    return (1ULL << size) - 1ULL;
}

static void ia_append_subexpr_label(GString *out, dfsan_label label)
{
    g_string_append_printf(out, "<0x%x>", label);
}

static const char *ia_c_int_type_name(uint16_t size, bool is_signed)
{
    switch (size) {
    case 8:
        return is_signed ? "int8_t" : "uint8_t";
    case 16:
        return is_signed ? "int16_t" : "uint16_t";
    case 32:
        return is_signed ? "int32_t" : "uint32_t";
    case 64:
        return is_signed ? "int64_t" : "uint64_t";
    default:
        return is_signed ? "int64_t" : "uint64_t";
    }
}

static int64_t ia_sign_extend_immediate(uint16_t size, uint64_t imm)
{
    uint64_t masked = imm & ia_mask_for_bits(size);

    if (size == 0 || size >= 64) {
        return (int64_t)masked;
    }
    if ((masked & (1ULL << (size - 1))) == 0) {
        return (int64_t)masked;
    }
    return (int64_t)(masked | ~ia_mask_for_bits(size));
}

static void ia_append_immediate(GString *out, uint16_t size, uint64_t imm)
{
    uint64_t masked;
    int64_t signed_value;

    if (size == 1) {
        g_string_append(out, imm ? "true" : "false");
        return;
    }

    masked = imm & ia_mask_for_bits(size);
    signed_value = ia_sign_extend_immediate(size, imm);

    if (signed_value < 0 && signed_value >= -4096) {
        g_string_append_printf(out, "%" PRId64, signed_value);
        return;
    }
    if (masked <= 9) {
        g_string_append_printf(out, "%" PRIu64, masked);
        return;
    }
    g_string_append_printf(out, "0x%" PRIx64, masked);
}

static bool ia_append_operand(GString *out, dfsan_label child, uint16_t size, uint64_t imm, unsigned depth)
{
    if (child != 0) {
        return ia_format_symbolic_expression_inner(out, child, depth + 1);
    }
    ia_append_immediate(out, size, imm);
    return true;
}

static const char *ia_c_binary_op(uint16_t op)
{
    switch (op) {
    case Add: return "+";
    case Sub: return "-";
    case Mul: return "*";
    case UDiv:
    case SDiv: return "/";
    case URem:
    case SRem: return "%";
    case Shl: return "<<";
    case LShr:
    case AShr: return ">>";
    case And: return "&";
    case Or: return "|";
    case Xor: return "^";
    case Concat: return "/* concat */";
    default: return NULL;
    }
}

static const char *ia_icmp_predicate_symbol(uint64_t predicate)
{
    switch ((uint32_t)predicate) {
    case bveq: return "==";
    case bvneq: return "!=";
    case bvugt:
    case bvsgt: return ">";
    case bvuge:
    case bvsge: return ">=";
    case bvult:
    case bvslt: return "<";
    case bvule:
    case bvsle: return "<=";
    default: return "??";
    }
}

static bool ia_icmp_predicate_is_signed(uint64_t predicate)
{
    switch ((uint32_t)predicate) {
    case bvsgt:
    case bvsge:
    case bvslt:
    case bvsle:
        return true;
    default:
        return false;
    }
}

static bool ia_format_symbolic_expression_inner(GString *out, dfsan_label label, unsigned depth)
{
    IADfsanLabelInfo *info;
    uint16_t op;
    const char *binary_op;

    if (label == 0) {
        g_string_append(out, "concrete");
        return true;
    }
    if (depth > IA_EXPR_MAX_DEPTH || out->len > IA_EXPR_MAX_CHARS) {
        ia_append_subexpr_label(out, label);
        return true;
    }

    info = dfsan_get_label_info(label);
    if (!info) {
        g_string_append(out, "<invalid-label>");
        return false;
    }

    op = info->op & 0xff;

    if (info->op == 0) {
        g_string_append_printf(out, "input(%" PRIu64 ")", info->op1.i);
        return true;
    }

    switch (op) {
    case ZExt:
    case Trunc:
        g_string_append_printf(out, "((%s)", ia_c_int_type_name(info->size, false));
        g_string_append(out, " ");
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append(out, ")");
        return true;
    case SExt:
        g_string_append_printf(out, "((%s)", ia_c_int_type_name(info->size, true));
        g_string_append(out, " ");
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append(out, ")");
        return true;
    case IntToPtr:
        g_string_append(out, "((uintptr_t) ");
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append(out, ")");
        return true;
    case PtrToInt:
        g_string_append_printf(out, "((%s) ", ia_c_int_type_name(info->size, false));
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append(out, ")");
        return true;
    case Extract:
        g_string_append(out, "(((");
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append_printf(out, ") >> %" PRIu64 ") & ", info->op2.i);
        ia_append_immediate(out, info->size, ia_mask_for_bits(info->size));
        g_string_append(out, ")");
        return true;
    case Load:
        g_string_append_printf(out, "load_%s(", ia_c_int_type_name(info->size, false));
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append_printf(out, ", %u)", info->l2);
        return true;
    case Not:
        g_string_append(out, "(~");
        ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
        g_string_append(out, ")");
        return true;
    case Neg:
        g_string_append(out, "(-");
        ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
        g_string_append(out, ")");
        return true;
    case ICmp:
        g_string_append(out, "(");
        if (ia_icmp_predicate_is_signed(info->op >> 8)) {
            g_string_append_printf(out, "(%s)(", ia_c_int_type_name(info->size, true));
            ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
            g_string_append(out, ")");
        } else {
            ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        }
        g_string_append_printf(out, " %s ", ia_icmp_predicate_symbol(info->op >> 8));
        if (ia_icmp_predicate_is_signed(info->op >> 8)) {
            g_string_append_printf(out, "(%s)(", ia_c_int_type_name(info->size, true));
            ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
            g_string_append(out, ")");
        } else {
            ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
        }
        g_string_append(out, ")");
        return true;
    case fmemcmp:
        g_string_append(out, "fmemcmp(");
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        g_string_append(out, ", ");
        ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
        g_string_append_printf(out, ", size=%u)", info->size);
        return true;
    case fsize:
        g_string_append_printf(out, "fsize(%" PRIu64 ")", info->op1.i);
        return true;
    case Ite:
        g_string_append(out, "(");
        ia_append_operand(out, info->l1, 1, info->op1.i, depth);
        g_string_append(out, " ? ");
        ia_append_immediate(out, info->size, 1);
        g_string_append(out, " : ");
        ia_append_immediate(out, info->size, 0);
        g_string_append(out, ")");
        return true;
    default:
        binary_op = ia_c_binary_op(op);
        if (binary_op) {
            g_string_append(out, "(");
            ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
            g_string_append_printf(out, " %s ", binary_op);
            ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
            g_string_append(out, ")");
            return true;
        }
        g_string_append_printf(out, "%s(", ia_label_op_name(info->op));
        ia_append_operand(out, info->l1, info->size, info->op1.i, depth);
        if (info->l2 != 0 || info->op2.i != 0) {
            g_string_append(out, ", ");
            ia_append_operand(out, info->l2, info->size, info->op2.i, depth);
        }
        g_string_append(out, ")");
        return true;
    }
}

static QDict *ia_handle_get_symbolic_expression(int64_t id, QDict *params)
{
    dfsan_label label;
    IADfsanLabelInfo *info;
    Error *err = NULL;
    QDict *result;

    if (!params) {
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    if (!ia_parse_label_param(params, "label", &label, &err)) {
        const char *message = error_get_pretty(err);
        QDict *resp = ia_make_error_response(id, "invalid_params", message);
        error_free(err);
        return resp;
    }

    info = dfsan_get_label_info(label);
    if (!info) {
        return ia_make_error_response(id, "invalid_params", "label is not valid");
    }

    result = ia_make_symbolic_label_entry(label);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_get_path_constraints(int64_t id, QDict *params)
{
    dfsan_label label;
    size_t constraint_count;
    dfsan_label *constraint_labels = NULL;
    uint8_t *constraint_directions = NULL;
    uint8_t root_taken = 0;
    Error *err = NULL;
    QDict *result = NULL;
    QList *constraints = NULL;
    size_t i;

    if (!params) {
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    if (!ia_parse_label_param(params, "label", &label, &err)) {
        const char *message = error_get_pretty(err);
        QDict *resp = ia_make_error_response(id, "invalid_params", message);
        error_free(err);
        return resp;
    }
    if (label == 0 || label > dfsan_get_label_count() || !dfsan_get_label_info(label)) {
        return ia_make_error_response(id, "invalid_params", "label is not valid");
    }
    if (!dfsan_is_branch_condition_label ||
        !dfsan_get_branch_direction ||
        !dfsan_get_nested_constraint_count ||
        !dfsan_get_nested_constraints ||
        !dfsan_get_nested_constraint_directions) {
        return ia_make_error_response(id, "unsupported",
                                      "path-constraint introspection is unavailable in the current Symsan runtime");
    }
    if (!dfsan_is_branch_condition_label(label)) {
        return ia_make_error_response(id, "invalid_params",
                                      "label is not a branch-condition label");
    }

    constraint_count = dfsan_get_nested_constraint_count(label);
    if (constraint_count > 0) {
        constraint_labels = g_new(dfsan_label, constraint_count);
        constraint_directions = g_new0(uint8_t, constraint_count);
        constraint_count = dfsan_get_nested_constraints(label, constraint_labels,
                                                       constraint_count);
        if (constraint_count > 0) {
            size_t direction_count = dfsan_get_nested_constraint_directions(label,
                                                                            constraint_directions,
                                                                            constraint_count);
            if (direction_count < constraint_count) {
                constraint_count = direction_count;
            }
        }
    }

    if (!dfsan_get_branch_direction(label, &root_taken)) {
        g_free(constraint_directions);
        g_free(constraint_labels);
        return ia_make_error_response(id, "internal_error",
                                      "failed to recover branch direction for label");
    }

    result = qdict_new();
    constraints = qlist_new();
    qdict_put(result, "root", ia_make_symbolic_label_entry_with_taken(label, root_taken != 0));
    for (i = 0; i < constraint_count; i++) {
        qlist_append(constraints,
                     ia_make_symbolic_label_entry_with_taken(constraint_labels[i],
                                                             constraint_directions[i] != 0));
    }
    qdict_put(result, "constraints", constraints);
    qdict_put_int(result, "count", constraint_count);

    g_free(constraint_directions);
    g_free(constraint_labels);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_get_recent_path_constraints(int64_t id, QDict *params)
{
    int64_t limit = 16;
    size_t available;
    size_t count;
    size_t i;
    QDict *result = qdict_new();
    QList *entries = qlist_new();

    if (params && qdict_haskey(params, "limit")) {
        if (qdict_get_try_str(params, "limit") != NULL) {
            qobject_unref(entries);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_params",
                                          "limit must be an integer");
        }
        limit = qdict_get_try_int(params, "limit", -1);
        if (limit == 0 || limit > 256) {
            qobject_unref(entries);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_params",
                                          "limit must be between 1 and 256");
        }
    }

    qemu_mutex_lock(&ia_state.lock);
    available = ia_state.path_constraints_count;
    count = MIN((size_t)limit, available);
    for (i = 0; i < count; i++) {
        size_t idx = (ia_state.path_constraints_head + 256 - 1 - i) % 256;
        ia_append_path_constraint_entry(entries,
                                        ia_state.path_constraints[idx].pc,
                                        ia_state.path_constraints[idx].label,
                                        ia_state.path_constraints[idx].taken);
    }
    qemu_mutex_unlock(&ia_state.lock);

    qdict_put(result, "constraints", entries);
    qdict_put_int(result, "count", count);
    qdict_put_bool(result, "truncated", available > count);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_queue_stdin_chunk(int64_t id, QDict *params)
{
    int64_t size;
    bool symbolic;
    uint64_t stream_offset = 0;
    g_autofree char *stream_offset_hex = NULL;
    Error *err = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }

    size = qdict_get_try_int(params, "size", -1);
    if (size <= 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "size must be >= 1");
    }
    symbolic = qdict_get_try_bool(params, "symbolic", false);

    if (!ia_rpc_queue_stdin_chunk((uint64_t)size, symbolic, &stream_offset, &err)) {
        const char *message = error_get_pretty(err);
        QDict *resp = ia_make_error_response(id, "invalid_state", message);
        error_free(err);
        qobject_unref(result);
        return resp;
    }

    stream_offset_hex = g_strdup_printf("0x%" PRIx64, stream_offset);
    qemu_mutex_lock(&ia_state.lock);
    qdict_put_int(result, "size", size);
    qdict_put_bool(result, "symbolic", symbolic);
    qdict_put_str(result, "stream_offset", stream_offset_hex);
    qdict_put_int(result, "pending_stdin_bytes", ia_state.pending_stdin_bytes);
    qdict_put_int(result, "pending_symbolic_stdin_bytes",
                  ia_state.pending_symbolic_stdin_bytes);
    qemu_mutex_unlock(&ia_state.lock);
    return ia_make_ok_response(id, result);
}

static bool ia_symbolic_mode_active(void)
{
    return second_ccache_flag != 0;
}

static void ia_ensure_symbolic_mode_active(void)
{
    if (!ia_symbolic_mode_active()) {
        second_ccache_flag = 1;
    }
    if (noSymbolicData != 0) {
        noSymbolicData = 0;
    }
}

static dfsan_label ia_create_symbolic_value_label(uint32_t width_bits,
                                                  uint64_t base_offset, uint64_t pc)
{
    dfsan_label acc = 0;
    uint32_t byte_count;
    uint32_t i;

    if (width_bits == 0 || (width_bits % 8) != 0) {
        return 0;
    }

    byte_count = width_bits / 8;
    for (i = 0; i < byte_count; i++) {
        dfsan_label byte_label = dfsan_create_label((off_t)(base_offset + i));
        if (byte_label == 0) {
            return 0;
        }
        if (acc == 0) {
            acc = byte_label;
        } else {
            acc = dfsan_union(acc, byte_label, Concat, (i + 1) * 8, 0, 0, pc);
            if (acc == 0) {
                return 0;
            }
        }
    }
    return acc;
}

static void ia_symbolize_stdin_segment(uint8_t *host_ptr, size_t size,
                                       uint64_t stream_offset, uint64_t pc)
{
    size_t i;

    if (!host_ptr || size == 0) {
        return;
    }
    for (i = 0; i < size; i++) {
        dfsan_label label = dfsan_create_label((int)(stream_offset + i));
        dfsan_store_label(label, host_ptr + i, 1, pc);
    }
    ia_ensure_symbolic_mode_active();
}

bool ia_rpc_queue_stdin_chunk(uint64_t size, bool symbolic,
                              uint64_t *stream_offset, Error **errp)
{
    size_t tail;
    uint64_t chunk_stream_offset = 0;

    if (size == 0) {
        error_setg(errp, "size must be >= 1");
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    if (ia_state.stdin_chunks_count >= ARRAY_SIZE(ia_state.stdin_chunks)) {
        qemu_mutex_unlock(&ia_state.lock);
        error_setg(errp, "stdin chunk queue is full");
        return false;
    }

    if (symbolic) {
        chunk_stream_offset = ia_state.stdin_stream_next_offset;
        ia_state.stdin_stream_next_offset += size;
        ia_state.pending_symbolic_stdin_bytes += size;
    }

    tail = (ia_state.stdin_chunks_head + ia_state.stdin_chunks_count) %
           ARRAY_SIZE(ia_state.stdin_chunks);
    ia_state.stdin_chunks[tail].stream_offset = chunk_stream_offset;
    ia_state.stdin_chunks[tail].remaining = size;
    ia_state.stdin_chunks[tail].chunk_offset = 0;
    ia_state.stdin_chunks[tail].symbolic = symbolic;
    ia_state.stdin_chunks_count++;
    ia_state.pending_stdin_bytes += size;
    qemu_mutex_unlock(&ia_state.lock);

    if (stream_offset) {
        *stream_offset = chunk_stream_offset;
    }
    return true;
}

void ia_rpc_consume_stdin_read(int fd, void *host_buf, size_t size)
{
    uint8_t *cursor = host_buf;
    size_t remaining = size;

    if (!ia_state.enabled || fd != 0 || !host_buf || size == 0) {
        return;
    }

    qemu_mutex_lock(&ia_state.lock);
    while (remaining > 0 && ia_state.stdin_chunks_count > 0) {
        size_t head = ia_state.stdin_chunks_head;
        size_t consumed = MIN((uint64_t)remaining,
                              ia_state.stdin_chunks[head].remaining);
        uint64_t stream_offset =
            ia_state.stdin_chunks[head].stream_offset +
            ia_state.stdin_chunks[head].chunk_offset;
        bool symbolic = ia_state.stdin_chunks[head].symbolic;

        ia_state.stdin_chunks[head].remaining -= consumed;
        ia_state.stdin_chunks[head].chunk_offset += consumed;
        ia_state.pending_stdin_bytes -= consumed;
        if (symbolic) {
            ia_state.pending_symbolic_stdin_bytes -= consumed;
        }

        if (ia_state.stdin_chunks[head].remaining == 0) {
            ia_state.stdin_chunks_head =
                (ia_state.stdin_chunks_head + 1) %
                ARRAY_SIZE(ia_state.stdin_chunks);
            ia_state.stdin_chunks_count--;
        }

        CPUState *cpu;
        CPUArchState *env;
        qemu_mutex_unlock(&ia_state.lock);
        cpu = ia_state.current_cpu;
        if (!cpu) {
            return;
        }
        env = (CPUArchState *)cpu->env_ptr;
        if (symbolic) {
            ia_symbolize_stdin_segment(cursor, consumed, stream_offset, get_pc(env));
        }
        cursor += consumed;
        remaining -= consumed;
        qemu_mutex_lock(&ia_state.lock);
    }
    qemu_mutex_unlock(&ia_state.lock);
}

static void ia_trace_close_locked(void)
{
    if (ia_state.trace_file) {
        fclose(ia_state.trace_file);
        ia_state.trace_file = NULL;
    }
}

static bool ia_trace_open_locked(const char *requested_path, Error **errp)
{
    g_autofree char *trace_path = NULL;
    g_autofree char *trace_dir = NULL;
    int fd = -1;

    ia_trace_close_locked();
    g_clear_pointer(&ia_state.trace_path, g_free);
    ia_state.trace_seq = 0;

    if (requested_path && requested_path[0] != '\0') {
        trace_path = g_strdup(requested_path);
        fd = open(trace_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    } else {
        const char *socket_path = ia_state.socket_path ? ia_state.socket_path : g_get_tmp_dir();
        trace_dir = g_path_get_dirname(socket_path);
        trace_path = g_strdup_printf("%s/symfit-trace-XXXXXX", trace_dir);
        fd = g_mkstemp(trace_path);
    }

    if (fd < 0) {
        error_setg(errp, "failed to create trace file: %s", strerror(errno));
        return false;
    }

    ia_state.trace_file = fdopen(fd, "a+");
    if (!ia_state.trace_file) {
        close(fd);
        error_setg(errp, "failed to open trace file stream: %s", strerror(errno));
        return false;
    }

    setvbuf(ia_state.trace_file, NULL, _IOLBF, 0);
    ia_state.trace_path = g_strdup(trace_path);
    ia_trace_emit_backend_ready();
    return true;
}

static void ia_trace_append_status_locked(QDict *dict)
{
    qdict_put_bool(dict, "trace_active", ia_state.trace_file != NULL);
    if (ia_state.trace_path) {
        qdict_put_str(dict, "trace_file", ia_state.trace_path);
    }
    if (ia_state.trace_file) {
        qdict_put_str(dict, "trace_kind", "basic_block");
    }
}

static const char *ia_status_string_locked(void)
{
    switch (ia_state.exec_state) {
    case IA_EXEC_IDLE:
        return "idle";
    case IA_EXEC_RUNNING:
        return "running";
    case IA_EXEC_PAUSED:
        return "paused";
    case IA_EXEC_EXITED:
        return "exited";
    default:
        return "idle";
    }
}

static void ia_write_response(FILE *out, QDict *resp)
{
    QString *json = qobject_to_json(QOBJECT(resp));
    fprintf(out, "%s\n", qstring_get_str(json));
    fflush(out);
    qobject_unref(json);
}

static QDict *ia_make_error_response(int64_t id, const char *code,
                                     const char *message)
{
    QDict *resp = qdict_new();
    QDict *err = qdict_new();

    qdict_put_int(resp, "id", id);
    qdict_put_bool(resp, "ok", false);
    qdict_put_str(err, "code", code);
    qdict_put_str(err, "message", message);
    qdict_put(resp, "error", err);
    return resp;
}

static QDict *ia_make_ok_response(int64_t id, QDict *result)
{
    QDict *resp = qdict_new();
    qdict_put_int(resp, "id", id);
    qdict_put_bool(resp, "ok", true);
    qdict_put(resp, "result", result);
    return resp;
}

static bool ia_copy_requested_names(QList *names, const char **out_names, size_t *out_count)
{
    const QListEntry *entry;
    size_t i = 0;

    QLIST_FOREACH_ENTRY(names, entry) {
        QString *name = qobject_to(QString, qlist_entry_obj(entry));
        if (!name || i >= 64) {
            return false;
        }
        out_names[i++] = qstring_get_str(name);
    }
    *out_count = i;
    return true;
}

static QDict *ia_make_symbolic_byte_entry(size_t offset, dfsan_label label)
{
    QDict *entry = qdict_new();
    g_autofree char *label_hex = g_strdup_printf("0x%x", label);

    qdict_put_int(entry, "offset", (int64_t)offset);
    qdict_put_str(entry, "label", label_hex);
    qdict_put_bool(entry, "symbolic", label != 0);
    return entry;
}

static void ia_append_memory_labels(QList *bytes, const uint8_t *host_ptr, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++) {
        dfsan_label label = dfsan_read_label(host_ptr + i, 1);
        qlist_append(bytes, ia_make_symbolic_byte_entry(i, label));
    }
}

static bool ia_current_cpu_pc(CPUState *cpu, uint64_t *out)
{
    if (!cpu || !out) {
        return false;
    }
#if defined(TARGET_X86_64) || defined(TARGET_I386)
    {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        *out = env->eip;
        return true;
    }
#elif defined(TARGET_AARCH64)
    {
        CPUARMState *env = (CPUARMState *)cpu->env_ptr;
        *out = env->pc;
        return true;
    }
#else
    return false;
#endif
}

#if defined(TARGET_X86_64) || defined(TARGET_I386)
static bool ia_lookup_register_binding(CPUX86State *env, const char *name,
                                       target_ulong **out_shadow, uint64_t *out_value,
                                       uint32_t *out_width_bits, int *out_reg_index)
{
    if (strcmp(name, "esp") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ESP]; }
        if (out_value) { *out_value = env->regs[R_ESP]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_ESP; }
    } else if (strcmp(name, "ebp") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EBP]; }
        if (out_value) { *out_value = env->regs[R_EBP]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_EBP; }
    } else if (strcmp(name, "eax") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EAX]; }
        if (out_value) { *out_value = env->regs[R_EAX]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_EAX; }
    } else if (strcmp(name, "ebx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EBX]; }
        if (out_value) { *out_value = env->regs[R_EBX]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_EBX; }
    } else if (strcmp(name, "ecx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ECX]; }
        if (out_value) { *out_value = env->regs[R_ECX]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_ECX; }
    } else if (strcmp(name, "edx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EDX]; }
        if (out_value) { *out_value = env->regs[R_EDX]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_EDX; }
    } else if (strcmp(name, "esi") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ESI]; }
        if (out_value) { *out_value = env->regs[R_ESI]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_ESI; }
    } else if (strcmp(name, "edi") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EDI]; }
        if (out_value) { *out_value = env->regs[R_EDI]; }
        if (out_width_bits) { *out_width_bits = 32; }
        if (out_reg_index) { *out_reg_index = R_EDI; }
#if defined(TARGET_X86_64)
    } else if (strcmp(name, "rsp") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ESP]; }
        if (out_value) { *out_value = env->regs[R_ESP]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_ESP; }
    } else if (strcmp(name, "rbp") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EBP]; }
        if (out_value) { *out_value = env->regs[R_EBP]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_EBP; }
    } else if (strcmp(name, "rax") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EAX]; }
        if (out_value) { *out_value = env->regs[R_EAX]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_EAX; }
    } else if (strcmp(name, "rbx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EBX]; }
        if (out_value) { *out_value = env->regs[R_EBX]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_EBX; }
    } else if (strcmp(name, "rcx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ECX]; }
        if (out_value) { *out_value = env->regs[R_ECX]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_ECX; }
    } else if (strcmp(name, "rdx") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EDX]; }
        if (out_value) { *out_value = env->regs[R_EDX]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_EDX; }
    } else if (strcmp(name, "rsi") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_ESI]; }
        if (out_value) { *out_value = env->regs[R_ESI]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_ESI; }
    } else if (strcmp(name, "rdi") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_EDI]; }
        if (out_value) { *out_value = env->regs[R_EDI]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_EDI; }
    } else if (strcmp(name, "r8") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R8]; }
        if (out_value) { *out_value = env->regs[R_R8]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R8; }
    } else if (strcmp(name, "r9") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R9]; }
        if (out_value) { *out_value = env->regs[R_R9]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R9; }
    } else if (strcmp(name, "r10") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R10]; }
        if (out_value) { *out_value = env->regs[R_R10]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R10; }
    } else if (strcmp(name, "r11") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R11]; }
        if (out_value) { *out_value = env->regs[R_R11]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R11; }
    } else if (strcmp(name, "r12") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R12]; }
        if (out_value) { *out_value = env->regs[R_R12]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R12; }
    } else if (strcmp(name, "r13") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R13]; }
        if (out_value) { *out_value = env->regs[R_R13]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R13; }
    } else if (strcmp(name, "r14") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R14]; }
        if (out_value) { *out_value = env->regs[R_R14]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R14; }
    } else if (strcmp(name, "r15") == 0) {
        if (out_shadow) { *out_shadow = &env->shadow_regs[R_R15]; }
        if (out_value) { *out_value = env->regs[R_R15]; }
        if (out_width_bits) { *out_width_bits = 64; }
        if (out_reg_index) { *out_reg_index = R_R15; }
#endif
    } else {
        return false;
    }

    return true;
}

static bool ia_lookup_register_shadow(CPUArchState *env, const char *name,
                                      uint64_t *out_value, dfsan_label *out_label,
                                      uint32_t *out_width_bits)
{
    target_ulong *shadow = NULL;
    int reg_index = -1;

    if (strcmp(name, "pc") == 0 || strcmp(name, "eip") == 0) {
        *out_value = env->eip;
        *out_label = 0;
        if (out_width_bits) {
            *out_width_bits = 32;
        }
        return true;
#if defined(TARGET_X86_64)
    } else if (strcmp(name, "rip") == 0) {
        *out_value = env->eip;
        *out_label = 0;
        if (out_width_bits) {
            *out_width_bits = 64;
        }
        return true;
#endif
    } else if (!ia_lookup_register_binding(env, name, &shadow, out_value, out_width_bits, &reg_index)) {
        return false;
    }

    *out_label = *shadow;

    return true;
}

#endif

#if defined(TARGET_X86_64) || defined(TARGET_I386)
static bool ia_lookup_register(CPUX86State *env, const char *name, uint64_t *out)
{
    if (strcmp(name, "pc") == 0 || strcmp(name, "eip") == 0 || strcmp(name, "rip") == 0) {
        *out = env->eip;
    } else if (strcmp(name, "esp") == 0 || strcmp(name, "rsp") == 0) {
        *out = env->regs[R_ESP];
    } else if (strcmp(name, "ebp") == 0 || strcmp(name, "rbp") == 0) {
        *out = env->regs[R_EBP];
    } else if (strcmp(name, "eax") == 0 || strcmp(name, "rax") == 0) {
        *out = env->regs[R_EAX];
    } else if (strcmp(name, "ebx") == 0 || strcmp(name, "rbx") == 0) {
        *out = env->regs[R_EBX];
    } else if (strcmp(name, "ecx") == 0 || strcmp(name, "rcx") == 0) {
        *out = env->regs[R_ECX];
    } else if (strcmp(name, "edx") == 0 || strcmp(name, "rdx") == 0) {
        *out = env->regs[R_EDX];
    } else if (strcmp(name, "esi") == 0 || strcmp(name, "rsi") == 0) {
        *out = env->regs[R_ESI];
    } else if (strcmp(name, "edi") == 0 || strcmp(name, "rdi") == 0) {
        *out = env->regs[R_EDI];
#if defined(TARGET_X86_64)
    } else if (strcmp(name, "r8") == 0) {
        *out = env->regs[R_R8];
    } else if (strcmp(name, "r9") == 0) {
        *out = env->regs[R_R9];
    } else if (strcmp(name, "r10") == 0) {
        *out = env->regs[R_R10];
    } else if (strcmp(name, "r11") == 0) {
        *out = env->regs[R_R11];
    } else if (strcmp(name, "r12") == 0) {
        *out = env->regs[R_R12];
    } else if (strcmp(name, "r13") == 0) {
        *out = env->regs[R_R13];
    } else if (strcmp(name, "r14") == 0) {
        *out = env->regs[R_R14];
    } else if (strcmp(name, "r15") == 0) {
        *out = env->regs[R_R15];
#endif
    } else {
        return false;
    }
    return true;
}
#endif

#if defined(TARGET_AARCH64)
static bool ia_parse_aarch64_xreg(const char *name, unsigned int *out_index)
{
    unsigned int index = 0;
    const char *p = name;

    if (*p != 'x') {
        return false;
    }
    p++;
    if (*p < '0' || *p > '9') {
        return false;
    }
    while (*p >= '0' && *p <= '9') {
        index = index * 10 + (unsigned int)(*p - '0');
        if (index > 31) {
            return false;
        }
        p++;
    }
    if (*p != '\0') {
        return false;
    }
    *out_index = index;
    return true;
}

static bool ia_lookup_register_shadow(CPUARMState *env, const char *name,
                                      uint64_t *out_value, dfsan_label *out_label,
                                      uint32_t *out_width_bits)
{
    unsigned int index;

    if (strcmp(name, "pc") == 0) {
        *out_value = env->pc;
        *out_label = 0;
    } else if (strcmp(name, "sp") == 0) {
        *out_value = env->xregs[31];
        *out_label = env->shadow_xregs[31];
    } else if (ia_parse_aarch64_xreg(name, &index)) {
        *out_value = env->xregs[index];
        *out_label = env->shadow_xregs[index];
    } else {
        return false;
    }
    if (out_width_bits) {
        *out_width_bits = 64;
    }
    return true;
}

static bool ia_lookup_register(CPUARMState *env, const char *name, uint64_t *out)
{
    dfsan_label label;

    return ia_lookup_register_shadow(env, name, out, &label, NULL);
}

static bool ia_lookup_register_binding(CPUARMState *env, const char *name,
                                       target_ulong **out_shadow, uint64_t *out_value,
                                       uint32_t *out_width_bits, int *out_reg_index)
{
    unsigned int index;

    if (strcmp(name, "pc") == 0) {
        return false;
    } else if (strcmp(name, "sp") == 0) {
        index = 31;
    } else if (!ia_parse_aarch64_xreg(name, &index)) {
        return false;
    }

    if (out_shadow) {
        *out_shadow = &env->shadow_xregs[index];
    }
    if (out_value) {
        *out_value = env->xregs[index];
    }
    if (out_width_bits) {
        *out_width_bits = 64;
    }
    if (out_reg_index) {
        *out_reg_index = (int)index;
    }
    return true;
}
#endif

static QDict *ia_handle_query_status(int64_t id)
{
    QDict *result = qdict_new();
    g_autofree char *fault_hex = NULL;

    qemu_mutex_lock(&ia_state.lock);
    qdict_put_str(result, "status", ia_status_string_locked());
    qdict_put_str(result, "execution_mode", ia_symbolic_mode_active() ? "symbolic" : "concrete");
    qdict_put_int(result, "pending_stdin_bytes", ia_state.pending_stdin_bytes);
    qdict_put_int(result, "pending_symbolic_stdin_bytes",
                  ia_state.pending_symbolic_stdin_bytes);
    if (ia_state.has_exit_code) {
        qdict_put_int(result, "exit_code", ia_state.exit_code);
    }
    qdict_put_bool(result, "pending_termination", ia_state.pending_termination);
    if (ia_state.pending_termination) {
        switch (ia_state.termination_kind) {
        case IA_TERM_EXIT:
            qdict_put_str(result, "termination_kind", "exit");
            break;
        case IA_TERM_EXIT_GROUP:
            qdict_put_str(result, "termination_kind", "exit_group");
            break;
        case IA_TERM_SIGNAL:
            qdict_put_str(result, "termination_kind", "signal");
            qdict_put_int(result, "termination_signal", ia_state.termination_signal);
            qdict_put_int(result, "termination_si_code", ia_state.termination_si_code);
            fault_hex = g_strdup_printf("0x%" PRIx64, ia_state.termination_fault_addr);
            qdict_put_str(result, "termination_fault_address", fault_hex);
            break;
        default:
            break;
        }
    }
    ia_trace_append_status_locked(result);
    qemu_mutex_unlock(&ia_state.lock);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_capabilities(int64_t id)
{
    QDict *result = qdict_new();
    QDict *caps = qdict_new();

    qdict_put_int(result, "protocol_version", 1);
    qdict_put_bool(caps, "pause_resume", true);
    qdict_put_bool(caps, "read_registers", true);
    qdict_put_bool(caps, "read_memory", true);
    qdict_put_bool(caps, "read_symbolic_memory", true);
    qdict_put_bool(caps, "read_symbolic_expression", true);
    qdict_put_bool(caps, "read_path_constraints", true);
    qdict_put_bool(caps, "read_recent_path_constraints", true);
    qdict_put_bool(caps, "queue_stdin_chunk", true);
    qdict_put_bool(caps, "close", true);
    qdict_put_bool(caps, "symbolize_memory", true);
    qdict_put_bool(caps, "symbolize_register", true);
    qdict_put_bool(caps, "disassemble", true);
    qdict_put_bool(caps, "list_memory_maps", true);
    qdict_put_bool(caps, "take_snapshot", false);
    qdict_put_bool(caps, "restore_snapshot", false);
    qdict_put_bool(caps, "trace_basic_block", true);
    qdict_put_bool(caps, "trace_branch", false);
    qdict_put_bool(caps, "trace_memory", false);
    qdict_put_bool(caps, "trace_syscall", false);
    qdict_put_bool(caps, "run_until_address", true);
    qdict_put_bool(caps, "run_until_any_address", true);
    qdict_put_bool(caps, "single_step", true);
    qdict_put(result, "capabilities", caps);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_start_trace(int64_t id, QDict *params)
{
    bool basic_block = true;
    QDict *result = qdict_new();
    Error *err = NULL;
    g_autofree char *message = NULL;

    if (params) {
        basic_block = qdict_get_try_bool(params, "basic_block", true);
    }
    if (!basic_block) {
        qobject_unref(result);
        return ia_make_error_response(id, "unsupported_feature", "only basic_block tracing is supported");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.trace_file == NULL) {
        if (!ia_trace_open_locked(NULL, &err)) {
            qemu_mutex_unlock(&ia_state.lock);
            qobject_unref(result);
            message = g_strdup(error_get_pretty(err));
            error_free(err);
            return ia_make_error_response(id, "internal_error", message ? message : "failed to start trace");
        }
    }
    ia_trace_append_status_locked(result);
    qemu_mutex_unlock(&ia_state.lock);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_stop_trace(int64_t id)
{
    QDict *result = qdict_new();

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    ia_trace_close_locked();
    ia_trace_append_status_locked(result);
    qemu_mutex_unlock(&ia_state.lock);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_resume(int64_t id)
{
    QDict *result = qdict_new();

    qemu_mutex_lock(&ia_state.lock);
    ia_state.run_requested = true;
    if (!ia_state.pending_termination) {
        ia_state.exec_state = IA_EXEC_RUNNING;
    }
    qemu_cond_signal(&ia_state.cond);
    qemu_mutex_unlock(&ia_state.lock);

    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_pause(int64_t id)
{
    QDict *result = qdict_new();
    const char *status = NULL;
    CPUState *cpu = NULL;
    bool request_exit = false;

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }

    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        ia_state.block_budget = 0;
        ia_state.instruction_budget = 0;
        ia_state.stop_address_enabled = false;
        ia_state.stop_address_set_enabled = false;
        ia_state.stop_address_count = 0;
        ia_state.stop_address_matched = false;
        ia_state.start_paused = true;
        ia_state.run_requested = false;
        ia_state.pause_pending = true;
        cpu = ia_state.current_cpu;
        request_exit = cpu != NULL;
    }
    qemu_mutex_unlock(&ia_state.lock);

    if (request_exit) {
        cpu_exit(cpu);
    }

    qemu_mutex_lock(&ia_state.lock);
    while (ia_state.pause_pending &&
           ia_state.exec_state != IA_EXEC_EXITED &&
           !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }
    status = ia_status_string_locked();
    qemu_mutex_unlock(&ia_state.lock);

    qdict_put_str(result, "status", status);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_close(int64_t id)
{
    QDict *result = qdict_new();

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state",
                                      "close is only supported during terminal pause");
    }
    ia_state.close_requested = true;
    ia_state.start_paused = false;
    ia_state.run_requested = true;
    qemu_cond_signal(&ia_state.cond);
    qemu_mutex_unlock(&ia_state.lock);

    return ia_make_ok_response(id, result);
}

static bool ia_stop_address_set_contains_locked(uint64_t address)
{
    size_t i;

    if (ia_state.stop_address_enabled && ia_state.stop_address == address) {
        return true;
    }
    if (!ia_state.stop_address_set_enabled) {
        return false;
    }
    for (i = 0; i < ia_state.stop_address_count; i++) {
        if (ia_state.stop_addresses[i] == address) {
            return true;
        }
    }
    return false;
}

static QDict *ia_handle_set_breakpoints(int64_t id, QDict *params)
{
    QList *addresses;
    const QListEntry *entry;
    size_t count = 0;
    QDict *result = qdict_new();
    QList *installed = qlist_new();

    if (!params) {
        qobject_unref(installed);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addresses = qobject_to(QList, qdict_get(params, "addresses"));
    if (!addresses) {
        qobject_unref(installed);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "addresses must be a list");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(installed);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(installed);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is in terminal pause");
    }

    QLIST_FOREACH_ENTRY(addresses, entry) {
        QString *item = qobject_to(QString, qlist_entry_obj(entry));
        uint64_t address = 0;
        g_autofree char *address_hex = NULL;

        if (!item || count >= G_N_ELEMENTS(ia_state.stop_addresses) ||
            qemu_strtou64(qstring_get_str(item), NULL, 0, &address) != 0) {
            qemu_mutex_unlock(&ia_state.lock);
            qobject_unref(installed);
            qobject_unref(result);
            return ia_make_error_response(
                id,
                "invalid_params",
                "addresses must contain 0-64 hex strings"
            );
        }
        ia_state.stop_addresses[count++] = address;
        address_hex = g_strdup_printf("0x%" PRIx64, address);
        qlist_append_str(installed, address_hex);
    }

    ia_state.stop_address_enabled = false;
    ia_state.stop_address_set_enabled = count > 0;
    ia_state.stop_address_count = count;
    ia_state.stop_address_matched = false;
    ia_state.stop_address = 0;
    ia_state.last_matched_pc = 0;
    qdict_put_str(result, "status", ia_status_string_locked());
    qdict_put_bool(result, "armed", count > 0);
    qdict_put(result, "breakpoints", installed);
    qemu_mutex_unlock(&ia_state.lock);

    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_resume_until_address(int64_t id, QDict *params)
{
    const char *addr_str;
    uint64_t address;
    uint64_t stop_pc;
    uint64_t last_insn_pc;
    uint64_t last_matched_pc;
    bool matched;
    const char *status;
    CPUState *cpu;
    g_autofree char *pc_hex = NULL;
    g_autofree char *last_insn_hex = NULL;
    g_autofree char *matched_hex = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &address) != 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING &&
        !ia_stop_address_set_contains_locked(address)) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is already running");
    }
    if (ia_state.pause_pending ||
        ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state",
                                      ia_state.pending_termination
                                      ? "backend is in terminal pause"
                                      : "backend is already running");
    }

    if (ia_state.exec_state != IA_EXEC_RUNNING) {
        ia_state.stop_address_enabled = true;
        ia_state.stop_address_set_enabled = false;
        ia_state.stop_address_count = 0;
        ia_state.stop_address_matched = false;
        ia_state.stop_address = address;
        ia_state.instruction_budget = 0;
        ia_state.last_matched_pc = 0;
        ia_state.start_paused = false;
        ia_state.run_requested = true;
        ia_state.exec_state = IA_EXEC_RUNNING;
        qemu_cond_signal(&ia_state.cond);
    }

    while (((ia_state.stop_address_enabled || ia_state.stop_address_set_enabled) || ia_state.pause_pending) &&
           ia_state.exec_state != IA_EXEC_EXITED &&
           !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }


    stop_pc = ia_state.last_block_pc;
    last_insn_pc = ia_state.last_insn_pc;
    last_matched_pc = ia_state.last_matched_pc;
    matched = ia_state.stop_address_matched;
    cpu = ia_state.current_cpu;
    status = ia_status_string_locked();
    qemu_mutex_unlock(&ia_state.lock);

    if (strcmp(status, "paused") == 0) {
        ia_current_cpu_pc(cpu, &stop_pc);
    }

    qdict_put_str(result, "status", status);
    qdict_put_bool(result, "matched", matched);
    pc_hex = g_strdup_printf("0x%" PRIx64, stop_pc);
    qdict_put_str(result, "pc", pc_hex);
    last_insn_hex = g_strdup_printf("0x%" PRIx64, last_insn_pc);
    qdict_put_str(result, "last_insn_pc", last_insn_hex);
    matched_hex = g_strdup_printf("0x%" PRIx64, last_matched_pc);
    qdict_put_str(result, "matched_pc", matched_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_resume_until_any_address(int64_t id, QDict *params)
{
    QList *addresses;
    const QListEntry *entry;
    size_t count = 0;
    uint64_t stop_pc;
    uint64_t last_insn_pc;
    uint64_t last_matched_pc;
    bool matched;
    const char *status;
    CPUState *cpu;
    g_autofree char *pc_hex = NULL;
    g_autofree char *last_insn_hex = NULL;
    g_autofree char *matched_hex = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addresses = qobject_to(QList, qdict_get(params, "addresses"));
    if (!addresses) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "addresses must be a list");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.pause_pending || ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state",
                                      ia_state.pending_termination
                                      ? "backend is in terminal pause"
                                      : "backend is already running");
    }

    QLIST_FOREACH_ENTRY(addresses, entry) {
        QString *item = qobject_to(QString, qlist_entry_obj(entry));
        uint64_t address = 0;
        if (!item || count >= G_N_ELEMENTS(ia_state.stop_addresses) ||
            qemu_strtou64(qstring_get_str(item), NULL, 0, &address) != 0) {
            qemu_mutex_unlock(&ia_state.lock);
            qobject_unref(result);
            return ia_make_error_response(
                id,
                "invalid_params",
                "addresses must contain 1-64 hex strings"
            );
        }
        ia_state.stop_addresses[count++] = address;
    }

    if (count == 0) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "addresses must not be empty");
    }

    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        bool armed = false;
        size_t i;

        for (i = 0; i < count; i++) {
            if (ia_stop_address_set_contains_locked(ia_state.stop_addresses[i])) {
                armed = true;
                break;
            }
        }
        if (!armed) {
            qemu_mutex_unlock(&ia_state.lock);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_state", "backend is already running");
        }
    } else {
        ia_state.stop_address_enabled = false;
        ia_state.stop_address_set_enabled = true;
        ia_state.stop_address_count = count;
        ia_state.stop_address_matched = false;
        ia_state.stop_address = 0;
        ia_state.instruction_budget = 0;
        ia_state.last_matched_pc = 0;
        ia_state.start_paused = false;
        ia_state.run_requested = true;
        ia_state.exec_state = IA_EXEC_RUNNING;
        qemu_cond_signal(&ia_state.cond);
    }

    while (((ia_state.stop_address_enabled || ia_state.stop_address_set_enabled) || ia_state.pause_pending) &&
           ia_state.exec_state != IA_EXEC_EXITED &&
           !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }

    stop_pc = ia_state.last_block_pc;
    last_insn_pc = ia_state.last_insn_pc;
    last_matched_pc = ia_state.last_matched_pc;
    matched = ia_state.stop_address_matched;
    cpu = ia_state.current_cpu;
    status = ia_status_string_locked();
    qemu_mutex_unlock(&ia_state.lock);

    if (strcmp(status, "paused") == 0) {
        ia_current_cpu_pc(cpu, &stop_pc);
    }

    qdict_put_str(result, "status", status);
    qdict_put_bool(result, "matched", matched);
    pc_hex = g_strdup_printf("0x%" PRIx64, stop_pc);
    qdict_put_str(result, "pc", pc_hex);
    last_insn_hex = g_strdup_printf("0x%" PRIx64, last_insn_pc);
    qdict_put_str(result, "last_insn_pc", last_insn_hex);
    matched_hex = g_strdup_printf("0x%" PRIx64, last_matched_pc);
    qdict_put_str(result, "matched_pc", matched_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_resume_until_basic_block(int64_t id, QDict *params)
{
    int64_t count;
    uint64_t blocks_executed;
    uint64_t stop_pc;
    const char *status;
    CPUState *cpu;
    g_autofree char *pc_hex = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    count = qdict_get_try_int(params, "count", -1);
    if (count <= 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "count must be a positive integer");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending ||
        ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state",
                                      ia_state.pending_termination
                                      ? "backend is in terminal pause"
                                      : "backend is already running");
    }

    ia_state.block_budget = (uint64_t)count;
    ia_state.instruction_budget = 0;
    ia_state.start_paused = false;
    ia_state.run_requested = true;
    ia_state.exec_state = IA_EXEC_RUNNING;
    qemu_cond_signal(&ia_state.cond);

    while ((ia_state.block_budget > 0 || ia_state.pause_pending) &&
           ia_state.exec_state != IA_EXEC_EXITED &&
           !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }

    blocks_executed = (uint64_t)count - ia_state.block_budget;
    stop_pc = ia_state.last_block_pc;
    cpu = ia_state.current_cpu;
    status = ia_status_string_locked();
    qemu_mutex_unlock(&ia_state.lock);

    if (strcmp(status, "paused") == 0) {
        ia_current_cpu_pc(cpu, &stop_pc);
    }

    qdict_put_str(result, "status", status);
    qdict_put_int(result, "blocks_executed", blocks_executed);
    pc_hex = g_strdup_printf("0x%" PRIx64, stop_pc);
    qdict_put_str(result, "pc", pc_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_single_step(int64_t id, QDict *params)
{
    int64_t count;
    uint64_t budget_remaining;
    uint64_t executed;
    uint64_t stop_pc;
    const char *status;
    CPUState *cpu;
    g_autofree char *pc_hex = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    count = qdict_get_try_int(params, "count", -1);
    if (count <= 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "count must be a positive integer");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending ||
        ia_state.pending_termination) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state",
                                      ia_state.pending_termination
                                      ? "backend is in terminal pause"
                                      : "backend is already running");
    }

    ia_state.block_budget = 0;
    ia_state.stop_address_enabled = false;
    ia_state.stop_address_set_enabled = false;
    ia_state.stop_address_count = 0;
    ia_state.stop_address_matched = false;
    ia_state.stop_address = 0;
    ia_state.last_matched_pc = 0;
    /*
     * Instruction hook runs at instruction entry.  For stepping N instructions,
     * stop when we reach the (N+1)-th instruction entry.
     */
    ia_state.instruction_budget = (uint64_t)count + 1;
    ia_state.start_paused = false;
    ia_state.run_requested = true;
    ia_state.exec_state = IA_EXEC_RUNNING;
    qemu_cond_signal(&ia_state.cond);

    while ((ia_state.instruction_budget > 0 || ia_state.pause_pending) &&
           ia_state.exec_state != IA_EXEC_EXITED &&
           !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }

    budget_remaining = ia_state.instruction_budget;
    stop_pc = ia_state.last_insn_pc;
    cpu = ia_state.current_cpu;
    status = ia_status_string_locked();
    qemu_mutex_unlock(&ia_state.lock);

    if (budget_remaining >= (uint64_t)count + 1) {
        executed = 0;
    } else {
        executed = ((uint64_t)count + 1) - budget_remaining;
        if (executed > 0) {
            executed -= 1;
        }
    }

    if (strcmp(status, "paused") == 0) {
        ia_current_cpu_pc(cpu, &stop_pc);
    }

    qdict_put_str(result, "status", status);
    qdict_put_int(result, "count", count);
    qdict_put_int(result, "executed", executed);
    pc_hex = g_strdup_printf("0x%" PRIx64, stop_pc);
    qdict_put_str(result, "pc", pc_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_get_registers(int64_t id, QDict *params)
{
#if defined(TARGET_AARCH64)
    static const char *default_names[] = {
        "pc", "sp",
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30",
    };
#elif defined(TARGET_X86_64)
    static const char *default_names[] = {
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
#elif defined(TARGET_I386)
    static const char *default_names[] = {
        "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi",
    };
#else
    return ia_make_error_response(id, "unsupported_arch",
                                  "get_registers is only implemented for x86 and AArch64 targets");
#endif
    const char *requested[64];
    size_t count = G_N_ELEMENTS(default_names);
    QList *names = NULL;
    const char *const *name_list = default_names;
    CPUState *cpu;
    CPUArchState *env;
    QDict *regs = qdict_new();
    QDict *symbolic_regs = qdict_new();
    QDict *result = qdict_new();
    size_t i;

    if (params) {
        names = qobject_to(QList, qdict_get(params, "names"));
    }
    if (names && !qlist_empty(names)) {
        if (!ia_copy_requested_names(names, requested, &count)) {
            qobject_unref(regs);
            qobject_unref(symbolic_regs);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_params", "names must be an array of register strings");
        }
        name_list = requested;
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regs);
        qobject_unref(symbolic_regs);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regs);
        qobject_unref(symbolic_regs);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "registers are only available while paused");
    }
    cpu = ia_state.current_cpu;
    qemu_mutex_unlock(&ia_state.lock);

    env = (CPUArchState *)cpu->env_ptr;
    for (i = 0; i < count; i++) {
        uint64_t value;
        dfsan_label label;
        g_autofree char *label_hex = NULL;
        g_autofree char *hex = NULL;
        if (!ia_lookup_register(env, name_list[i], &value)) {
            continue;
        }
        hex = g_strdup_printf("0x%" PRIx64, value);
        qdict_put_str(regs, name_list[i], hex);

        if (!ia_lookup_register_shadow(env, name_list[i], &value, &label, NULL)) {
            continue;
        }
        {
            QDict *sym_reg = qdict_new();
            label_hex = g_strdup_printf("0x%x", label);
            qdict_put_bool(sym_reg, "symbolic", label != 0);
            qdict_put_str(sym_reg, "label", label_hex);
            qdict_put(symbolic_regs, name_list[i], sym_reg);
        }
    }
    qdict_put(result, "registers", regs);
    qdict_put(result, "symbolic_registers", symbolic_regs);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_read_memory(int64_t id, QDict *params)
{
    const char *addr_str;
    uint64_t addr;
    int64_t size;
    int rc;
    g_autofree uint8_t *buf = NULL;
    g_autofree char *bytes_hex = NULL;
    g_autofree char *norm_addr = NULL;
    CPUState *cpu;
    CPUState *saved_thread_cpu;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &addr) != 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }
    size = qdict_get_try_int(params, "size", -1);
    if (size < 0 || size > 256) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "size must be between 0 and 256");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "memory reads are only available while paused");
    }
    cpu = ia_state.current_cpu;
    qemu_mutex_unlock(&ia_state.lock);

    buf = g_malloc0(size > 0 ? (size_t)size : 1);
    saved_thread_cpu = thread_cpu;
    thread_cpu = cpu;
    rc = copy_from_user(buf, (abi_ulong)addr, size);
    thread_cpu = saved_thread_cpu;
    if (rc != 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_address", "guest memory read failed");
    }

    bytes_hex = g_malloc0((size_t)size * 2 + 1);
    for (int64_t i = 0; i < size; i++) {
        sprintf(bytes_hex + (i * 2), "%02x", buf[i]);
    }
    {
        void *label_ptr = lock_user(VERIFY_READ, (abi_ulong)addr, size, 0);
        QList *symbolic_bytes = qlist_new();
        if (!label_ptr && size > 0) {
            qobject_unref(symbolic_bytes);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_address", "guest symbolic memory read failed");
        }
        if (size > 0) {
            ia_append_memory_labels(symbolic_bytes, label_ptr, (size_t)size);
            unlock_user(label_ptr, (abi_ulong)addr, 0);
        }
        qdict_put(result, "symbolic_bytes", symbolic_bytes);
    }
    norm_addr = g_strdup_printf("0x%" PRIx64, addr);
    qdict_put_str(result, "address", norm_addr);
    qdict_put_int(result, "size", size);
    qdict_put_str(result, "bytes", bytes_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_read_symbolic_memory(int64_t id, QDict *params)
{
    const char *addr_str;
    uint64_t addr;
    int64_t size;
    void *host_ptr;
    QList *bytes = qlist_new();
    g_autofree char *norm_addr = NULL;
    QDict *result = qdict_new();

    if (!params) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &addr) != 0) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }
    size = qdict_get_try_int(params, "size", -1);
    if (size < 0 || size > 256) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "size must be between 0 and 256");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "symbolic memory reads are only available while paused");
    }
    qemu_mutex_unlock(&ia_state.lock);

    host_ptr = lock_user(VERIFY_READ, (abi_ulong)addr, size, 0);
    if (!host_ptr && size > 0) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_address", "guest symbolic memory read failed");
    }

    if (size > 0) {
        ia_append_memory_labels(bytes, host_ptr, (size_t)size);
        unlock_user(host_ptr, (abi_ulong)addr, 0);
    }

    norm_addr = g_strdup_printf("0x%" PRIx64, addr);
    qdict_put_str(result, "address", norm_addr);
    qdict_put_int(result, "size", size);
    qdict_put(result, "bytes", bytes);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_symbolize_memory(int64_t id, QDict *params)
{
    const char *addr_str;
    uint64_t addr;
    int64_t size;
    void *host_ptr;
    QList *bytes = qlist_new();
    g_autofree char *norm_addr = NULL;
    QDict *result = qdict_new();
    int64_t i;

    if (!params) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &addr) != 0) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }
    size = qdict_get_try_int(params, "size", -1);
    if (size <= 0 || size > 256) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "size must be between 1 and 256");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "symbolization is only available while paused");
    }

    CPUState *cpu;
    CPUArchState *env;
    cpu = ia_state.current_cpu;
    env = (CPUArchState *)cpu->env_ptr;
    uint64_t pc = get_pc(env);
    qemu_mutex_unlock(&ia_state.lock);

    host_ptr = lock_user(VERIFY_WRITE, (abi_ulong)addr, size, 0);
    if (!host_ptr) {
        qobject_unref(bytes);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_address", "guest memory symbolization failed");
    }

    for (i = 0; i < size; i++) {
        dfsan_label label = dfsan_create_label((int)i);
        dfsan_store_label(label, (uint8_t *)host_ptr + i, 1, pc);
    }
    ia_ensure_symbolic_mode_active();
    ia_append_memory_labels(bytes, host_ptr, (size_t)size);
    unlock_user(host_ptr, (abi_ulong)addr, 0);

    norm_addr = g_strdup_printf("0x%" PRIx64, addr);
    qdict_put_str(result, "address", norm_addr);
    qdict_put_int(result, "size", size);
    qdict_put(result, "bytes", bytes);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_symbolize_register(int64_t id, QDict *params)
{
    const char *name;
    CPUState *cpu;
    CPUArchState *env;
    target_ulong *shadow = NULL;
    uint64_t value = 0;
    uint32_t width_bits = 0;
    uint64_t base_offset = 0;
    dfsan_label reg_label;
    QDict *result = qdict_new();
    g_autofree char *value_hex = NULL;
    g_autofree char *label_hex = NULL;

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    name = qdict_get_try_str(params, "register");
    if (!name) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "register must be provided");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "symbolization is only available while paused");
    }
    cpu = ia_state.current_cpu;
    qemu_mutex_unlock(&ia_state.lock);

    // This reaaaaally shouldn't be just x86...
    env = (CPUArchState *)cpu->env_ptr;
    if (!ia_lookup_register_binding(env, name, &shadow, &value, &width_bits, NULL)) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "register is not supported for symbolization");
    }

    qemu_mutex_lock(&ia_state.lock);
    base_offset = ia_state.symbolic_value_next_offset;
    ia_state.symbolic_value_next_offset += MAX(1u, width_bits / 8);
    qemu_mutex_unlock(&ia_state.lock);

    reg_label = ia_create_symbolic_value_label(width_bits, base_offset, get_pc(env));
    if (reg_label == 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "internal_error", "failed to create symbolic register label");
    }
    *shadow = reg_label;
    ia_ensure_symbolic_mode_active();
    value_hex = g_strdup_printf("0x%" PRIx64, value);
    label_hex = g_strdup_printf("0x%x", reg_label);
    qdict_put_str(result, "register", name);
    qdict_put_str(result, "value", value_hex);
    qdict_put_bool(result, "symbolic", true);
    qdict_put_str(result, "label", label_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_list_memory_maps(int64_t id)
{
    CPUState *cpu = NULL;
    TaskState *ts = NULL;
    FILE *maps = NULL;
    char *line = NULL;
    size_t line_cap = 0;
    QDict *result = qdict_new();
    QList *regions = qlist_new();

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regions);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regions);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "memory maps are only available while paused");
    }
    cpu = ia_state.current_cpu;
    ts = cpu->opaque;
    qemu_mutex_unlock(&ia_state.lock);

    maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        qobject_unref(regions);
        qobject_unref(result);
        return ia_make_error_response(id, "internal_error", "failed to open /proc/self/maps");
    }

    while (getline(&line, &line_cap, maps) > 0) {
        unsigned long long start_addr = 0;
        unsigned long long end_addr = 0;
        unsigned long long offset = 0;
        unsigned long long inode = 0;
        abi_ulong guest_start;
        abi_ulong guest_end;
        int flags;
        char perms[5] = {0};
        char dev[16] = {0};
        char name_raw[4096] = {0};
        int fields;
        char perm_norm[4] = "---";
        QDict *entry;
        g_autofree char *start_hex = NULL;
        g_autofree char *end_hex = NULL;
        g_autofree char *offset_hex = NULL;

        fields = sscanf(line,
                        "%llx-%llx %4s %llx %15s %llu %4095[^\n]",
                        &start_addr, &end_addr, perms, &offset, dev, &inode, name_raw);
        if (fields < 6) {
            continue;
        }
        if (!h2g_valid(start_addr)) {
            continue;
        }

        guest_start = h2g(start_addr);
        guest_end = h2g_valid(end_addr - 1)
            ? h2g(end_addr - 1) + 1
            : GUEST_ADDR_MAX + 1;
        flags = page_get_flags(guest_start);
        if (!(flags & PAGE_VALID)) {
            continue;
        }
        if (page_check_range(guest_start, guest_end - guest_start, flags) == -1) {
            continue;
        }

        perm_norm[0] = (perms[0] != '\0') ? perms[0] : '-';
        perm_norm[1] = (perms[1] != '\0') ? perms[1] : '-';
        perm_norm[2] = (perms[2] != '\0') ? perms[2] : '-';

        entry = qdict_new();
        start_hex = g_strdup_printf("0x" TARGET_ABI_FMT_lx, guest_start);
        end_hex = g_strdup_printf("0x" TARGET_ABI_FMT_lx, guest_end);
        qdict_put_str(entry, "start", start_hex);
        qdict_put_str(entry, "end", end_hex);
        qdict_put_str(entry, "perm", perm_norm);
        offset_hex = g_strdup_printf("0x%llx", offset);
        qdict_put_str(entry, "offset", offset_hex);
        qdict_put_int(entry, "inode", (int64_t)inode);

        if (fields >= 7) {
            char *name_cursor = name_raw;
            const char *name;
            while (*name_cursor == ' ' || *name_cursor == '\t') {
                name_cursor++;
            }
            name = name_cursor;
            if (guest_start == ts->info->stack_limit) {
                name = "[stack]";
            }
            if (*name != '\0') {
                qdict_put_str(entry, "path", name);
                qdict_put_str(entry, "name", name);
            }
        } else if (guest_start == ts->info->stack_limit) {
            qdict_put_str(entry, "path", "[stack]");
            qdict_put_str(entry, "name", "[stack]");
        }

        qlist_append(regions, entry);
    }

    free(line);
    fclose(maps);
    qdict_put(result, "regions", regions);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_disassemble(int64_t id, QDict *params)
{
#ifndef CONFIG_CAPSTONE
    return ia_make_error_response(id, "unsupported_feature", "qemu was built without capstone support");
#else
    const char *addr_str;
    uint64_t pc;
    int64_t count;
    CPUState *cpu;
    csh handle;
    cs_insn *insn = NULL;
#if defined(TARGET_X86_64)
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_64;
#elif defined(TARGET_I386)
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_32;
#elif defined(TARGET_AARCH64)
    cs_arch arch = CS_ARCH_ARM64;
    cs_mode mode = CS_MODE_ARM;
#else
    cs_arch arch = -1;
    cs_mode mode = 0;
#endif
    QDict *result = qdict_new();
    QList *instructions = qlist_new();

    if (!params) {
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &pc) != 0) {
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }
    count = qdict_get_try_int(params, "count", -1);
    if (count <= 0 || count > 64) {
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "count must be between 1 and 64");
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "disassembly is only available while paused");
    }
    cpu = ia_state.current_cpu;
#if defined(TARGET_X86_64)
    {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        mode = (env->hflags & HF_CS64_MASK ? CS_MODE_64
                : env->hflags & HF_CS32_MASK ? CS_MODE_32
                : CS_MODE_16);
    }
#elif defined(TARGET_I386)
    mode = CS_MODE_32;
#endif
    qemu_mutex_unlock(&ia_state.lock);

#if defined(TARGET_WORDS_BIGENDIAN)
    mode += CS_MODE_BIG_ENDIAN;
#else
    mode += CS_MODE_LITTLE_ENDIAN;
#endif

    if (arch < 0) {
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "unsupported_arch", "disassemble is not implemented for this target");
    }
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "internal_error", "failed to initialize capstone");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    if (arch == CS_ARCH_X86) {
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }
    insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        qobject_unref(instructions);
        qobject_unref(result);
        return ia_make_error_response(id, "internal_error", "failed to allocate capstone instruction");
    }

    for (int64_t i = 0; i < count; i++) {
        uint8_t buf[32] = {0};
        const uint8_t *code = buf;
        size_t code_size = sizeof(buf);
        uint64_t cur_pc = pc;
        QDict *entry;
        g_autofree char *addr_hex = NULL;
        g_autofree char *bytes_hex = NULL;
        g_autofree char *text_repr = NULL;

        if (cpu_memory_rw_debug(cpu, cur_pc, buf, sizeof(buf), 0) != 0) {
            if (i == 0) {
                cs_free(insn, 1);
                cs_close(&handle);
                qobject_unref(instructions);
                qobject_unref(result);
                return ia_make_error_response(id, "invalid_address", "guest memory read failed during disassembly");
            }
            break;
        }
        if (!cs_disasm_iter(handle, &code, &code_size, &pc, insn)) {
            if (i == 0) {
                cs_free(insn, 1);
                cs_close(&handle);
                qobject_unref(instructions);
                qobject_unref(result);
                return ia_make_error_response(id, "invalid_address", "failed to disassemble requested address");
            }
            break;
        }

        entry = qdict_new();
        addr_hex = g_strdup_printf("0x%" PRIx64, insn->address);
        bytes_hex = g_malloc0((size_t)insn->size * 2 + 1);
        for (size_t j = 0; j < insn->size; j++) {
            sprintf(bytes_hex + (j * 2), "%02x", insn->bytes[j]);
        }
        if (insn->op_str[0] != '\0') {
            text_repr = g_strdup_printf("%s %s", insn->mnemonic, insn->op_str);
        } else {
            text_repr = g_strdup(insn->mnemonic);
        }

        qdict_put_str(entry, "address", addr_hex);
        qdict_put_int(entry, "size", insn->size);
        qdict_put_str(entry, "bytes", bytes_hex);
        qdict_put_str(entry, "text", text_repr);
        qlist_append(instructions, entry);
    }

    cs_free(insn, 1);
    cs_close(&handle);
    qdict_put(result, "instructions", instructions);
    return ia_make_ok_response(id, result);
#endif
}

static QDict *ia_dispatch_request(QDict *request)
{
    QObject *id_obj = qdict_get(request, "id");
    QDict *params = qobject_to(QDict, qdict_get(request, "params"));
    const char *method = qdict_get_try_str(request, "method");
    int64_t id = 0;

    if (!qobject_to(QNum, id_obj)) {
        return ia_make_error_response(0, "invalid_request", "id must be an integer");
    }
    id = qnum_get_int(qobject_to(QNum, id_obj));
    if (!method) {
        return ia_make_error_response(id, "invalid_request", "method is required");
    }
    if (strcmp(method, "capabilities") == 0) {
        return ia_handle_capabilities(id);
    }
    if (strcmp(method, "query_status") == 0) {
        return ia_handle_query_status(id);
    }
    if (strcmp(method, "resume") == 0) {
        return ia_handle_resume(id);
    }
    if (strcmp(method, "pause") == 0) {
        return ia_handle_pause(id);
    }
    if (strcmp(method, "close") == 0) {
        return ia_handle_close(id);
    }
    if (strcmp(method, "set_breakpoints") == 0) {
        return ia_handle_set_breakpoints(id, params);
    }
    if (strcmp(method, "start_trace") == 0) {
        return ia_handle_start_trace(id, params);
    }
    if (strcmp(method, "stop_trace") == 0) {
        return ia_handle_stop_trace(id);
    }
    if (strcmp(method, "resume_until_basic_block") == 0) {
        return ia_handle_resume_until_basic_block(id, params);
    }
    if (strcmp(method, "single_step") == 0) {
        return ia_handle_single_step(id, params);
    }
    if (strcmp(method, "resume_until_address") == 0) {
        return ia_handle_resume_until_address(id, params);
    }
    if (strcmp(method, "resume_until_any_address") == 0) {
        return ia_handle_resume_until_any_address(id, params);
    }
    if (strcmp(method, "get_registers") == 0) {
        return ia_handle_get_registers(id, params);
    }
    if (strcmp(method, "read_memory") == 0) {
        return ia_handle_read_memory(id, params);
    }
    if (strcmp(method, "get_symbolic_expression") == 0) {
        return ia_handle_get_symbolic_expression(id, params);
    }
    if (strcmp(method, "get_path_constraints") == 0) {
        return ia_handle_get_path_constraints(id, params);
    }
    if (strcmp(method, "get_recent_path_constraints") == 0) {
        return ia_handle_get_recent_path_constraints(id, params);
    }
    if (strcmp(method, "queue_stdin_chunk") == 0) {
        return ia_handle_queue_stdin_chunk(id, params);
    }
    if (strcmp(method, "read_symbolic_memory") == 0) {
        return ia_handle_read_symbolic_memory(id, params);
    }
    if (strcmp(method, "symbolize_memory") == 0) {
        return ia_handle_symbolize_memory(id, params);
    }
    if (strcmp(method, "symbolize_register") == 0) {
        return ia_handle_symbolize_register(id, params);
    }
    if (strcmp(method, "list_memory_maps") == 0) {
        return ia_handle_list_memory_maps(id);
    }
    if (strcmp(method, "disassemble") == 0) {
        return ia_handle_disassemble(id, params);
    }
    return ia_make_error_response(id, "unknown_method", "unknown instrumentation RPC method");
}

static void ia_handle_client(int fd)
{
    FILE *io = fdopen(fd, "r+");
    char *line = NULL;
    size_t cap = 0;

    if (!io) {
        close(fd);
        return;
    }

    while (getline(&line, &cap, io) >= 0) {
        Error *err = NULL;
        QObject *obj = qobject_from_json(line, &err);
        QDict *resp = NULL;
        QDict *req;

        if (err || !obj) {
            resp = ia_make_error_response(0, "invalid_request", "malformed JSON request");
            ia_write_response(io, resp);
            qobject_unref(resp);
            error_free(err);
            continue;
        }
        req = qobject_to(QDict, obj);
        if (!req) {
            resp = ia_make_error_response(0, "invalid_request", "request must be a JSON object");
            ia_write_response(io, resp);
            qobject_unref(resp);
            qobject_unref(obj);
            continue;
        }
        resp = ia_dispatch_request(req);
        ia_write_response(io, resp);
        qobject_unref(resp);
        qobject_unref(obj);
    }

    g_free(line);
    fclose(io);
}

static void *ia_server_thread(void *opaque)
{
    while (true) {
        int client_fd;

        qemu_mutex_lock(&ia_state.lock);
        if (ia_state.shutting_down) {
            qemu_mutex_unlock(&ia_state.lock);
            break;
        }
        qemu_mutex_unlock(&ia_state.lock);

        client_fd = accept(ia_state.listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        ia_handle_client(client_fd);
    }
    return NULL;
}

void ia_rpc_init(CPUState *cpu)
{
    struct sockaddr_un addr;
    const char *socket_path = getenv("IA_RPC_SOCKET");
    const char *trace_path = getenv("IA_TRACE_FILE");
    Error *err = NULL;

    if (!socket_path || !*socket_path) {
        return;
    }

    symsan_reset_load_metadata();
    qemu_mutex_init(&ia_state.lock);
    qemu_cond_init(&ia_state.cond);
    qemu_mutex_lock(&ia_state.lock);
    if (ia_state.enabled) {
        ia_state.current_cpu = cpu;
        ia_state.attached = true;
        qemu_mutex_unlock(&ia_state.lock);
        return;
    }

    ia_state.listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ia_state.listen_fd < 0) {
        qemu_mutex_unlock(&ia_state.lock);
        error_report("ia-rpc: failed to create socket: %s", strerror(errno));
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    pstrcpy(addr.sun_path, sizeof(addr.sun_path), socket_path);
    unlink(socket_path);
    if (bind(ia_state.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        error_report("ia-rpc: failed to bind %s: %s", socket_path, strerror(errno));
        close(ia_state.listen_fd);
        ia_state.listen_fd = -1;
        qemu_mutex_unlock(&ia_state.lock);
        return;
    }
    if (listen(ia_state.listen_fd, 1) < 0) {
        error_report("ia-rpc: failed to listen on %s: %s", socket_path, strerror(errno));
        close(ia_state.listen_fd);
        ia_state.listen_fd = -1;
        unlink(socket_path);
        qemu_mutex_unlock(&ia_state.lock);
        return;
    }

    ia_state.socket_path = g_strdup(socket_path);
    ia_state.current_cpu = cpu;
    ia_state.attached = true;
    ia_state.start_paused = true;
    ia_state.run_requested = false;
    ia_state.pause_pending = false;
    ia_state.block_budget = 0;
    ia_state.instruction_budget = 0;
    ia_state.stop_address_enabled = false;
    ia_state.stop_address_set_enabled = false;
    ia_state.stop_address_count = 0;
    ia_state.stop_address_matched = false;
    ia_state.stop_address = 0;
    ia_state.last_block_pc = 0;
    ia_state.last_insn_pc = 0;
    ia_state.last_matched_pc = 0;
    ia_state.trace_seq = 0;
    ia_trace_close_locked();
    g_clear_pointer(&ia_state.trace_path, g_free);
    if (trace_path && trace_path[0] != '\0') {
        err = NULL;
        if (!ia_trace_open_locked(trace_path, &err)) {
            error_report("ia-rpc: %s", error_get_pretty(err));
            error_free(err);
        }
    }
    ia_state.exec_state = IA_EXEC_PAUSED;
    ia_state.enabled = true;
    ia_state.shutting_down = false;
    qemu_thread_create(&ia_state.server_thread, "ia-rpc", ia_server_thread,
                       NULL, QEMU_THREAD_DETACHED);
    qemu_mutex_unlock(&ia_state.lock);
}

void ia_rpc_shutdown(void)
{
    if (!ia_state.enabled) {
        return;
    }
    symsan_reset_load_metadata();
    qemu_mutex_lock(&ia_state.lock);
    ia_state.shutting_down = true;
    ia_state.attached = false;
    ia_state.exec_state = IA_EXEC_EXITED;
    qemu_cond_broadcast(&ia_state.cond);
    if (ia_state.listen_fd >= 0) {
        close(ia_state.listen_fd);
        ia_state.listen_fd = -1;
    }
    if (ia_state.socket_path) {
        unlink(ia_state.socket_path);
        g_clear_pointer(&ia_state.socket_path, g_free);
    }
    ia_trace_close_locked();
    g_clear_pointer(&ia_state.trace_path, g_free);
    qemu_mutex_unlock(&ia_state.lock);
}

void ia_wait_if_paused(void)
{
    if (!ia_state.enabled) {
        return;
    }

    qemu_mutex_lock(&ia_state.lock);
    while (ia_state.start_paused && !ia_state.run_requested && !ia_state.shutting_down) {
        qemu_cond_wait(&ia_state.cond, &ia_state.lock);
    }
    if (ia_state.run_requested) {
        ia_state.start_paused = false;
        ia_state.run_requested = false;
        ia_state.exec_state = IA_EXEC_RUNNING;
    }
    qemu_mutex_unlock(&ia_state.lock);
}

bool ia_rpc_pause_on_exit(int code, bool group_exit)
{
    if (!ia_state.enabled) {
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    ia_state.pending_termination = true;
    ia_state.termination_kind = group_exit ? IA_TERM_EXIT_GROUP : IA_TERM_EXIT;
    ia_state.termination_signal = 0;
    ia_state.termination_si_code = 0;
    ia_state.termination_fault_addr = 0;
    ia_state.exit_code = code;
    ia_state.has_exit_code = true;
    ia_enter_terminal_pause_locked();
    qemu_mutex_unlock(&ia_state.lock);
    return true;
}

bool ia_rpc_pause_on_signal(int sig, int si_code, uint64_t fault_addr)
{
    if (!ia_state.enabled) {
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    ia_state.pending_termination = true;
    ia_state.termination_kind = IA_TERM_SIGNAL;
    ia_state.termination_signal = sig;
    ia_state.termination_si_code = si_code;
    ia_state.termination_fault_addr = fault_addr;
    ia_state.has_exit_code = false;
    ia_enter_terminal_pause_locked();
    qemu_mutex_unlock(&ia_state.lock);
    return true;
}

bool ia_rpc_finalize_pending_termination(CPUArchState *env)
{
    IATerminationKind kind;
    int code;
    int sig;
    int si_code;
    uint64_t fault_addr;

    if (!ia_state.enabled) {
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.pending_termination || ia_state.start_paused) {
        qemu_mutex_unlock(&ia_state.lock);
        return false;
    }

    kind = ia_state.termination_kind;
    code = ia_state.exit_code;
    sig = ia_state.termination_signal;
    si_code = ia_state.termination_si_code;
    fault_addr = ia_state.termination_fault_addr;
    ia_state.pending_termination = false;
    ia_state.termination_kind = IA_TERM_NONE;
    ia_state.termination_signal = 0;
    ia_state.termination_si_code = 0;
    ia_state.termination_fault_addr = 0;
    ia_state.close_requested = false;
    ia_state.exec_state = IA_EXEC_RUNNING;
    qemu_mutex_unlock(&ia_state.lock);

    switch (kind) {
    case IA_TERM_EXIT:
        preexit_cleanup(env, code);
        _exit(code);
        break;
    case IA_TERM_EXIT_GROUP:
        preexit_cleanup(env, code);
        _exit(code);
        break;
    case IA_TERM_SIGNAL: {
        target_siginfo_t info;
        memset(&info, 0, sizeof(info));
        info.si_signo = sig;
        info.si_errno = 0;
        info.si_code = si_code;
        info._sifields._sigfault._addr = (abi_ulong)fault_addr;
        queue_signal(env, sig, QEMU_SI_FAULT, &info);
        process_pending_signals(env);
        return true;
    }
    case IA_TERM_NONE:
    default:
        break;
    }

    return true;
}

void ia_rpc_set_exec_state(IAExecState state)
{
    if (!ia_state.enabled) {
        return;
    }
    qemu_mutex_lock(&ia_state.lock);
    ia_state.exec_state = state;
    if (state == IA_EXEC_PAUSED) {
        ia_state.pause_pending = false;
        qemu_cond_broadcast(&ia_state.cond);
    } else if (state == IA_EXEC_EXITED) {
        qemu_cond_broadcast(&ia_state.cond);
    }
    qemu_mutex_unlock(&ia_state.lock);
}

bool ia_rpc_should_pause_after_trap(void)
{
    bool should_pause;

    if (!ia_state.enabled) {
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    should_pause = ia_state.pause_pending;
    qemu_mutex_unlock(&ia_state.lock);

    return should_pause;
}

void ia_rpc_set_exit_code(int code)
{
    if (!ia_state.enabled) {
        return;
    }
    qemu_mutex_lock(&ia_state.lock);
    ia_state.exit_code = code;
    ia_state.has_exit_code = true;
    ia_state.pause_pending = false;
    ia_state.stop_address_enabled = false;
    ia_state.stop_address_set_enabled = false;
    ia_state.stop_address_count = 0;
    ia_state.stop_address_matched = false;
    ia_state.instruction_budget = 0;
    ia_state.exec_state = IA_EXEC_EXITED;
    qemu_cond_broadcast(&ia_state.cond);
    qemu_mutex_unlock(&ia_state.lock);
}

void symsan_record_path_constraint(uint64_t pc, dfsan_label label, bool taken)
{
    size_t idx;
    size_t max_label;

    if (label == 0 || !ia_state.enabled) {
        return;
    }

    max_label = dfsan_get_label_count();
    if (label > max_label) {
        fprintf(stderr,
                "[ia-pc] dropping invalid path constraint label=0x%x pc=0x%" PRIx64
                " taken=%d max_label=0x%zx\n",
                label, pc, taken ? 1 : 0, max_label);
        return;
    }

    qemu_mutex_lock(&ia_state.lock);
    idx = ia_state.path_constraints_head;
    ia_state.path_constraints[idx].pc = pc;
    ia_state.path_constraints[idx].label = label;
    ia_state.path_constraints[idx].taken = taken;
    ia_state.path_constraints_head = (idx + 1) % G_N_ELEMENTS(ia_state.path_constraints);
    if (ia_state.path_constraints_count < G_N_ELEMENTS(ia_state.path_constraints)) {
        ia_state.path_constraints_count++;
    }
    qemu_mutex_unlock(&ia_state.lock);

    if (ia_debug_path_constraints_enabled()) {
        fprintf(stderr, "[ia-pc] record pc=0x%" PRIx64 " label=0x%x taken=%d count=%zu\n",
                pc, label, taken ? 1 : 0, ia_state.path_constraints_count);
    }
}

bool ia_should_stop_before_instruction(CPUState *cpu, vaddr pc)
{
    bool should_stop = false;

    if (!ia_state.enabled) {
        return false;
    }

    qemu_mutex_lock(&ia_state.lock);
    ia_state.current_cpu = cpu;
    ia_state.last_insn_pc = pc;
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        bool address_match = false;
        if (ia_state.stop_address_enabled && ia_state.stop_address == (uint64_t)pc) {
            address_match = true;
            ia_state.stop_address_enabled = false;
        } else if (ia_state.stop_address_set_enabled) {
            size_t i;
            for (i = 0; i < ia_state.stop_address_count; i++) {
                if (ia_state.stop_addresses[i] == (uint64_t)pc) {
                    address_match = true;
                    break;
                }
            }
            if (address_match) {
                ia_state.stop_address_set_enabled = false;
                ia_state.stop_address_count = 0;
            }
        }
        if (address_match) {
            ia_state.stop_address_enabled = false;
            ia_state.stop_address_matched = true;
            ia_state.last_matched_pc = pc;
            ia_state.start_paused = true;
            ia_state.run_requested = false;
            ia_state.pause_pending = true;
            should_stop = true;
        } else if (ia_state.instruction_budget > 0) {
            ia_state.instruction_budget--;
            if (ia_state.instruction_budget == 0) {
                ia_state.start_paused = true;
                ia_state.run_requested = false;
                ia_state.pause_pending = true;
                should_stop = true;
            }
        }
    }
    qemu_mutex_unlock(&ia_state.lock);

    return should_stop;
}

void ia_on_basic_block_executed(CPUState *cpu, vaddr pc)
{
    bool request_exit = false;

    if (!ia_state.enabled) {
        return;
    }

    qemu_mutex_lock(&ia_state.lock);
    ia_state.current_cpu = cpu;
    ia_state.last_block_pc = pc;
    ia_trace_emit_basic_block(cpu, pc);
    if (ia_state.exec_state == IA_EXEC_RUNNING && ia_state.block_budget > 0) {
        ia_state.block_budget--;
        if (ia_state.block_budget == 0) {
            ia_state.start_paused = true;
            ia_state.run_requested = false;
            ia_state.pause_pending = true;
            request_exit = true;
        }
    }
    qemu_mutex_unlock(&ia_state.lock);

    if (request_exit) {
        cpu_exit(cpu);
    }
}
