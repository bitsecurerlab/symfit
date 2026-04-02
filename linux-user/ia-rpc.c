#include "qemu/osdep.h"

#include <sys/socket.h>
#include <sys/un.h>
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
#include "target/i386/cpu.h"
#include "ia-rpc.h"

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
    uint64_t trace_seq;
    QemuThread server_thread;
} IAState;

static IAState ia_state = {
    .listen_fd = -1,
};

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
        if (!name || i >= 32) {
            return false;
        }
        out_names[i++] = qstring_get_str(name);
    }
    *out_count = i;
    return true;
}

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

static QDict *ia_handle_query_status(int64_t id)
{
    QDict *result = qdict_new();

    qemu_mutex_lock(&ia_state.lock);
    qdict_put_str(result, "status", ia_status_string_locked());
    if (ia_state.has_exit_code) {
        qdict_put_int(result, "exit_code", ia_state.exit_code);
    }
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
    qdict_put_bool(caps, "disassemble", true);
    qdict_put_bool(caps, "list_memory_maps", true);
    qdict_put_bool(caps, "take_snapshot", false);
    qdict_put_bool(caps, "restore_snapshot", false);
    qdict_put_bool(caps, "trace_basic_block", ia_state.trace_file != NULL);
    qdict_put_bool(caps, "trace_branch", false);
    qdict_put_bool(caps, "trace_memory", false);
    qdict_put_bool(caps, "trace_syscall", false);
    qdict_put_bool(caps, "run_until_address", true);
    qdict_put_bool(caps, "run_until_any_address", true);
    qdict_put_bool(caps, "single_step", true);
    qdict_put(result, "capabilities", caps);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_resume(int64_t id)
{
    QDict *result = qdict_new();

    qemu_mutex_lock(&ia_state.lock);
    ia_state.run_requested = true;
    ia_state.exec_state = IA_EXEC_RUNNING;
    qemu_cond_signal(&ia_state.cond);
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
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is already running");
    }

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

#ifdef TARGET_X86_64
    if (cpu && strcmp(status, "paused") == 0) {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        stop_pc = env->eip;
    }
#endif

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
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is already running");
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

#ifdef TARGET_X86_64
    if (cpu && strcmp(status, "paused") == 0) {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        stop_pc = env->eip;
    }
#endif

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
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is already running");
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

#ifdef TARGET_X86_64
    if (cpu && strcmp(status, "paused") == 0) {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        stop_pc = env->eip;
    }
#endif

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
    if (ia_state.exec_state == IA_EXEC_RUNNING || ia_state.pause_pending) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "backend is already running");
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

#ifdef TARGET_X86_64
    if (cpu && strcmp(status, "paused") == 0) {
        CPUX86State *env = (CPUX86State *)cpu->env_ptr;
        stop_pc = env->eip;
    }
#endif

    qdict_put_str(result, "status", status);
    qdict_put_int(result, "count", count);
    qdict_put_int(result, "executed", executed);
    pc_hex = g_strdup_printf("0x%" PRIx64, stop_pc);
    qdict_put_str(result, "pc", pc_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_get_registers(int64_t id, QDict *params)
{
#if !defined(TARGET_X86_64) && !defined(TARGET_I386)
    return ia_make_error_response(id, "unsupported_arch", "get_registers is only implemented for x86 targets");
#else
#if defined(TARGET_X86_64)
    static const char *default_names[] = {
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
#else
    static const char *default_names[] = {
        "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi",
    };
#endif
    const char *requested[32];
    size_t count = G_N_ELEMENTS(default_names);
    QList *names = NULL;
    const char *const *name_list = default_names;
    CPUState *cpu;
    CPUX86State *env;
    QDict *regs = qdict_new();
    QDict *result = qdict_new();
    size_t i;

    if (params) {
        names = qobject_to(QList, qdict_get(params, "names"));
    }
    if (names && !qlist_empty(names)) {
        if (!ia_copy_requested_names(names, requested, &count)) {
            qobject_unref(regs);
            qobject_unref(result);
            return ia_make_error_response(id, "invalid_params", "names must be an array of register strings");
        }
        name_list = requested;
    }

    qemu_mutex_lock(&ia_state.lock);
    if (!ia_state.attached || !ia_state.current_cpu) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regs);
        qobject_unref(result);
        return ia_make_error_response(id, "not_attached", "backend is not attached");
    }
    if (ia_state.exec_state == IA_EXEC_RUNNING) {
        qemu_mutex_unlock(&ia_state.lock);
        qobject_unref(regs);
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_state", "registers are only available while paused");
    }
    cpu = ia_state.current_cpu;
    qemu_mutex_unlock(&ia_state.lock);

    env = (CPUX86State *)cpu->env_ptr;
    for (i = 0; i < count; i++) {
        uint64_t value;
        g_autofree char *hex = NULL;
        if (!ia_lookup_register(env, name_list[i], &value)) {
            continue;
        }
        hex = g_strdup_printf("0x%" PRIx64, value);
        qdict_put_str(regs, name_list[i], hex);
    }
    qdict_put(result, "registers", regs);
    return ia_make_ok_response(id, result);
#endif
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
    norm_addr = g_strdup_printf("0x%" PRIx64, addr);
    qdict_put_str(result, "address", norm_addr);
    qdict_put_int(result, "size", size);
    qdict_put_str(result, "bytes", bytes_hex);
    return ia_make_ok_response(id, result);
}

static QDict *ia_handle_list_memory_maps(int64_t id)
{
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

        perm_norm[0] = (perms[0] != '\0') ? perms[0] : '-';
        perm_norm[1] = (perms[1] != '\0') ? perms[1] : '-';
        perm_norm[2] = (perms[2] != '\0') ? perms[2] : '-';

        entry = qdict_new();
        start_hex = g_strdup_printf("0x%llx", start_addr);
        end_hex = g_strdup_printf("0x%llx", end_addr);
        qdict_put_str(entry, "start", start_hex);
        qdict_put_str(entry, "end", end_hex);
        qdict_put_str(entry, "perm", perm_norm);
        offset_hex = g_strdup_printf("0x%llx", offset);
        qdict_put_str(entry, "offset", offset_hex);
        qdict_put_int(entry, "inode", (int64_t)inode);

        if (fields >= 7) {
            char *name = name_raw;
            while (*name == ' ' || *name == '\t') {
                name++;
            }
            if (*name != '\0') {
                qdict_put_str(entry, "path", name);
                qdict_put_str(entry, "name", name);
            }
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
#if !defined(TARGET_X86_64) && !defined(TARGET_I386)
    return ia_make_error_response(id, "unsupported_arch", "disassemble is only implemented for x86 targets");
#else
    const char *addr_str;
    uint64_t pc;
    int64_t count;
    CPUState *cpu;
    csh handle;
    cs_insn *insn = NULL;
    #if defined(TARGET_X86_64)
    cs_mode mode = CS_MODE_64;
#else
    cs_mode mode = CS_MODE_32;
#endif
    QDict *result = qdict_new();
    QList *instructions = qlist_new();

    if (!params) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "params are required");
    }
    addr_str = qdict_get_try_str(params, "address");
    if (!addr_str || qemu_strtou64(addr_str, NULL, 0, &pc) != 0) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "address must be a hex string");
    }
    count = qdict_get_try_int(params, "count", -1);
    if (count <= 0 || count > 64) {
        qobject_unref(result);
        return ia_make_error_response(id, "invalid_params", "count must be between 1 and 64");
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

    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
        qobject_unref(result);
        return ia_make_error_response(id, "internal_error", "failed to initialize capstone");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
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

    if (!socket_path || !*socket_path) {
        return;
    }

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
    if (ia_state.trace_file) {
        fclose(ia_state.trace_file);
        ia_state.trace_file = NULL;
    }
    if (trace_path && trace_path[0] != '\0') {
        ia_state.trace_file = fopen(trace_path, "a");
        if (!ia_state.trace_file) {
            error_report("ia-rpc: failed to open IA_TRACE_FILE %s: %s", trace_path, strerror(errno));
        } else {
            setvbuf(ia_state.trace_file, NULL, _IOLBF, 0);
            ia_trace_emit_backend_ready();
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
    if (ia_state.trace_file) {
        fclose(ia_state.trace_file);
        ia_state.trace_file = NULL;
    }
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
