#ifndef LINUX_USER_IA_RPC_H
#define LINUX_USER_IA_RPC_H

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"
#include "qapi/error.h"
#include "dfsan_interface.h"

typedef enum IAExecState {
    IA_EXEC_IDLE = 0,
    IA_EXEC_RUNNING,
    IA_EXEC_PAUSED,
    IA_EXEC_EXITED,
} IAExecState;

typedef enum IATerminationKind {
    IA_TERM_NONE = 0,
    IA_TERM_EXIT,
    IA_TERM_EXIT_GROUP,
    IA_TERM_SIGNAL,
} IATerminationKind;

void ia_rpc_init(CPUState *cpu);
void ia_rpc_shutdown(void);
void ia_rpc_set_exec_state(IAExecState state);
bool ia_rpc_should_pause_after_trap(void);
void ia_rpc_set_exit_code(int code);
bool ia_rpc_pause_on_exit(int code, bool group_exit);
bool ia_rpc_pause_on_signal(int sig, int si_code, uint64_t fault_addr);
bool ia_rpc_finalize_pending_termination(CPUArchState *env);
void ia_wait_if_paused(void);
bool ia_should_stop_before_instruction(CPUState *cpu, vaddr pc);
void ia_on_basic_block_executed(CPUState *cpu, vaddr pc);
void symsan_record_path_constraint(uint64_t pc, dfsan_label label, bool taken);
bool ia_rpc_queue_stdin_chunk(uint64_t size, bool symbolic,
                              uint64_t *stream_offset, Error **errp);
void ia_rpc_consume_stdin_read(int fd, void *host_buf, size_t size);

#endif
