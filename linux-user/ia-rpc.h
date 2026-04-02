#ifndef LINUX_USER_IA_RPC_H
#define LINUX_USER_IA_RPC_H

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"

typedef enum IAExecState {
    IA_EXEC_IDLE = 0,
    IA_EXEC_RUNNING,
    IA_EXEC_PAUSED,
    IA_EXEC_EXITED,
} IAExecState;

void ia_rpc_init(CPUState *cpu);
void ia_rpc_shutdown(void);
void ia_rpc_set_exec_state(IAExecState state);
void ia_rpc_set_exit_code(int code);
void ia_wait_if_paused(void);
bool ia_should_stop_before_instruction(CPUState *cpu, vaddr pc);
void ia_on_basic_block_executed(CPUState *cpu, vaddr pc);

#endif
