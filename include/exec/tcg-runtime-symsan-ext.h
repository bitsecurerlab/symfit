#ifndef EXEC_TCG_RUNTIME_SYMSAN_EXT_H
#define EXEC_TCG_RUNTIME_SYMSAN_EXT_H

#include "qemu/osdep.h"
#include "dfsan_interface.h"

void symsan_reset_load_concretizations(void);
bool symsan_find_load_concretization(dfsan_label addr_label,
                                     uint16_t width,
                                     target_ulong *concrete_addr,
                                     uint64_t *pc);
bool symsan_find_load_concretization_for_label(dfsan_label load_label,
                                               dfsan_label *addr_label,
                                               target_ulong *concrete_addr,
                                               uint64_t *concrete_value,
                                               uint64_t *pc);

#endif
