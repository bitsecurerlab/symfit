//===-- dfsan_interface.h -------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Public interface header.
//===----------------------------------------------------------------------===//
#ifndef DFSAN_INTERFACE_H
#define DFSAN_INTERFACE_H

#include <stddef.h>
#include <stdint.h>
#include "common_interface_defs.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

enum operators {
  Not       = 1,
  Neg       = 2,
#define HANDLE_BINARY_INST(num, opcode, Class) opcode = num,
#define HANDLE_MEMORY_INST(num, opcode, Class) opcode = num,
#define HANDLE_CAST_INST(num, opcode, Class) opcode = num,
#define HANDLE_OTHER_INST(num, opcode, Class) opcode = num,
#define LAST_OTHER_INST(num) last_llvm_op = num,
#include "llvm/IR/Instruction.def"
#undef HANDLE_BINARY_INST
#undef HANDLE_MEMORY_INST
#undef HANDLE_CAST_INST
#undef HANDLE_OTHER_INST
#undef LAST_OTHER_INST
  // self-defined
  Free      = last_llvm_op + 3,
  Extract   = last_llvm_op + 4,
  Concat    = last_llvm_op + 5,
  Arg       = last_llvm_op + 6,
  // higher-order
  fmemcmp   = last_llvm_op + 7,
  fsize     = last_llvm_op + 8,
  /* last_llvm_op + 9 was previously reserved for LoadAddr */
  Ite       = last_llvm_op + 10,
};

enum predicate {
  bveq = 32,
  bvneq = 33,
  bvugt = 34,
  bvuge = 35,
  bvult = 36,
  bvule = 37,
  bvsgt = 38,
  bvsge = 39,
  bvslt = 40,
  bvsle = 41
};
/// Check if a page is concrete.
int dfsan_concrete_page(void *addr);

/// Signature of the callback argument to dfsan_set_write_callback().
typedef void (*dfsan_write_callback_t)(int fd, const void *buf, size_t count);

/// Computes the union of \c l1 and \c l2, possibly creating a union label in
/// the process.
//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u8 op, u8 size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size,
                        u64 op1, u64 op2, u64 pc);

/// Creates and returns a base label with the given description and user data.
dfsan_label dfsan_create_label(int pos);
  
/// Sets the label for each address in [addr,addr+size) to \c label.
void dfsan_set_label(dfsan_label label, void *addr, size_t size, u64 pc);

/// Sets the label for each address in [addr,addr+size) to the union of the
/// current label for that address and \c label.
void dfsan_add_label(dfsan_label label, u8 op, void *addr, size_t size);

/// Retrieves the label associated with the given data.
///
/// The type of 'data' is arbitrary.  The function accepts a value of any type,
/// which can be truncated or extended (implicitly or explicitly) as necessary.
/// The truncation/extension operations will preserve the label of the original
/// value.
dfsan_label dfsan_get_label(long data);

/// Retrieves the label associated with the data at the given address.
dfsan_label dfsan_read_label(const void *addr, size_t size);

void dfsan_store_label(dfsan_label l, void *addr, size_t size, u64 pc);

/// Returns non-zero when every byte in [addr, addr + size) is concrete.
int dfsan_region_is_concrete(const void *addr, size_t size);

/// Retrieves the starting address for the shadow memory of the given address
const dfsan_label * dfsan_shadow_for(const void * addr);

/// Returns whether the given label label contains the label elem.
int dfsan_has_label(dfsan_label label, dfsan_label elem);

/// Returns the number of labels allocated.
size_t dfsan_get_label_count(void);

/// Sets a callback to be invoked on calls to write().  The callback is invoked
/// before the write is done.  The write is not guaranteed to succeed when the
/// callback executes.  Pass in NULL to remove any callback.
void dfsan_set_write_callback(dfsan_write_callback_t labeled_write_callback);

/// Writes the labels currently used by the program to the given file
/// descriptor. The lines of the output have the following format:
///
/// <label> <parent label 1> <parent label 2> <label description if any>
void dfsan_dump_labels(int fd);

void dfsan_init_qemu(void);

void dfsan_unimplemented(char *fname);

dfsan_label __taint_trace_cmp(dfsan_label l1, dfsan_label l2, u8 size, u32 predicate,
                       u64 op1, u64 op2, u32 cid);

int dfsan_is_branch_condition_label(dfsan_label label);
int dfsan_get_branch_direction(dfsan_label label, uint8_t *taken);
size_t dfsan_get_nested_constraint_count(dfsan_label label);
size_t dfsan_get_nested_constraints(dfsan_label label, dfsan_label *out, size_t capacity);
size_t dfsan_get_nested_constraint_directions(dfsan_label label, uint8_t *out, size_t capacity);
size_t dfsan_format_simplified_expression(dfsan_label label, char *out, size_t capacity);

#ifndef DFSAN_SOLVE_PATH_CONSTRAINT_TYPES
#define DFSAN_SOLVE_PATH_CONSTRAINT_TYPES
typedef struct {
  uint64_t offset;
  uint8_t value;
} dfsan_solve_assignment;

typedef struct {
  dfsan_label load_label;
  dfsan_label addr_label;
  uint64_t concrete_addr;
  uint64_t concrete_value;
  uint64_t pc;
  uint16_t size;
} dfsan_solve_assumption;
#endif

int dfsan_solve_path_constraint(dfsan_label label, uint8_t desired_taken,
                                dfsan_solve_assignment *assignments,
                                size_t assignment_capacity,
                                size_t *assignment_count,
                                dfsan_solve_assumption *assumptions,
                                size_t assumption_capacity,
                                size_t *assumption_count,
                                char *error, size_t error_capacity);

void addContextRecording(u64 func_addr);

/// Interceptor hooks.
/// Whenever a dfsan's custom function is called the corresponding
/// hook is called it non-zero. The hooks should be defined by the user.
/// The primary use case is taint-guided fuzzing, where the fuzzer
/// needs to see the parameters of the function and the labels.
/// FIXME: implement more hooks.
void dfsan_weak_hook_memcmp(void *caller_pc, const void *s1, const void *s2,
                            size_t n, dfsan_label s1_label,
                            dfsan_label s2_label, dfsan_label n_label);
void dfsan_weak_hook_strncmp(void *caller_pc, const char *s1, const char *s2,
                             size_t n, dfsan_label s1_label,
                             dfsan_label s2_label, dfsan_label n_label);
#ifdef __cplusplus
}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data, u64 pc = 0) {  // NOLINT
  dfsan_set_label(label, (void *)&data, sizeof(T), pc);
}

#endif

#endif  // DFSAN_INTERFACE_H
