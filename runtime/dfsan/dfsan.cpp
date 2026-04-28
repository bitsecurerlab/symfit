//===-- dfsan.cc ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//

// Suppress redeclaration warnings — definitions below match dfsan.h declarations
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wredundant-decls"

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_posix.h"

#include "dfsan.h"
#include "taint_allocator.h"
#include "union_util.h"
#include "union_hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <map>
//#include <algorithm>
//#include <string> // For op-to-string conversion

std::map<uintptr_t, dfsan_label *> g_shadow_pages;
extern "C" void telemetry_send(const char *json);
extern "C" char telemetry_enabled;

using namespace __dfsan;

typedef atomic_uint32_t atomic_dfsan_label;

static atomic_dfsan_label __dfsan_last_label;
static dfsan_label_info *__dfsan_label_info;
static const size_t uniontable_size = 0xc00000000; // FIXME

// FIXME: single thread
// statck bottom
static dfsan_label __alloca_stack_bottom;
static dfsan_label __alloca_stack_top;
static const int MAX_SAVED_STACK_ENTRIES = 1024;
static dfsan_label __saved_alloca_stack_top[MAX_SAVED_STACK_ENTRIES];
static int __current_saved_stack_index = 0;

// taint source
struct taint_file __dfsan::tainted;

char taint_file_name[PATH_MAX];

// Hash table
static const uptr hashtable_size = (1ULL << 32);
static const size_t hashtable_buckets = (1ULL << 20);
static __taint::union_hashtable __union_table(hashtable_buckets);

Flags __dfsan::flags_data;
bool print_debug;

// The size of TLS variables. These constants must be kept in sync with the ones
// in Taint.cc
static const int kArgTlsSize = 800;
static const int kRetvalTlsSize = 800;

SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u64
    __dfsan_retval_tls[kRetvalTlsSize / sizeof(u64)];
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u64
    __dfsan_arg_tls[kArgTlsSize / sizeof(u64)];

SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;

// On Linux/x86_64, memory is laid out as follows:
//
// +--------------------+ 0x800000000000 (top of memory)
// | application memory |
// +--------------------+ 0x700000040000 (kAppAddr)
// |--------------------| UnusedAddr()
// |                    |
// |    union table     |
// |                    |
// +--------------------+ 0x400100000000 (kUnionTableAddr)
// |    hash table      |
// +--------------------+ 0x400000000000 (kHashTableAddr)
// |   shadow memory    |
// +--------------------+ 0x000000100000 (kShadowAddr)
// |       unused       |
// +--------------------+ 0x000000010000 (kKernelAddr)
// | reserved by kernel |
// +--------------------+ 0x000000000000
//
// To derive a shadow memory address from an application memory address,
// bits 44-46 are cleared to bring the address into the range
// [0x000000040000,0x100000000000).  Then the address is shifted left by 2 to
// account for the double byte representation of shadow labels and move the
// address into the shadow memory range.  See the function shadow_for below.

#ifdef DFSAN_RUNTIME_VMA
// Runtime detected VMA size.
int __dfsan::vmaSize;
#endif

static uptr UnusedAddr() {
  return MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() + uniontable_size;
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label label) {
  if (label == kInitializingLabel) {
    Report("FATAL: Taint: out of labels\n");
    Die();
  } else if (label >= __alloca_stack_top) {
    Report("FATAL: Exhausted labels\n");
    Die();
  }
}

dfsan_label *__dfsan::shadow_for(void *ptr) {
    auto shadowPageIt = g_shadow_pages.find(pageStart(ptr));
            if (shadowPageIt != g_shadow_pages.end()) {
        return shadowPageIt->second + pageOffset(ptr);
    }
    return nullptr;
}

dfsan_label *getOrCreateShadow(void *ptr, dfsan_label l) {
    if (auto *shadow = shadow_for(ptr))
        return shadow;
    if (l == 0)
        return nullptr;
    auto *newShadow =
        static_cast<dfsan_label *>(malloc(kPageSize * sizeof(dfsan_label)));
    memset(newShadow, 0, kPageSize * sizeof(dfsan_label));
    g_shadow_pages[pageStart(ptr)] = newShadow;
    return newShadow + pageOffset(ptr);
}

/**** Gemini op decoding, Claude constraint printing code ****/
static char unknown_op_buf[32];
static char unknown_pred_buf[32];

const char* get_predicate_name(u64 pred) { // This should probably be a u8, it doesn't need to be a u64...
    switch (pred) {
    case 0:     return "ICmp"; // Default case; for no predicate
    case bveq:  return "==";
    case bvneq: return "!=";
    case bvugt: return ">u";
    case bvult: return "<u";
    case bvuge: return ">=u";
    case bvule: return "<=u";
    case bvsgt: return ">s";
    case bvslt: return "<s";
    case bvsge: return ">=s";
    case bvsle: return "<=s";
    default:
      __sanitizer::internal_snprintf(unknown_pred_buf, sizeof(unknown_pred_buf), "pred_%d", (int)pred);
      return unknown_pred_buf;
    }
}

const char* get_op_name(u16 op, u64 pred) {
    // 1. Handle custom DFSan operators first
    switch (op) {
        case 28:    return get_predicate_name(pred); // ICmp
        case 1:     return "Not"; // Not
        case 2:     return "Neg"; // Neg
        case Extract: return "Extract";
        case Concat:  return "Concat";
        case Ite:     return "If-Then-Else";
        //case Equal:   return "Equal"; // This opcode was eliminated from this branch
        case fmemcmp: return "memcmp_func";
        case Arg:     return "Function_Arg";
    }

    // 2. Handle LLVM Instructions using macro expansion
    // This maps the 'num' from Instruction.def to a string
    switch (op) {
#define HANDLE_BINARY_INST(num, opcode, Class) case num: return #opcode;
#define HANDLE_MEMORY_INST(num, opcode, Class) case num: return #opcode;
#define HANDLE_CAST_INST(num, opcode, Class)   case num: return #opcode;
#define HANDLE_OTHER_INST(num, opcode, Class)  case num: return #opcode;
#include "llvm/IR/Instruction.def"
#undef HANDLE_BINARY_INST
#undef HANDLE_MEMORY_INST
#undef HANDLE_CAST_INST
#undef HANDLE_OTHER_INST
    }
    __sanitizer::internal_snprintf(unknown_op_buf, sizeof(unknown_op_buf), "Unknown_Op(%d)", op);
    return unknown_op_buf;
    //return "Unknown_Op (" + std::to_string(op) + ")";
}

static void print_constraint_recursive_readable(dfsan_label label, int depth) {
    if (label == 0) {
        printf("%*s<concrete>\n", depth * 2, "");
        return;
    }

    dfsan_label_info *info = get_label_info(label);
    if (!info) return;

    const char *op_str = get_op_name(info->op, 0);

    // Special handling for common patterns
    if (info->op == Concat && depth == 0) {
        printf("%*s(Building multi-byte value from symbolic bytes)\n", depth * 2, "");
    } else if (info->op == ZExt) {
        printf("%*sZero-extend to %u bits:\n", depth * 2, "", info->size);
    } else if (info->op == Extract) {
        printf("%*sExtract bits [%llu:%llu]:\n", depth * 2, "", info->op1.i, info->op2.i);
    } else if (info->op == Mul && (info->op1.i == 0x2c || info->op2.i == 0x2c)) {
        printf("%*s(symbolic * 44) [calculating array size]:\n", depth * 2, "");
    } else if (info->op == Add && info->op1.i == 0xffffffff) {
        printf("%*s(value - 1):\n", depth * 2, "");
    } else {
        printf("%*s%s (size=%u):\n", depth * 2, "", op_str, info->size);
        if (info->op1.i || info->op2.i) {
            printf("%*s  constants: %llu, %llu\n", depth * 2, "", info->op1.i, info->op2.i);
        }
    }

    if (info->l1) print_constraint_recursive_readable(info->l1, depth + 1);
    if (info->l2) print_constraint_recursive_readable(info->l2, depth + 1);
}

extern "C" void print_constraint(dfsan_label label) {
    printf("=== Human-readable constraint for Label %u ===\n", label);
    print_constraint_recursive_readable(label, 0);
    printf("=============================================\n");
}

/**** print_constraint() is old and pending deletion ****/

// In dfsan.cpp

// Branch constraint structure
struct branch_constraint_t {
    u64 pc;
    dfsan_label label;
    u64 actual_value;
    u8 operation;
    u64 compared_to;
    bool result;
};

// Operation encoding
enum constraint_op {
    OP_EQUAL = 0,
    OP_NOT_EQUAL = 1,
    OP_LESS = 2,
    OP_LESS_EQUAL = 3,
    OP_GREATER = 4,
    OP_GREATER_EQUAL = 5,
    OP_SLESS = 6,
    OP_SLESS_EQUAL = 7,
    OP_SGREATER = 8,
    OP_SGREATER_EQUAL = 9
};

static const char* op_to_string(u8 op) {
    switch (op) {
        case OP_EQUAL: return "==";
        case OP_NOT_EQUAL: return "!=";
        case OP_LESS: return "<";
        case OP_LESS_EQUAL: return "<=";
        case OP_GREATER: return ">";
        case OP_GREATER_EQUAL: return ">=";
        case OP_SLESS: return "<s";
        case OP_SLESS_EQUAL: return "<=s";
        case OP_SGREATER: return ">s";
        case OP_SGREATER_EQUAL: return ">=s";
        default: return "?";
    }
}

static u8 string_to_op(const char* str) {
    if (internal_strcmp(str, "==") == 0) return OP_EQUAL;
    if (internal_strcmp(str, "!=") == 0) return OP_NOT_EQUAL;
    if (internal_strcmp(str, "<") == 0) return OP_LESS;
    if (internal_strcmp(str, "<=") == 0) return OP_LESS_EQUAL;
    if (internal_strcmp(str, ">") == 0) return OP_GREATER;
    if (internal_strcmp(str, ">=") == 0) return OP_GREATER_EQUAL;
    if (internal_strcmp(str, "<s") == 0) return OP_SLESS;
    if (internal_strcmp(str, "<=s") == 0) return OP_SLESS_EQUAL;
    if (internal_strcmp(str, ">s") == 0) return OP_SGREATER;
    if (internal_strcmp(str, ">=s") == 0) return OP_SGREATER_EQUAL;
    return OP_EQUAL;
}

/**** End LLM code ****/


// based on https://github.com/Cyan4973/xxHash
// simplified since we only have 12 bytes info
static inline u32 xxhash(u32 h1, u32 h2, u32 h3) {
  const u32 PRIME32_1 = 2654435761U;
  const u32 PRIME32_2 = 2246822519U;
  const u32 PRIME32_3 = 3266489917U;
  const u32 PRIME32_4 =  668265263U;
  const u32 PRIME32_5 =  374761393U;

  #define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
  u32 h32 = PRIME32_5;
  h32 += h1 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h2 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h3 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  #undef XXH_rotl32

  h32 ^= h32 >> 15;
  h32 *= PRIME32_2;
  h32 ^= h32 >> 13;
  h32 *= PRIME32_3;
  h32 ^= h32 >> 16;

  return h32;
}

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

static inline bool is_constant_label(dfsan_label label) {
  return label == CONST_LABEL;
}

static inline bool is_kind_of_label(dfsan_label label, u16 kind) {
  return get_label_info(label)->op == kind;
}

static bool isZeroOrPowerOfTwo(uint16_t x) { return (x & (x - 1)) == 0; }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
int dfsan_concrete_page(void *addr) {
  // Return true if the page is not shadowed.
  if (g_shadow_pages.find(pageStart(addr)) == g_shadow_pages.end()) return 1;
  return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label
__taint_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size,
                          u64 op1, u64 op2, u64 pc) {
  if (l1 > l2 && is_commutative(op)) {
    // needs to swap both labels and concretes
    Swap(l1, l2);
    Swap(op1, op2);
  }
  if (l1 == 0 && l2 < CONST_OFFSET && op != fsize && op != Alloca) return 0;
  if (l1 == kInitializingLabel || l2 == kInitializingLabel) return kInitializingLabel;

  // special handling for bounds
  if (get_label_info(l1)->op == Alloca || get_label_info(l2)->op == Alloca) {
    // propagate if it's casting op
    if (op == BitCast) return l1;
    if (op == PtrToInt) {AOUT("WARNING: ptrtoint %d\n", l1); return 0;}
    if (op != Extract) return 0;
  }

  // special handling for bounds, which may use all four fields
  if (op != Alloca) {
    if (l1 >= CONST_OFFSET) op1 = 0;
    if (l2 >= CONST_OFFSET) op2 = 0;
  }

  // setup a hash tree for dedup
  u32 h1 = l1 ? __dfsan_label_info[l1].hash : 0;
  u32 h2 = l2 ? __dfsan_label_info[l2].hash : 0;
  u32 h3 = op;
  h3 = (h3 << 16) | size;
  u32 hash = xxhash(h1, h2, h3);

  struct dfsan_label_info label_info = {
    .l1 = l1, .l2 = l2, .op1 = op1, .op2 = op2, .op = op, .size = size,
    .hash = hash, .pc = pc};

  __taint::option res = __union_table.lookup(label_info);
  if (res != __taint::none()) {
    dfsan_label label = *res;
    AOUT("%u found\n", label);
    return label;
  }
  // for debugging
  
  dfsan_label l = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  assert(l1 <= l && l2 <= l);

  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);
  assert(label > l1 && label > l2);

  const char* op_name = get_op_name(op & 0xff, (op >> 8));
  //AOUT("%u = (%u, %u, %u, %u, %llu, %llu)\n", label, l1, l2, op, size, op1, op2);
  AOUT("%u = (%u, %u, %s, %u, %llu, %llu, 0x%llx)\n", label, l1, l2, op_name, size, op1, op2, pc);
  if (telemetry_enabled) {
      char jsonbuffer[956];
      char label_summary[256];
      u16 op_base = op & 0xff;  // strip predicate from upper byte
      if (op_base == Extract) {
        internal_snprintf(label_summary, sizeof(label_summary) - 1,
            "label %u = Extract bits [%llu:%llu] of label %u at PC 0x%llx",
            label, op1, op2, l1, pc);
    } else if (op_base == Concat) {
        internal_snprintf(label_summary, sizeof(label_summary) - 1,
            "label %u = Concat label %u (val=%llu) : label %u (val=%llu, size=%u) at PC 0x%llx",
            label, l1, op1, l2, op2, size, pc);
    } else if (l2 == 0) {
        // Unary operation
        internal_snprintf(label_summary, sizeof(label_summary) - 1,
            "label %u = %s label %u (val=%llu, size=%u) at PC 0x%llx",
            label, op_name, l1, op1, size, pc);
    } else {
        // Binary operation
        internal_snprintf(label_summary, sizeof(label_summary) - 1,
            "label %u = label %u (val=%llu) %s label %u (val=%llu, size=%u) at PC 0x%llx",
            label, l1, op1, op_name, l2, op2, size, pc);
    }
    internal_snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
          "{"
          "\"source\": \"dfsan\","
          "\"trigger\": \"label_creation\","
          "\"label_summary\": \"%s\","
          "\"label\": %u,"
          "\"l1\": %u,"
          "\"l2\": %u,"
          "\"op\": \"%s\","
          "\"size\": %u,"
          "\"op1\": %llu,"
          "\"op2\": %llu,"
          "\"pc\": \"0x%llx\""
          "}",
          label_summary, label, l1, l2, op_name, size, op1, op2, pc);
      telemetry_send(jsonbuffer);
  }
  internal_memcpy(&__dfsan_label_info[label], &label_info, sizeof(dfsan_label_info));
  __union_table.insert(&__dfsan_label_info[label], label);
  return label;
}

inline uptr getPageStart(uptr addr) { return addr & ~(kPageSize - 1); }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union_load(const dfsan_label *ls, const void *addr, uptr n) {
  // TODO: Return if concrete.
  if (ls == nullptr) return 0;
  dfsan_label label0 = ls[0];
  if (label0 == kInitializingLabel) return kInitializingLabel;

  // for debugging
  // dfsan_label l = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  // assert(label0 <= l);
  if (label0 >= CONST_OFFSET) assert(get_label_info(label0)->size != 0);
  uptr pos = 0;
  dfsan_label *next_ls = nullptr;
  if (getPageStart((uptr)addr) != getPageStart((uptr)addr + n - 1)) {
    // cross page
    pos = kPageSize - ((uptr)addr & (kPageSize - 1));
    uptr next_addr = (uptr)addr + n;
    // the second argument is not used.
    next_ls = getOrCreateShadow((void*)next_addr, -1);
    AOUT("cross page load addr: %p, n: %u position %u\n", addr, n, pos);
  }

  // fast path 1: constant and bounds
  if (is_constant_label(label0) || is_kind_of_label(label0, Alloca)) {
    bool same = true;
    for (uptr i = 1; i < n; i++) {
      if (next_ls && i >= pos) {
        if (next_ls[i - pos] != label0) {
          same = false;
          break;
        }
      } else {
        if (ls[i] != label0) {
          same = false;
          break;
        }
      }
    }
    if (same) return label0;
  }
  AOUT("label0 = %d, n = %d, ls = %p\n", label0, n, ls);

  // shape
  bool shape = true;
  if (__dfsan_label_info[label0].op != 0) {
    // not raw input bytes
    shape = false;
  } else {
    off_t offset = get_label_info(label0)->op1.i;
    for (uptr i = 1; i != n; ++i) {
      dfsan_label next_label;
      if (next_ls && i >= pos) {
        next_label = next_ls[i - pos];
      } else {
        next_label = ls[i];
      }
      if (next_label == kInitializingLabel) return kInitializingLabel;
      else if (get_label_info(next_label)->op1.i != offset + i) {
        shape = false;
        break;
      }
    }
  }
  if (shape) {
    // if (n == 1) return label0;
    if (n == 1) {
      assert(get_label_info(label0)->size == 8);
      return __taint_union(label0, CONST_LABEL, ZExt, 64, 0, 0, __dfsan_label_info[label0].pc);
    }

    AOUT("shape: label0: %d %d shadow addr: %p app_for %p\n", label0, n, ls, app_for(ls));
    // return __taint_union(label0, (dfsan_label)n, Load, n * 8, 0, 0);
    if (n == 8) {
      return __taint_union(label0, (dfsan_label)n, Load, n * 8, 0, 0, __dfsan_label_info[label0].pc);
    } else {
      // symqemu: extend label to 64-bit
      dfsan_label out = __taint_union(label0, (dfsan_label)n, Load, n * 8, 0, 0, __dfsan_label_info[label0].pc);
      return __taint_union(out, CONST_LABEL, ZExt, 64, 0, 0, __dfsan_label_info[label0].pc);
    }
  }

  // fast path 2: all labels are extracted from a n-size label, then return that label
  if (is_kind_of_label(label0, Extract)) {
    dfsan_label parent = get_label_info(label0)->l1;
    uptr offset = 0;
    for (uptr i = 0; i < n; i++) {
      dfsan_label_info *info = nullptr;
      if (next_ls && i >= pos) {
        info = get_label_info(next_ls[i - pos]);
      } else {
        info = get_label_info(ls[i]);
      }
      if (!is_kind_of_label(ls[i], Extract)
            || offset != info->op2.i
            || parent != info->l1) {
        break;
      }
      offset += info->size;
    }
    if (get_label_info(parent)->size == offset && offset == n * 8) {
      AOUT("Fast path (2): all labels are extracts: %u\n", parent);
      return parent;
    }
  }

  // slowpath
  AOUT("union load slowpath at %p\n", __builtin_return_address(0));
  dfsan_label label = label0;
  // for (uptr i = get_label_info(label0)->size / 8; i < n;) {
  // symqemu:
  for (uptr i = 1; i < n;) {
    dfsan_label next_label;
    if (next_ls && i >= pos) {
      next_label = next_ls[i - pos];
    } else {
      next_label = ls[i];
    }
    u16 next_size = get_label_info(next_label)->size;
    AOUT("next label=%u, size=%u ls = %p\n", next_label, next_size, &ls[i]);
    if (next_size == 0) {
      // next_label = 0;
      AOUT("shadow %p is not initialized\n", &ls[i]);
    }
    if (!is_constant_label(next_label)) {
      // if (next_size <= (n - i) * 8) {
      if (next_size <= 64) {
        // i += next_size / 8;
        i += 1;
        label = __taint_union(label, next_label, Concat, i * 8, 0, 0, __dfsan_label_info[label0].pc);
      } else {
        Report("WARNING: partial loading expected=%d has=%d\n", n-i, next_size);
        uptr size = n - i;
        dfsan_label trunc = __taint_union(next_label, CONST_LABEL, Trunc, size * 8, 0, 0, __dfsan_label_info[label0].pc);
        return __taint_union(label, trunc, Concat, n * 8, 0, 0, __dfsan_label_info[label0].pc); // Which PC value should we be using here? label0?
      }
    } else {
      // Report("WARNING: taint mixed with concrete %d %p\n", i, &ls[i]);
      // symqemu: disable app_for for now.
      // char *c = (char *)app_for(&ls[i]);
      ++i;
      // label = __taint_union(label, 0, Concat, i * 8, 0, *c);
      label = __taint_union(label, 0, Concat, i * 8, 0, 0, __dfsan_label_info[label0].pc);
    }
  }
  AOUT("\n");
  label = __taint_union(label, CONST_LABEL, ZExt, 64, 0, 0, __dfsan_label_info[label0].pc);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_union_store(dfsan_label l, dfsan_label *ls, const void *addr, uptr n, u64 pc) {
  // AOUT("label = %d, n = %d, ls = %p\n", l, n, ls);
  // TODO: add concrete page check
  uptr pos = 0;
  dfsan_label *next_ls = nullptr;
  if (getPageStart((uptr)addr) != getPageStart((uptr)addr + n - 1)) {
    // cross page
    AOUT("cross page store addr: %p, n: %u\n", addr, n);
    pos = kPageSize - ((uptr)addr & (kPageSize - 1));
    uptr next_addr = (uptr)addr + n;
    // the second argument is not used.
    next_ls = getOrCreateShadow((void*)next_addr, -1);
  }
  if (l != kInitializingLabel) {
    // for debugging
    dfsan_label h = atomic_load(&__dfsan_last_label, memory_order_relaxed);
    assert(l <= h);
  } else {
    for (uptr i = 0; i < n; ++i) {
      if (next_ls && i >= pos) {
        assert(pos != 0);
        next_ls[i - pos] = l;
      } else {
        ls[i] = l;
      }
    }
    return;
  }

  // fast path 1: constant and bounds
  if (l == 0 || is_kind_of_label(l, Alloca)) {
    for (uptr i = 0; i < n; ++i){
      if (next_ls && i >= pos) {
        assert(pos != 0);
        next_ls[i - pos] = l;
      } else {
        ls[i] = l;
      }
    }
    return;
  }

  dfsan_label_info *info = get_label_info(l);
  // fast path 2: single byte
  if (n == 1 && info->size == 8) {
    ls[0] = l;
    return;
  }

  // fast path 3: load
  if (is_kind_of_label(l, Load)) {
    // if source label is union load, just break it up
    dfsan_label label0 = info->l1;
    if (n > info->l2) {
      Report("WARNING: store size=%u larger than load size=%d\n", n, info->l2);
    }
    for (uptr i = 0; i < n; ++i){
      if (next_ls && i >= pos) {
        assert(pos != 0);
        next_ls[i - pos] = label0 + i;
      } else {
        ls[i] = label0 + i;
      }
    }
    return;
  }

  // default fall through
  for (uptr i = 0; i < n; ++i) {
    if (next_ls && i >= pos) {
      assert(pos != 0);
      next_ls[i - pos] = __taint_union(l, CONST_LABEL, Extract, 8, 0, i * 8, pc); // TO DO: Is the PC value for this sane?
    } else {
      ls[i] = __taint_union(l, CONST_LABEL, Extract, 8, 0, i * 8, pc);
    }
    // ls[i] = __taint_union(l, CONST_LABEL, Extract, 8, 0, i * 8);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_push_stack_frame() {
  if (flags().trace_bounds) {
    if (__current_saved_stack_index < MAX_SAVED_STACK_ENTRIES)
      __saved_alloca_stack_top[++__current_saved_stack_index] = __alloca_stack_top;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_pop_stack_frame() {
  if (flags().trace_bounds) {
    __alloca_stack_top = __saved_alloca_stack_top[__current_saved_stack_index--];
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_trace_alloca(dfsan_label l, u64 size, u64 elem_size, u64 base) {
  if (flags().trace_bounds) {
    __alloca_stack_top -= 1;
    AOUT("label = %d, base = %p, size = %lld, elem_size = %lld\n",
        __alloca_stack_top, base, size, elem_size);
    dfsan_label_info *info = get_label_info(__alloca_stack_top);
    internal_memset(info, 0, sizeof(dfsan_label_info));
    info->l2    = l;
    info->op    = Alloca;
    info->size  = sizeof(void*) * 8;
    info->op1.i = base;
    info->op2.i = base + size * elem_size;

    return __alloca_stack_top;
  } else {
    return 0;
  }
}

// NOTES: for Alloca, or buffer buounds info
// .l1 = num of elements label, for calloc style allocators
// .l2 = (element) size label
// .op1 = lower bounds
// .op2 = upper bounds
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_check_bounds(dfsan_label l, uptr addr) {
  if (flags().trace_bounds) {
    dfsan_label_info *info = get_label_info(l);
    if (info->op == Free) {
      // UAF
      AOUT("ERROR: UAF detected %p = %d @%p\n", addr, l, __builtin_return_address(0));
    } else if (info->op == Alloca) {
      AOUT("addr = %p, lower = %p, upper = %p\n", addr, info->op1.i, info->op2.i);
      if (addr < info->op1.i || addr >= info->op2.i) {
        AOUT("ERROR: OOB detected %p = %d @%p\n", addr, l, __builtin_return_address(0));
      }
    } else {
      AOUT("WARNING: incorrect label %p = %d @%p\n", addr, l, __builtin_return_address(0));
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_store_label(dfsan_label l, void *addr, uptr size, u64 pc) {
  // This check is wrong. Removed.
  // if (l == 0) return;
  // __taint_union_store(l, shadow_for(addr), size);
  dfsan_label *ls = getOrCreateShadow(addr, l);
  if (ls == nullptr) return;
  AOUT("Storing label %d with address %p, size %d, pc 0x%llx\n", l, addr, size, pc);
  __taint_union_store(l, ls, addr, size, pc);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_unimplemented(char *fname) {
  if (flags().warn_unimplemented)
    Report("WARNING: DataFlowSanitizer: call to uninstrumented function %s\n",
           fname);

}
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_unimplemented(char *fname) {
  if (flags().warn_unimplemented)
    Report("WARNING: DataFlowSanitizer: call to unimplemented function %s\n",
           fname);
  Die();
}
// Use '-mllvm -dfsan-debug-nonzero-labels' and break on this function
// to try to figure out where labels are being introduced in a nominally
// label-free program.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_nonzero_label() {
  if (flags().warn_nonzero_labels)
    Report("WARNING: DataFlowSanitizer: saw nonzero label\n");
}

// Indirect call to an uninstrumented vararg function. We don't have a way of
// handling these at the moment.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__dfsan_vararg_wrapper(const char *fname) {
  Report("FATAL: DataFlowSanitizer: unsupported indirect call to vararg "
         "function %s\n", fname);
  Die();
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size, u64 op1, u64 op2, u64 pc) {
  return __taint_union(l1, l2, op, size, op1, op2, pc);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_label(off_t offset) {
  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);
  internal_memset(&__dfsan_label_info[label], 0, sizeof(dfsan_label_info));
  __dfsan_label_info[label].size = 8;
  // label may not equal to offset when using stdin
  __dfsan_label_info[label].op1.i = offset;
  // init a non-zero hash
  __dfsan_label_info[label].hash = xxhash(offset, 0, 8);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_set_label(dfsan_label label, void *addr, uptr size, u64 pc) {
  for (dfsan_label *labelp = getOrCreateShadow(addr, label); size != 0; --size, ++labelp) {
    if (labelp == nullptr && label == 0) break;
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp)
      continue;
    if (telemetry_enabled) {
      char jsonbuffer[500];
      snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
          "{"
          "\"source\": \"dfsan\","
          "\"trigger\": \"taint_introduction\","
          "\"address\": \"0x%lx\","
          "\"label\": %u,"
          "\"label_size\": %d,"
          "\"pc\": \"0x%llx\""
          "}",
          (unsigned long)addr, label, get_label_info(label)->size, pc);
      telemetry_send(jsonbuffer);
    }
    AOUT("set label %p = %u, label size %d shadow addr: %p, pc 0x%llx\n", addr, label, get_label_info(label)->size, shadow_for(addr), pc);
    *labelp = label;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_set_label(dfsan_label label, void *addr, uptr size, u64 pc) {
  __dfsan_set_label(label, addr, size, pc);
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_add_label(dfsan_label label, u8 op, void *addr, uptr size, u64 pc) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    *labelp = __taint_union(*labelp, label, op, 1, 0, 0, pc);
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsw_dfsan_get_label(long data, dfsan_label data_label,
                       dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
__attribute__((no_sanitize("dataflow"), noinline)) dfsan_label
dfsan_read_label(const void *addr, uptr size) {
  if (size == 0)
    return 0;
  return __taint_union_load(shadow_for(const_cast<void *>(addr)), addr, size);
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_get_label(const void *addr) {
  return *shadow_for(addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
__attribute__((no_sanitize("dataflow"), noinline)) int
dfsan_region_is_concrete(const void *addr, uptr size) {
  const u8 *cursor = reinterpret_cast<const u8 *>(addr);
  uptr remaining = size;

  while (remaining > 0) {
    uptr page_bytes = Min(kPageSize - pageOffset(const_cast<u8 *>(cursor)), remaining);
    const dfsan_label *shadow = shadow_for(const_cast<u8 *>(cursor));

    if (shadow != nullptr) {
      for (uptr i = 0; i < page_bytes; ++i) {
        if (shadow[i] != 0) {
          return 0;
        }
      }
    }

    cursor += page_bytes;
    remaining -= page_bytes;
  }

  return 1;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label_info *dfsan_get_label_info(dfsan_label label) {
  dfsan_check_label(label);
  return &__dfsan_label_info[label];
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_is_branch_condition_label(dfsan_label label) {
  const dfsan_label_info *info;

  if (label == CONST_LABEL) {
    return 0;
  }
  dfsan_check_label(label);
  info = &__dfsan_label_info[label];
  return (info->op & 0xff) == ICmp;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_has_label(dfsan_label label, dfsan_label elem) {
  if (label == elem)
    return true;
  const dfsan_label_info *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label(info->l1, elem);
  }
  if (info->l2 != 0) {
    return dfsan_has_label(info->l2, elem);
  }
  return false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
dfsan_get_label_count(void) {
  dfsan_label max_label_allocated =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  return static_cast<uptr>(max_label_allocated);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_dump_labels(int fd) {
  dfsan_label last_label =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);
  for (uptr l = 1; l <= last_label; ++l) {
    char buf[64];
    internal_snprintf(buf, sizeof(buf), "%u (%u %u %u %u 0x%llx)", l,
                      __dfsan_label_info[l].l1, __dfsan_label_info[l].l2,
                      __dfsan_label_info[l].op, __dfsan_label_info[l].size, __dfsan_label_info[l].pc);
    AOUT("fd:%d writing to file: %s\n", fd, buf);
    WriteToFile(fd, buf, internal_strlen(buf));
    WriteToFile(fd, "\n", 1);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_debug(dfsan_label op1, dfsan_label op2, int predicate,
              u32 size, u32 target) {
  if (op1 == 0 && op2 == 0) return;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_set_file(const char *filename, int fd) {
  char path[PATH_MAX];
  realpath(filename, path);
  // if (internal_strcmp(tainted.filename, path) == 0) {
  if (internal_strcmp(taint_file_name, path) == 0) {
    tainted.fd = fd;
    AOUT("fd:%d created\n", fd);
  }
}

SANITIZER_INTERFACE_ATTRIBUTE int
is_taint_file(const char *filename) {
  char path[PATH_MAX];
  realpath(filename, path);
  if (internal_strcmp(tainted.filename, path) == 0) {
    tainted.is_utmp = 1;
    return 1;
  }
  tainted.is_utmp = 0;
  return 0;
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
taint_get_file(int fd) {
  AOUT("fd: %d\n", fd);
  AOUT("tainted.fd: %d\n", tainted.fd);
  return tainted.fd == fd ? tainted.size : 0;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_close_file(int fd) {
  if (fd == tainted.fd) {
    AOUT("close tainted.fd: %d\n", tainted.fd);
    tainted.fd = -1;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE int
is_stdin_taint(void) {
  return tainted.is_stdin;
}

// for utmp interface
SANITIZER_INTERFACE_ATTRIBUTE int
is_utmp_taint(void) {
  return tainted.is_utmp;
}

SANITIZER_INTERFACE_ATTRIBUTE void
set_utmp_offset(off_t offset) {
  tainted.offset = offset;
}

SANITIZER_INTERFACE_ATTRIBUTE off_t
get_utmp_offset() {
  return tainted.offset;
}

SANITIZER_INTERFACE_ATTRIBUTE void
taint_set_offset_label(dfsan_label label) {
  tainted.offset_label = label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
taint_get_offset_label() {
  return tainted.offset_label;
}

void Flags::SetDefaults() {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void RegisterDfsanFlags(FlagParser *parser, Flags *f) {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void InitializeTaintFile() {
  for (long i = 1; i < CONST_OFFSET; i++) {
    // for synthesis
    dfsan_label label = dfsan_create_label(i);
    assert(label == i);
  }
  struct stat st;
  const char *filename = flags().taint_file;
  if (internal_strcmp(filename, "stdin") == 0) {
    tainted.fd = 0;
    // try to get the size, as stdin may be a file
    if (!fstat(0, &st) && st.st_size > 0) {
        tainted.size = st.st_size;
        tainted.is_stdin = 0;
        // map a copy
        tainted.buf_size = RoundUpTo(st.st_size, GetPageSizeCached());
        uptr map = internal_mmap(nullptr, tainted.buf_size, PROT_READ, MAP_PRIVATE, 0, 0);
        if (internal_iserror(map)) {
            Printf("FATAL: failed to map a copy of input file\n");
            Die();
        }
    tainted.buf = reinterpret_cast<char *>(map);
    } else {
      tainted.size = 1;
      tainted.is_stdin = 1; // truly stdin
    }
  } else if (internal_strcmp(filename, "") == 0) {
    tainted.fd = -1;
  } else {
    if (!realpath(filename, tainted.filename)) {
      Report("WARNING: failed to get to real path for taint file\n");
      return;
    }
    stat(filename, &st);
    tainted.size = st.st_size;
    tainted.is_stdin = 0;
    // map a copy
    tainted.buf = static_cast<char *>(
      MapFileToMemory(filename, &tainted.buf_size));
    if (tainted.buf == nullptr) {
      Printf("FATAL: failed to map a copy of input file\n");
      Die();
    }
    realpath(filename, taint_file_name);
    AOUT("%s %lld size\n", filename, tainted.size);
    AOUT("tainted filename %s\n", tainted.filename);
  }

  if (tainted.fd != -1 && !tainted.is_stdin) {
    for (off_t i = 0; i < tainted.size; i++) {
      dfsan_label label = dfsan_create_label(i);
      dfsan_check_label(label);
    }
  }
}

// information is passed implicitly through flags()
extern "C" void InitializeSolver(void);

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  flags().SetDefaults();

  FlagParser parser;
  RegisterCommonFlags(&parser);
  RegisterDfsanFlags(&parser, &flags());
  parser.ParseString(GetEnv("TAINT_OPTIONS"));
  InitializeCommonFlags();
  if (Verbosity()) ReportUnrecognizedFlags();
  if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void InitializePlatformEarly() {
  AvoidCVE_2016_2143();
#ifdef DFSAN_RUNTIME_VMA
  __dfsan::vmaSize =
    (MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
  if (__dfsan::vmaSize == 39 || __dfsan::vmaSize == 42 ||
      __dfsan::vmaSize == 48) {
    __dfsan_shadow_ptr_mask = ShadowMask();
  } else {
    Printf("FATAL: DataFlowSanitizer: unsupported VMA range\n");
    Printf("FATAL: Found %d - Supported 39, 42, and 48\n", __dfsan::vmaSize);
    Die();
  }
#endif
}

static void dfsan_fini() {
  if (internal_strcmp(flags().dump_labels_at_exit, "") != 0) {
    fd_t fd = OpenFile(flags().dump_labels_at_exit, WrOnly);
    if (fd == kInvalidFd) {
      Report("WARNING: DataFlowSanitizer: unable to open output file %s\n",
             flags().dump_labels_at_exit);
      return;
    }

    Report("INFO: DataFlowSanitizer: dumping labels to %s\n",
           flags().dump_labels_at_exit);
    dfsan_dump_labels(fd);
    CloseFile(fd);
  }
  if (tainted.buf) {
    UnmapOrDie(tainted.buf, tainted.buf_size);
  }
  if (flags().shm_id != -1) {
    shmdt((void *)UnionTableAddr());
  }
}

static void dfsan_init(int argc, char **argv, char **envp) {
  InitializeFlags();
  print_debug = flags().debug;

  ::InitializePlatformEarly();
  // Disable direct shadow memopry mapping.
  // MmapFixedSuperNoReserve(ShadowAddr(), UnionTableAddr() - ShadowAddr());
  MmapFixedSuperNoReserve(HashTableAddr(), UnionTableAddr() - HashTableAddr());
  __dfsan_label_info = (dfsan_label_info *)UnionTableAddr();

  // init union table
  if (flags().shm_id != -1) {
    void *ret = shmat(flags().shm_id, (void *)UnionTableAddr(), SHM_REMAP);
    if (ret == (void*)-1) {
      Printf("FATAL: error mapping shared union table\n");
      Die();
    }
  } else {
    MmapFixedSuperNoReserve(UnionTableAddr(), uniontable_size);
  }

  // init const label
  internal_memset(&__dfsan_label_info[CONST_LABEL], 0, sizeof(dfsan_label_info));
  __dfsan_label_info[CONST_LABEL].size = 8;

  // init hashtable allocator
  __taint::allocator_init(HashTableAddr(), HashTableAddr() + hashtable_size);

  // init main thread
  auto num_of_labels = uniontable_size / sizeof(dfsan_label_info);
  __alloca_stack_top = __alloca_stack_bottom = (dfsan_label)(num_of_labels - 2);

  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uptr init_addr = (uptr)&dfsan_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());

  InitializeInterceptors();

  InitializeTaintFile();

  InitializeSolver();

  // Register the fini callback to run when the program terminates successfully
  // or it is killed by the runtime.
  Atexit(dfsan_fini);
  AddDieCallback(dfsan_fini);
}

static inline dfsan_label get_label_for(int fd, off_t offset) {
  // check if fd is stdin, if so, the label hasn't been pre-allocated
  if (is_stdin_taint()) return dfsan_create_label(offset);
  // if fd is a tainted file, the label should have been pre-allocated
  else {
    const dfsan_label_info *info = dfsan_get_label_info(offset + CONST_OFFSET);
    if (info->size == 0) { // not pre-allocated
      // sometimes the file is read multiple times
      // and it exceeds file size (should be related to qemu syscall).
      return 0;
    } else {
      return (offset + CONST_OFFSET);
    }
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
__dfsan_open(const char *path, int oflags, mode_t mode) {
  AOUT("__dfsan_open\n");
  int fd = open(path, oflags, mode);
  if (fd)
    taint_set_file(path, fd);
  return fd;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE ssize_t
__dfsan_read(int fd, void *buf, size_t count, size_t *isSymbolicPage) {
  off_t offset = lseek(fd, 0, SEEK_CUR);
  ssize_t ret = read(fd, buf, count);
  if (ret >= 0) {
    dfsan_label label;
    if (taint_get_file(fd)) {
      AOUT("offset = %d, ret = %d, count = %d\n", offset, ret, count);
      for(ssize_t i = 0; i < ret; i++) {
        label = get_label_for(fd, offset + i);
        dfsan_set_label(label, (char *)buf + i, 1, get_label_info(label)->pc);
      }
      *isSymbolicPage = 1;
      // for (size_t i = ret; i < count; i++)
      //   dfsan_set_label(-1, (char *)buf + i, 1);
      // *ret_label = dfsan_union(0, 0, fsize, sizeof(ret) * 8, offset, 0);
    } else {
      dfsan_set_label(0, buf, ret, 0);
      *isSymbolicPage = 0;
    }
  }
  return ret;
}

// Not implemented
/*
extern "C" SANITIZER_INTERFACE_ATTRIBUTE off_t
__dfsan_lseek(int fd, off_t offset, int whence, dfsan_label fd_label,
             dfsan_label offset_label, dfsan_label whence_label,
             dfsan_label *ret_label) {
  off_t ret = lseek(fd, offset, whence);
  if (ret != (off_t)-1) {
    if (taint_get_file(fd)) {
      taint_set_offset_label(offset_label);
      if (offset_label) {
        __taint_trace_offset(offset_label, offset, sizeof(offset) * 8);
      }
    }
    *ret_label = offset_label;
  } else *ret_label = 0;
  return ret;
}
*/
#if SANITIZER_CAN_USE_PREINIT_ARRAY
__attribute__((section(".preinit_array"), used))
static void (*dfsan_init_ptr)(int, char **, char **) = dfsan_init;
#endif

extern "C" {
// SANITIZER_INTERFACE_WEAK_DEF(void, InitializeSolver, void) {}

// Default empty implementations (weak) for hooks
// SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_cmp, dfsan_label, dfsan_label,
//                              u32, u32, u64, u64, u32) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_cond, dfsan_label, u8, u32) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_indcall, dfsan_label) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_gep, dfsan_label, uint64_t,
                             dfsan_label, int64_t, uint64_t, uint64_t, int64_t) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_offset, dfsan_label, int64_t,
                             unsigned) {}
SANITIZER_INTERFACE_WEAK_DEF(void, __taint_trace_memcmp, dfsan_label) {}
// SANITIZER_WEAK_ATTRIBUTE THREADLOCAL u32 __taint_trace_callstack;
}  // extern "C"

// Code from fastgen.cpp
static u32 __instance_id;
static u32 __session_id;
static int __pipe_fd;

SANITIZER_INTERFACE_WEAK_DEF(void, InitializeSolver, void) {
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
  __pipe_fd = flags().pipe_fd;
  AOUT("InitializeSolver: instance_id = %d, session_id = %d, pipe_fd = %d\n",
       __instance_id, __session_id, __pipe_fd);
}
// filter?
SANITIZER_INTERFACE_ATTRIBUTE SANITIZER_WEAK_ATTRIBUTE THREADLOCAL u32
    __taint_trace_callstack;

static u8 get_const_result(u64 c1, u64 c2, u32 predicate) {
  switch (predicate) {
    case __dfsan::bveq:  return c1 == c2;
    case __dfsan::bvneq: return c1 != c2;
    case __dfsan::bvugt: return c1 > c2;
    case __dfsan::bvuge: return c1 >= c2;
    case __dfsan::bvult: return c1 < c2;
    case __dfsan::bvule: return c1 <= c2;
    case __dfsan::bvsgt: return (s64)c1 > (s64)c2;
    case __dfsan::bvsge: return (s64)c1 >= (s64)c2;
    case __dfsan::bvslt: return (s64)c1 < (s64)c2;
    case __dfsan::bvsle: return (s64)c1 <= (s64)c2;
    default: break;
  }
  return 0;
}

static inline void __solve_cond(dfsan_label label, u8 result, u8 add_nested, u32 cid, void *addr) {

  u16 flags = 0;
  if (add_nested) flags |= F_ADD_CONS;

  // send info
  pipe_msg msg = {
    .msg_type = cond_type,
    .flags = flags,
    .instance_id = __instance_id,
    .addr = (uptr)addr,
    .context = __taint_trace_callstack,
    .id = cid,
    .label = label,
    .result = result
  };

  internal_write(__pipe_fd, &msg, sizeof(msg));
}

SANITIZER_INTERFACE_WEAK_DEF(dfsan_label, __taint_trace_cmp, dfsan_label op1,
                             dfsan_label op2, u32 size, u32 predicate, u64 c1,
                             u64 c2, u32 cid) {
  if ((op1 == 0 && op2 == 0))
    return 0;

  void *addr = __builtin_return_address(0);
  unsigned char result = get_const_result(c1, c2, predicate);

  if (telemetry_enabled) {
      // Build natural language summary first for LLM/JSON transmission
      char summary[256];
      const char * predicate_name = get_predicate_name(predicate); // Since we're using this twice, should we get this once unconditionally?
      if (op1 != 0 && op2 == 0) {
          snprintf(summary, sizeof(summary) - 1,
              "%llu (label %u) %s %llu (constant) at PC 0x%llx, result: %s",
              c1, op1, predicate_name, c2, cid, result ? "taken" : "not taken");
      } else if (op1 == 0 && op2 != 0) {
          snprintf(summary, sizeof(summary) - 1,
              "%llu (constant) %s %llu (label %u) at PC 0x%llx, result: %s",
              c1, predicate_name, c2, op2, cid, result ? "taken" : "not taken");
      } else {
          snprintf(summary, sizeof(summary) - 1,
              "%llu (label %u) %s %llu (label %u) at PC 0x%llx, result: %s",
              c1, op1, predicate_name, c2, op2, cid, result ? "taken" : "not taken");
      }
      char jsonbuffer[1280];
      snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
          "{"
          "\"source\": \"dfsan\","
          "\"trigger\": \"branch_eval\","
          "\"summary\": \"%s\","
          "\"pc\": \"0x%llx\","
          "\"predicate\": \"%s\","
          "\"op1_symbolic\": %s,"
          "\"op1_label\": %u,"
          "\"op1_val\": %llu,"
          "\"op2_symbolic\": %s,"
          "\"op2_label\": %u,"
          "\"op2_val\": %llu,"
          "\"result\": %d"
          "}",
          summary, cid, predicate_name,
          (op1 != 0) ? "true" : "false", op1, c1,
          (op2 != 0) ? "true" : "false", op2, c2,
          (int)result);
      telemetry_send(jsonbuffer);
  }

    // Enhanced logging with concrete values via Claude. Erase/etc as necessary
    if (print_debug) {
        const char * pred_name = get_predicate_name(predicate);
        fprintf(stderr, "[BRANCH] PC=0x%llx: ", cid);

        if (op1 != 0 && op2 == 0) {
            fprintf(stderr, "symbolic(label=%u, val=%llu) %s constant(%llu), result=%llu\n",
                    op1, c1, pred_name, c2, result);
        } else if (op1 == 0 && op2 != 0) {
            fprintf(stderr, "constant(%llu) %s symbolic(label=%u, val=%llu), result=%llu\n",
                    c1, pred_name, op2, c2, result);
        } else {
            fprintf(stderr, "symbolic(label=%u, val=%llu) %s symbolic(label=%u, val=%llu), result=%llu\n",
                    op1, c1, pred_name, op2, c2, result);
        }

        // Optionally print full expressions
        //if (g_print_expressions) {
            if (op1 != 0) {
                fprintf(stderr, "  [EXPR_OP1] label=%u: ", op1);
            }
            if (op2 != 0) {
                fprintf(stderr, "  [EXPR_OP2] label=%u: ", op2);
            }
        //}
    }

  AOUT("solving cmp: %u %u %u %d %llu %llu 0x%x @%p\n",
       op1, op2, size, predicate, c1, c2, cid, addr);

  // save info to a union table slot
  u8 r = get_const_result(c1, c2, predicate);
  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2, cid);

  // add nested only for matching cases
  __solve_cond(temp, r, r, cid, addr);
  return temp;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
addContextRecording(u64 func_addr) {
  u32 hash = xxhash(func_addr, 0, 0);
  __taint_trace_callstack ^= hash;
  // AOUT("UPDATE CONTEXT: %u\n", __taint_trace_callstack);
}
