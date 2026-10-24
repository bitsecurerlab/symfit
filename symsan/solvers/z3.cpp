#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "dfsan/dfsan.h"

#include <z3++.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <time.h>

#define OPTIMISTIC 1

using namespace __dfsan;

extern "C" bool symsan_find_load_metadata_for_label(
    dfsan_label load_label, dfsan_label *addr_label, uint64_t *concrete_addr,
    uint64_t *concrete_value, uint64_t *pc) __attribute__((weak));

// for output
static const char* __output_dir;
static u32 __instance_id;
static u32 __session_id;
static u32 __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");

// filter?
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u32 __taint_trace_callstack;

static std::unordered_set<dfsan_label> __solved_labels;
typedef std::pair<u32, u64> trace_context;
struct context_hash {
  std::size_t operator()(const trace_context &context) const {
    return std::hash<u32>{}(context.first) ^ std::hash<u64>{}(context.second);
  }
};
static std::unordered_map<trace_context, u16, context_hash> __branches;
static const u16 MAX_BRANCH_COUNT = 16;
static const u64 MAX_GEP_INDEX = 0x10000;
static std::unordered_set<uptr> __buffers;

// caches
static std::unordered_map<dfsan_label, u32> tsize_cache;
static std::unordered_map<dfsan_label, std::unordered_set<u32> > deps_cache;
static std::unordered_map<dfsan_label, z3::expr> expr_cache;
static std::unordered_map<u32, u8> input_seed;
static unsigned __value_query_relaxation_profile = 0;

// dependencies
struct expr_hash {
  std::size_t operator()(const z3::expr &expr) const {
    return expr.hash();
  }
};
struct expr_equal {
  bool operator()(const z3::expr &lhs, const z3::expr &rhs) const {
    return lhs.id() == rhs.id();
  }
};
typedef std::unordered_set<z3::expr, expr_hash, expr_equal> expr_set_t;
static expr_set_t __load_expr_deps;
static bool __collect_load_expr_deps = false;
static std::vector<dfsan_solve_assumption> __solve_assumptions;
static bool __collect_solve_assumptions = false;
typedef struct {
  expr_set_t expr_deps;
  std::unordered_set<dfsan_label> input_deps;
  std::unordered_map<dfsan_label, bool> cond_directions;
} branch_dep_t;
typedef struct {
  dfsan_label label;
  bool taken;
  u64 pc;
  u64 seq;
} recorded_branch_t;
static std::vector<branch_dep_t*> __branch_deps;
static std::vector<recorded_branch_t> __recorded_branches;
static u64 __recorded_branch_seq = 0;

static inline branch_dep_t* get_branch_dep(size_t n) {
  if (n >= __branch_deps.size()) {
    __branch_deps.resize(n + 1);
  }
  return __branch_deps.at(n);
}

static inline void set_branch_dep(size_t n, branch_dep_t* dep) {
  if (n >= __branch_deps.size()) {
    __branch_deps.resize(n + 1);
  }
  __branch_deps.at(n) = dep;
}

enum class SerializeMode {
  Solve,
  Format,
};

static z3::expr serialize(dfsan_label label, std::unordered_set<u32> &deps,
                          SerializeMode mode);
static z3::expr direction_expr(const z3::expr &cond, bool taken);

static bool matches_observed_value(const z3::expr &expr,
                                   const std::unordered_set<u32> &deps,
                                   u64 observed) {
  z3::expr_vector from(__z3_context);
  z3::expr_vector to(__z3_context);
  for (u32 offset : deps) {
    auto it = input_seed.find(offset);
    if (it == input_seed.end()) {
      return false;
    }
    std::string name = "symfit_input_" + std::to_string(offset);
    from.push_back(__z3_context.constant(
        __z3_context.str_symbol(name.c_str()), __z3_context.bv_sort(8)));
    to.push_back(__z3_context.bv_val(it->second, 8));
  }
  z3::expr candidate = expr;
  z3::expr concrete = candidate.substitute(from, to).simplify();
  uint64_t value = 0;
  return concrete.is_bv() && concrete.is_numeral() &&
         Z3_get_numeral_uint64(__z3_context, concrete, &value) &&
         value == observed;
}

static inline expr_set_t take_load_expr_deps() {
  expr_set_t out;
  out.swap(__load_expr_deps);
  __collect_load_expr_deps = false;
  return out;
}

static inline void begin_load_expr_dep_collection() {
  __load_expr_deps.clear();
  __collect_load_expr_deps = true;
}

static inline void begin_solve_assumption_collection() {
  __solve_assumptions.clear();
  __collect_solve_assumptions = true;
}

static inline std::vector<dfsan_solve_assumption> take_solve_assumptions() {
  std::vector<dfsan_solve_assumption> out;
  out.swap(__solve_assumptions);
  __collect_solve_assumptions = false;
  return out;
}

static std::string format_simplified_expr(const z3::expr &expr, unsigned depth);

static std::string make_display_load_name(unsigned bits,
                                          const std::string &addr_expr) {
  return "load" + std::to_string(bits) + "(" + addr_expr + ")";
}

static uint64_t mask_for_bits(unsigned bits) {
  if (bits == 0 || bits >= 64) {
    return UINT64_MAX;
  }
  return (1ULL << bits) - 1ULL;
}

static std::string format_bv_literal(const z3::expr &expr) {
  unsigned bits = expr.get_sort().bv_size();
  uint64_t raw = 0;
  Z3_get_numeral_uint64(expr.ctx(), expr, &raw);
  raw &= mask_for_bits(bits);

  if (bits == 1) {
    return raw ? "true" : "false";
  }

  int64_t signed_value = 0;
  if (bits == 0 || bits >= 64) {
    signed_value = static_cast<int64_t>(raw);
  } else if (raw & (1ULL << (bits - 1))) {
    signed_value = static_cast<int64_t>(raw | ~mask_for_bits(bits));
  } else {
    signed_value = static_cast<int64_t>(raw);
  }

  if (signed_value < 0 && signed_value >= -4096) {
    return std::to_string(signed_value);
  }
  if (raw <= 9) {
    return std::to_string(raw);
  }

  char buf[32];
  internal_snprintf(buf, sizeof(buf), "0x%llx",
                    static_cast<unsigned long long>(raw));
  return std::string(buf);
}

static const char *c_int_type_name(unsigned bits, bool is_signed) {
  switch (bits) {
    case 8:  return is_signed ? "int8_t" : "uint8_t";
    case 16: return is_signed ? "int16_t" : "uint16_t";
    case 32: return is_signed ? "int32_t" : "uint32_t";
    case 64: return is_signed ? "int64_t" : "uint64_t";
    default: return is_signed ? "int64_t" : "uint64_t";
  }
}

static std::string format_cast(const char *type_name, const z3::expr &arg,
                               unsigned depth) {
  return "((" + std::string(type_name) + ") " + format_simplified_expr(arg, depth + 1) + ")";
}

static std::string format_binary(const char *op, const z3::expr &lhs,
                                 const z3::expr &rhs, unsigned depth) {
  return "(" + format_simplified_expr(lhs, depth + 1) + " " + op + " " +
         format_simplified_expr(rhs, depth + 1) + ")";
}

static std::string format_nary(const char *op, const z3::expr &expr,
                               unsigned depth) {
  unsigned argc = expr.num_args();
  if (argc == 0) {
    return expr.to_string();
  }
  if (argc == 1) {
    return format_simplified_expr(expr.arg(0), depth + 1);
  }

  std::string out = "(" + format_simplified_expr(expr.arg(0), depth + 1);
  for (unsigned i = 1; i < argc; ++i) {
    out += " ";
    out += op;
    out += " ";
    out += format_simplified_expr(expr.arg(i), depth + 1);
  }
  out += ")";
  return out;
}

static std::string format_binary_strings(const char *op, const std::string &lhs,
                                         const std::string &rhs) {
  return "(" + lhs + " " + op + " " + rhs + ")";
}

static std::string format_simplified_expr(const z3::expr &expr, unsigned depth) {
  if (depth > 32) {
    return "...";
  }
  if (expr.is_true()) {
    return "true";
  }
  if (expr.is_false()) {
    return "false";
  }
  if (expr.is_numeral()) {
    return format_bv_literal(expr);
  }
  if (expr.is_const() && expr.num_args() == 0) {
    z3::symbol name = expr.decl().name();
    if (name.kind() == Z3_INT_SYMBOL) {
      return "input(" + std::to_string(name.to_int()) + ")";
    }
    if (name.kind() == Z3_STRING_SYMBOL) {
      return std::string(name.str());
    }
  }

  switch (expr.decl().decl_kind()) {
    case Z3_OP_BNOT:
      return "(~" + format_simplified_expr(expr.arg(0), depth + 1) + ")";
    case Z3_OP_NOT:
      return "(!" + format_simplified_expr(expr.arg(0), depth + 1) + ")";
    case Z3_OP_BNEG:
      return "(-" + format_simplified_expr(expr.arg(0), depth + 1) + ")";
    case Z3_OP_BADD:
      return format_nary("+", expr, depth);
    case Z3_OP_BSUB:
      return format_binary("-", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_BMUL:
      return format_nary("*", expr, depth);
    case Z3_OP_BAND:
      return format_nary("&", expr, depth);
    case Z3_OP_BOR:
      return format_nary("|", expr, depth);
    case Z3_OP_BXOR:
      return format_nary("^", expr, depth);
    case Z3_OP_AND:
      return format_nary("&&", expr, depth);
    case Z3_OP_OR:
      return format_nary("||", expr, depth);
    case Z3_OP_XOR:
      return format_nary("^", expr, depth);
    case Z3_OP_BSHL:
      return format_binary("<<", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_BLSHR:
    case Z3_OP_BASHR:
      return format_binary(">>", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_BUDIV:
    case Z3_OP_BSDIV:
      return format_binary("/", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_BUREM:
    case Z3_OP_BSREM:
    case Z3_OP_BSMOD:
      return format_binary("%", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_EQ:
      return format_binary("==", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_DISTINCT:
      return format_binary("!=", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_ULT:
      return format_binary("<", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_ULEQ:
      return format_binary("<=", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_UGT:
      return format_binary(">", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_UGEQ:
      return format_binary(">=", expr.arg(0), expr.arg(1), depth);
    case Z3_OP_SLT:
      return format_binary_strings("<",
                                   format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size(), true), expr.arg(0), depth),
                                   format_cast(c_int_type_name(expr.arg(1).get_sort().bv_size(), true), expr.arg(1), depth));
    case Z3_OP_SLEQ:
      return format_binary_strings("<=",
                                   format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size(), true), expr.arg(0), depth),
                                   format_cast(c_int_type_name(expr.arg(1).get_sort().bv_size(), true), expr.arg(1), depth));
    case Z3_OP_SGT:
      return format_binary_strings(">",
                                   format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size(), true), expr.arg(0), depth),
                                   format_cast(c_int_type_name(expr.arg(1).get_sort().bv_size(), true), expr.arg(1), depth));
    case Z3_OP_SGEQ:
      return format_binary_strings(">=",
                                   format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size(), true), expr.arg(0), depth),
                                   format_cast(c_int_type_name(expr.arg(1).get_sort().bv_size(), true), expr.arg(1), depth));
    case Z3_OP_ZERO_EXT: {
      unsigned ext = Z3_get_decl_int_parameter(expr.ctx(), expr.decl(), 0);
      return format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size() + ext, false), expr.arg(0), depth);
    }
    case Z3_OP_SIGN_EXT: {
      unsigned ext = Z3_get_decl_int_parameter(expr.ctx(), expr.decl(), 0);
      return format_cast(c_int_type_name(expr.arg(0).get_sort().bv_size() + ext, true), expr.arg(0), depth);
    }
    case Z3_OP_EXTRACT: {
      unsigned hi = Z3_get_decl_int_parameter(expr.ctx(), expr.decl(), 0);
      unsigned lo = Z3_get_decl_int_parameter(expr.ctx(), expr.decl(), 1);
      uint64_t mask = mask_for_bits(hi - lo + 1);
      char mask_buf[32];
      internal_snprintf(mask_buf, sizeof(mask_buf), "0x%llx",
                        static_cast<unsigned long long>(mask));
      return "(((" + format_simplified_expr(expr.arg(0), depth + 1) + ") >> " +
             std::to_string(lo) + ") & " + std::string(mask_buf) + ")";
    }
    case Z3_OP_CONCAT:
      return "concat(" + format_simplified_expr(expr.arg(0), depth + 1) + ", " +
             format_simplified_expr(expr.arg(1), depth + 1) + ")";
    case Z3_OP_ITE:
      return "(" + format_simplified_expr(expr.arg(0), depth + 1) + " ? " +
             format_simplified_expr(expr.arg(1), depth + 1) + " : " +
             format_simplified_expr(expr.arg(2), depth + 1) + ")";
    default:
      break;
  }

  return expr.to_string();
}

static bool eval_cmp_taken(u32 predicate, u32 size, u64 c1, u64 c2) {
  const unsigned bits = size;
  const uint64_t mask = (bits == 0 || bits >= 64) ? UINT64_MAX : ((1ULL << bits) - 1ULL);
  const uint64_t lhs = c1 & mask;
  const uint64_t rhs = c2 & mask;

  auto sext = [bits](uint64_t value) -> int64_t {
    if (bits == 0 || bits >= 64) {
      return static_cast<int64_t>(value);
    }
    const uint64_t sign_bit = 1ULL << (bits - 1);
    if (value & sign_bit) {
      return static_cast<int64_t>(value | ~((1ULL << bits) - 1ULL));
    }
    return static_cast<int64_t>(value);
  };

  switch (predicate) {
  case bveq:
    return lhs == rhs;
  case bvneq:
    return lhs != rhs;
  case bvugt:
    return lhs > rhs;
  case bvuge:
    return lhs >= rhs;
  case bvult:
    return lhs < rhs;
  case bvule:
    return lhs <= rhs;
  case bvsgt:
    return sext(lhs) > sext(rhs);
  case bvsge:
    return sext(lhs) >= sext(rhs);
  case bvslt:
    return sext(lhs) < sext(rhs);
  case bvsle:
    return sext(lhs) <= sext(rhs);
  default:
    return false;
  }
}

static bool get_branch_direction(dfsan_label label, bool *taken) {
  if (!dfsan_is_branch_condition_label(label)) {
    return false;
  }

  for (auto it = __recorded_branches.rbegin(); it != __recorded_branches.rend();
       ++it) {
    if (it->label == label) {
      if (taken != nullptr) {
        *taken = it->taken;
      }
      return true;
    }
  }

  return false;
}

static void expand_transitive_input_slice(std::unordered_set<u32> &inputs) {
  std::vector<u32> worklist;

  worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
  while (!worklist.empty()) {
    auto off = worklist.back();
    worklist.pop_back();

    auto deps = get_branch_dep(off);
    if (deps == nullptr) {
      continue;
    }
    for (auto input : deps->input_deps) {
      if (inputs.insert(input).second) {
        worklist.push_back(input);
      }
    }
  }
}

static bool collect_transitive_input_slice(dfsan_label label,
                                           std::unordered_set<u32> &inputs,
                                           bool require_branch_root = true) {
  if (require_branch_root && !dfsan_is_branch_condition_label(label)) {
    return false;
  }

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &) {
    return false;
  }

  expand_transitive_input_slice(inputs);
  return true;
}

static bool get_label_inputs(dfsan_label label, std::unordered_set<u32> &inputs) {
  auto deps_it = deps_cache.find(label);
  if (deps_it != deps_cache.end()) {
    inputs.insert(deps_it->second.begin(), deps_it->second.end());
    return true;
  }

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &) {
    return false;
  }

  return true;
}

static bool inputs_overlap(const std::unordered_set<u32> &lhs,
                           const std::unordered_set<u32> &rhs) {
  if (lhs.size() > rhs.size()) {
    return inputs_overlap(rhs, lhs);
  }

  for (auto input : lhs) {
    if (rhs.count(input) != 0) {
      return true;
    }
  }

  return false;
}

static dfsan_pc_range __pc_filter_ranges[DFSAN_MAX_PC_FILTER_RANGES];
static size_t __pc_filter_count = 0;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_set_constraint_pc_filter(const dfsan_pc_range *ranges, uptr count) {
  if (count > DFSAN_MAX_PC_FILTER_RANGES) return -1;
  memcpy(__pc_filter_ranges, ranges, count * sizeof(dfsan_pc_range));
  __pc_filter_count = count;
  return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_clear_constraint_pc_filter(void) {
  __pc_filter_count = 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
dfsan_get_constraint_pc_filter(dfsan_pc_range *out, uptr capacity) {
  uptr n = __pc_filter_count < capacity ? __pc_filter_count : capacity;
  if (n > 0 && out) memcpy(out, __pc_filter_ranges, n * sizeof(dfsan_pc_range));
  return __pc_filter_count;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_is_constraint_pc_filtered(u64 pc) {
  for (size_t i = 0; i < __pc_filter_count; i++) {
    if (pc >= __pc_filter_ranges[i].start && pc < __pc_filter_ranges[i].end)
      return 1;
  }
  return 0;
}

static bool collect_recorded_constraint_context(
    dfsan_label label, std::unordered_set<u32> &inputs,
    std::vector<dfsan_label> &labels, std::vector<uint8_t> *directions = nullptr,
    bool require_branch_root = true) {
  std::unordered_set<dfsan_label> seen;
  int64_t root_trace_index = -1;

  struct timespec ts_cc0, ts_cc1;
  clock_gettime(CLOCK_MONOTONIC, &ts_cc0);

  if (!collect_transitive_input_slice(label, inputs, require_branch_root)) {
    return false;
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_cc1);
  double slice_ms = (ts_cc1.tv_sec - ts_cc0.tv_sec) * 1000.0 +
                    (ts_cc1.tv_nsec - ts_cc0.tv_nsec) / 1e6;

  if (dfsan_is_branch_condition_label(label)) {
    for (int64_t i = static_cast<int64_t>(__recorded_branches.size()) - 1; i >= 0;
         --i) {
      if (__recorded_branches[i].label == label) {
        root_trace_index = i;
        break;
      }
    }
    if (require_branch_root && root_trace_index < 0) {
      return false;
    }
  }

  if (directions != nullptr) {
    directions->clear();
  }

  fprintf(stderr, "[COLLECT-ENTRY] label=%u slice=%.1fms "
          "expanded_inputs=%zu recorded_branches=%zu "
          "root_trace_idx=%lld\n",
          label, slice_ms, inputs.size(),
          __recorded_branches.size(), (long long)root_trace_index);

  size_t loop_iters = 0;
  size_t get_inputs_calls = 0;
  double get_inputs_total_ms = 0;
  dfsan_label slowest_label = 0;
  double slowest_ms = 0;

  for (size_t i = 0; i < __recorded_branches.size(); ++i) {
    const auto &entry = __recorded_branches[i];
    std::unordered_set<u32> cond_inputs;
    loop_iters++;

    if (root_trace_index >= 0 && static_cast<int64_t>(i) >= root_trace_index) {
      break;
    }
    if (!require_branch_root && entry.label == label) {
      continue;
    }
    if (entry.label == label || !seen.insert(entry.label).second) {
      continue;
    }

    struct timespec ts_gi0, ts_gi1;
    clock_gettime(CLOCK_MONOTONIC, &ts_gi0);

    if (!get_label_inputs(entry.label, cond_inputs) ||
        !inputs_overlap(inputs, cond_inputs)) {
      clock_gettime(CLOCK_MONOTONIC, &ts_gi1);
      double gi_ms = (ts_gi1.tv_sec - ts_gi0.tv_sec) * 1000.0 +
                     (ts_gi1.tv_nsec - ts_gi0.tv_nsec) / 1e6;
      get_inputs_calls++;
      get_inputs_total_ms += gi_ms;
      if (gi_ms > slowest_ms) { slowest_ms = gi_ms; slowest_label = entry.label; }
      continue;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_gi1);
    double gi_ms = (ts_gi1.tv_sec - ts_gi0.tv_sec) * 1000.0 +
                   (ts_gi1.tv_nsec - ts_gi0.tv_nsec) / 1e6;
    get_inputs_calls++;
    get_inputs_total_ms += gi_ms;
    if (gi_ms > slowest_ms) { slowest_ms = gi_ms; slowest_label = entry.label; }

    if (dfsan_is_constraint_pc_filtered(get_label_info(entry.label)->pc)) {
      continue;
    }

    labels.push_back(entry.label);
    if (directions != nullptr) {
      directions->push_back(entry.taken ? 1 : 0);
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_cc1);
  double total_ms = (ts_cc1.tv_sec - ts_cc0.tv_sec) * 1000.0 +
                    (ts_cc1.tv_nsec - ts_cc0.tv_nsec) / 1e6;
  if (total_ms > 100.0) {
    fprintf(stderr, "[COLLECT-DIAG] label=%u total=%.1fms "
            "input_slice=%.1fms expanded_inputs=%zu "
            "recorded_branches=%zu loop_iters=%zu "
            "get_inputs_calls=%zu get_inputs_total=%.1fms "
            "slowest_label=%u slowest=%.1fms "
            "root_trace_idx=%lld matched=%zu\n",
            label, total_ms, slice_ms, inputs.size(),
            __recorded_branches.size(), loop_iters,
            get_inputs_calls, get_inputs_total_ms,
            slowest_label, slowest_ms,
            (long long)root_trace_index, labels.size());
  }

  return true;
}
static void record_branch_inputs(dfsan_label label, bool taken, u64 pc) {
  std::unordered_set<u32> inputs;

  if (!dfsan_is_branch_condition_label(label)) {
    return;
  }

  __recorded_branches.push_back({label, taken, pc, __recorded_branch_seq++});

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &e) {
    Report("WARNING: record_branch_inputs: serialize(Format) threw for label %u: %s\n",
           label, e.msg());
    return;
  }

  for (auto off : inputs) {
    auto c = get_branch_dep(off);
    if (c == nullptr) {
      c = new branch_dep_t();
      set_branch_dep(off, c);
    }
    if (c == nullptr) {
      Report("WARNING: out of memory\n");
      continue;
    }
    c->input_deps.insert(inputs.begin(), inputs.end());
    c->cond_directions[label] = taken;
  }
}

static bool collect_nested_constraint_labels(dfsan_label label,
                                             std::vector<dfsan_label> &labels,
                                             std::vector<uint8_t> *directions = nullptr,
                                             bool require_branch_root = true) {
  std::unordered_set<u32> inputs;
  std::vector<dfsan_label> ordered;

  if (!collect_recorded_constraint_context(label, inputs, ordered, directions,
                                           require_branch_root)) {
    return false;
  }

  labels.swap(ordered);
  return true;
}

static z3::expr read_concrete(u64 addr, u8 size) {
  u8 *ptr = reinterpret_cast<u8*>(addr);
  if (ptr == nullptr) {
    throw z3::exception("invalid concrete address");
  }

  z3::expr val = __z3_context.bv_val(*ptr++, 8);
  for (u8 i = 1; i < size; i++) {
    val = z3::concat(__z3_context.bv_val(*ptr++, 8), val);
  }
  return val;
}

static size_t assert_recorded_path_constraints(dfsan_label label,
                                               expr_set_t &added,
                                               bool require_branch_root,
                                               bool include_cond_load_deps = true) {
  std::unordered_set<u32> inputs;
  std::vector<dfsan_label> cond_labels;
  std::vector<uint8_t> cond_taken;
  size_t asserted = 0;

  struct timespec ts_ap0, ts_ap1;
  clock_gettime(CLOCK_MONOTONIC, &ts_ap0);

  fprintf(stderr, "[ASSERT-PC] label=%u enter recorded_branches=%zu\n",
          label, __recorded_branches.size());

  if (!collect_recorded_constraint_context(label, inputs, cond_labels,
                                           &cond_taken, require_branch_root)) {
    fprintf(stderr, "[ASSERT-PC] label=%u collect returned false\n", label);
    return 0;
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_ap1);
  double collect_ms = (ts_ap1.tv_sec - ts_ap0.tv_sec) * 1000.0 +
                      (ts_ap1.tv_nsec - ts_ap0.tv_nsec) / 1e6;
  fprintf(stderr, "[ASSERT-PC] label=%u collect=%.1fms cond_labels=%zu "
          "inputs=%zu\n",
          label, collect_ms, cond_labels.size(), inputs.size());

  for (auto off : inputs) {
    auto deps = get_branch_dep(off);
    if (deps == nullptr) {
      continue;
    }
    for (auto &expr : deps->expr_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }
  }

  for (size_t i = 0; i < cond_labels.size() && i < cond_taken.size(); i++) {
    struct timespec ts_ser0, ts_ser1;
    clock_gettime(CLOCK_MONOTONIC, &ts_ser0);

    std::unordered_set<u32> cond_inputs;
    begin_load_expr_dep_collection();
    z3::expr cond = serialize(cond_labels[i], cond_inputs, SerializeMode::Solve);
    expr_set_t cond_load_expr_deps = take_load_expr_deps();
    z3::expr direction = direction_expr(cond, cond_taken[i] != 0);
    if (added.insert(direction).second) {
      __z3_solver.add(direction);
      asserted += 1;
    }
    if (include_cond_load_deps) {
      for (auto &expr : cond_load_expr_deps) {
        if (added.insert(expr).second) {
          __z3_solver.add(expr);
        }
      }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_ser1);
    double ser_ms = (ts_ser1.tv_sec - ts_ser0.tv_sec) * 1000.0 +
                    (ts_ser1.tv_nsec - ts_ser0.tv_nsec) / 1e6;
    if (ser_ms > 50.0) {
      fprintf(stderr, "[ASSERT-PC] label=%u nested[%zu]=%u "
              "serialize(Solve)=%.1fms\n",
              label, i, cond_labels[i], ser_ms);
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_ap1);
  double total_ms = (ts_ap1.tv_sec - ts_ap0.tv_sec) * 1000.0 +
                    (ts_ap1.tv_nsec - ts_ap0.tv_nsec) / 1e6;
  fprintf(stderr, "[ASSERT-PC] label=%u done=%.1fms asserted=%zu\n",
          label, total_ms, asserted);

  return asserted;
}

static z3::expr get_cmd(z3::expr const &lhs, z3::expr const &rhs, u32 predicate) {
  switch (predicate) {
    case bveq:  return lhs == rhs;
    case bvneq: return lhs != rhs;
    case bvugt: return z3::ugt(lhs, rhs);
    case bvuge: return z3::uge(lhs, rhs);
    case bvult: return z3::ult(lhs, rhs);
    case bvule: return z3::ule(lhs, rhs);
    case bvsgt: return lhs > rhs;
    case bvsge: return lhs >= rhs;
    case bvslt: return lhs < rhs;
    case bvsle: return lhs <= rhs;
    default:
      Printf("FATAL: unsupported predicate: %u\n", predicate);
      throw z3::exception("unsupported predicate");
      break;
  }
  // should never reach here
  Die();
}

static inline z3::expr cache_expr(dfsan_label label, z3::expr const &e,
                                  std::unordered_set<u32> &deps,
                                  SerializeMode mode) {
  if (mode == SerializeMode::Format) {
    expr_cache.insert({label, e});
    deps_cache.insert({label, deps});
  }
  return e;
}

static z3::expr serialize(dfsan_label label, std::unordered_set<u32> &deps,
                          SerializeMode mode) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    Report("WARNING: invalid label: %d\n", label);
    throw z3::exception("invalid label");
  }

  dfsan_label_info *info = get_label_info(label);
  AOUT("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%llu, op2:%llu)\n",
       label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  if (mode == SerializeMode::Format) {
    auto expr_itr = expr_cache.find(label);
    if (expr_itr != expr_cache.end()) {
      auto deps_itr = deps_cache.find(label);
      deps.insert(deps_itr->second.begin(), deps_itr->second.end());
      return expr_itr->second;
    }
  }

  // special ops
  if (info->op == 0) {
    // input
    z3::symbol symbol = __z3_context.int_symbol(info->op1.i);
    z3::sort sort = __z3_context.bv_sort(8);
    tsize_cache[label] = 1; // lazy init
    deps.insert(info->op1.i);
    input_seed[info->op1.i] = static_cast<u8>(info->op2.i);
    // caching is not super helpful
    return __z3_context.constant(symbol, sort);
  } else if (info->op == LoadAddr) {
    std::unordered_set<u32> addr_deps;
    z3::expr addr = serialize(info->l1, addr_deps, mode).simplify();
    if (!addr.is_bv()) {
      throw z3::exception("symbolic load address is not a bit-vector");
    }

    if (mode == SerializeMode::Format) {
      std::string addr_rendered = format_simplified_expr(addr, 0);
      z3::symbol load_symbol =
          __z3_context.str_symbol(
              make_display_load_name(info->size, addr_rendered).c_str());
      if (matches_observed_value(addr, addr_deps, info->op1.i)) {
        deps.insert(addr_deps.begin(), addr_deps.end());
      }
      if (info->l2 >= CONST_OFFSET) {
        std::unordered_set<u32> content_deps;
        serialize(info->l2, content_deps, mode);
        deps.insert(content_deps.begin(), content_deps.end());
      }
      tsize_cache[label] = 1;
      return cache_expr(label,
                        __z3_context.constant(
                            load_symbol, __z3_context.bv_sort(info->size)),
                        deps, mode);
    }

    if (!matches_observed_value(addr, addr_deps, info->op1.i)) {
      z3::expr out = __z3_context.bv_val(
          static_cast<uint64_t>(info->op2.i), info->size);
      if (info->l2 >= CONST_OFFSET) {
        out = serialize(info->l2, deps, mode).simplify();
      }
      tsize_cache[label] = 1;
      return cache_expr(label, out, deps, mode);
    }
    deps.insert(addr_deps.begin(), addr_deps.end());

    if (__collect_load_expr_deps) {
      __load_expr_deps.insert(
          addr == __z3_context.bv_val(static_cast<uint64_t>(info->op1.i),
                                      addr.get_sort().bv_size()));
    }
    if (__collect_solve_assumptions) {
      dfsan_solve_assumption assumption = {};
      assumption.load_label = label;
      assumption.addr_label = info->l1;
      assumption.concrete_addr = info->op1.i;
      assumption.concrete_value = info->op2.i;
      assumption.pc = info->pc;
      assumption.size = info->size;
      __solve_assumptions.push_back(assumption);
    }

    z3::expr out = __z3_context.bv_val(static_cast<uint64_t>(info->op2.i),
                                       info->size);
    if (info->l2 >= CONST_OFFSET) {
      out = serialize(info->l2, deps, mode).simplify();
      if (!out.is_bv()) {
        throw z3::exception("symbolic load value is not a bit-vector");
      }
      unsigned value_width = out.get_sort().bv_size();
      if (value_width > info->size) {
        out = out.extract(info->size - 1, 0);
      } else if (value_width < info->size) {
        out = z3::zext(out, info->size - value_width);
      }
    }
    tsize_cache[label] = 1;
    return cache_expr(label, out, deps, mode);
  } else if (info->op == Load) {
    dfsan_label addr_label = 0;
    uint64_t concrete_addr = 0;
    uint64_t concrete_value = 0;
    uint64_t pc = 0;
    bool has_load_metadata =
        symsan_find_load_metadata_for_label != nullptr &&
        symsan_find_load_metadata_for_label(label, &addr_label, &concrete_addr,
                                            &concrete_value, &pc) &&
        addr_label != 0;
    z3::expr out = __z3_context.bv_val(0, info->size);

    if (has_load_metadata) {
      if (mode == SerializeMode::Format) {
        z3::expr addr = serialize(addr_label, deps, mode).simplify();
        std::string addr_rendered = format_simplified_expr(addr, 0);
        z3::symbol load_symbol =
            __z3_context.str_symbol(
                make_display_load_name(info->size, addr_rendered).c_str());
        tsize_cache[label] = 1;
        return cache_expr(label,
                          __z3_context.constant(load_symbol, out.get_sort()),
                          deps, mode);
      }

      out = __z3_context.bv_val(concrete_value, info->size);
      if (__collect_load_expr_deps) {
        z3::expr addr = serialize(addr_label, deps, mode).simplify();
        if (!addr.is_bv()) {
          throw z3::exception("symbolic load address is not a bit-vector");
        }
        __load_expr_deps.insert(
            addr == __z3_context.bv_val(concrete_addr, addr.get_sort().bv_size()));
      }
      if (__collect_solve_assumptions) {
        dfsan_solve_assumption assumption = {};
        assumption.load_label = label;
        assumption.addr_label = addr_label;
        assumption.concrete_addr = concrete_addr;
        assumption.concrete_value = concrete_value;
        assumption.pc = pc;
        assumption.size = info->size;
        __solve_assumptions.push_back(assumption);
      }
    } else {
      u32 byte_count = info->l2;
      u64 offset;
      if (byte_count == 0) {
        byte_count = (info->size > 0 && info->size % 8 == 0)
                     ? info->size / 8 : 1;
        offset = 0x10000000ULL + label;
      } else {
        offset = get_label_info(info->l1)->op1.i;
      }
      {
        static unsigned __load_no_meta_count = 0;
        if (__load_no_meta_count < 5)
          Report("WARNING: Load label %u has no metadata (l1=%u l2=%u pc=0x%llx) — falling back to input-byte model (%u bytes)\n",
                 label, info->l1, info->l2, (unsigned long long)info->pc, byte_count);
        else if (__load_no_meta_count == 5)
          Report("WARNING: suppressing further 'Load label has no metadata' warnings\n");
        __load_no_meta_count++;
      }
      // Populate input_seed; use int_symbol(offset) consistent with
      // the op==0 (input) path so the solver can correlate them.
      if (byte_count > 0) {
        for (u32 i = 0; i < byte_count; i++) {
          dfsan_label candidate = info->l1 + i;
          dfsan_label_info *ci = get_label_info(candidate);
          if (ci->op == 0 && ci->op1.i == (u64)(offset + i)) {
            input_seed[offset + i] = static_cast<u8>(ci->op2.i);
          }
        }
      }
      z3::sort sort = __z3_context.bv_sort(8);
      out = __z3_context.constant(
          __z3_context.int_symbol(offset), sort);
      deps.insert(offset);
      for (u32 i = 1; i < byte_count; i++) {
        out = z3::concat(
            __z3_context.constant(
                __z3_context.int_symbol(offset + i), sort),
            out);
        deps.insert(offset + i);
      }
    }
    tsize_cache[label] = 1; // lazy init
    return cache_expr(label, out, deps, mode);
  } else if (info->op == ZExt) {
    z3::expr base = serialize(info->l1, deps, mode);
    if (base.is_bool()) // dirty hack since llvm lacks bool
      base = z3::ite(base, __z3_context.bv_val(1, 1),
                           __z3_context.bv_val(0, 1));
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::zext(base, info->size - base_size), deps, mode);
  } else if (info->op == SExt) {
    z3::expr base = serialize(info->l1, deps, mode);
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::sext(base, info->size - base_size), deps, mode);
  } else if (info->op == Trunc) {
    z3::expr base = serialize(info->l1, deps, mode);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract(info->size - 1, 0), deps, mode);
  } else if (info->op == Extract) {
    z3::expr base = serialize(info->l1, deps, mode);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract((info->op2.i + info->size) - 1, info->op2.i), deps, mode);
  } else if (info->op == Not) {
    if (info->l2 == 0) {
      throw z3::exception("invalid Not operation");
    }
    z3::expr e = serialize(info->l2, deps, mode);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    /*
    if (!e.is_bool()) {
      throw z3::exception("Only LNot should be recorded");
    */
    if (info->size == 1) {
      if (!e.is_bool()) {
        throw z3::exception("logical Not operand is not Boolean");
      }
      return cache_expr(label, !e, deps, mode);
    }
    if (!e.is_bv() || e.get_sort().bv_size() != info->size) {
      throw z3::exception("bitwise Not operand has invalid sort or width");
    }
    return cache_expr(label, ~e, deps, mode);
  } else if (info->op == Neg) {
    if (info->l2 == 0) {
      throw z3::exception("invalid Neg predicate");
    }
    z3::expr e = serialize(info->l2, deps, mode);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    return cache_expr(label, -e, deps, mode);
  } else if (info->op == IntToPtr) {
    z3::expr e = serialize(info->l1, deps, mode);
    return cache_expr(label, e, deps, mode);
  } else if (info->op == Ite) {
    z3::expr cond = serialize(info->l1, deps, mode);
    if (!cond.is_bool()) {
      if (!cond.is_bv()) {
        throw z3::exception("invalid Ite condition");
      }
      cond = cond != __z3_context.bv_val(0, cond.get_sort().bv_size());
    }
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label,
                      z3::ite(cond,
                              __z3_context.bv_val(1, info->size),
                              __z3_context.bv_val(0, info->size)),
                      deps, mode);
  }
  // higher-order
  else if (info->op == fmemcmp) {
    z3::expr op1 = (info->l1 >= CONST_OFFSET) ? serialize(info->l1, deps, mode) :
                   read_concrete(info->op1.i, info->size); // memcmp size in bytes
    if (info->l2 < CONST_OFFSET) {
      throw z3::exception("invalid memcmp operand2");
    }
    z3::expr op2 = serialize(info->l2, deps, mode);
    tsize_cache[label] = 1; // lazy init
    // don't cache becaue of read_concrete?
    return z3::ite(op1 == op2, __z3_context.bv_val(0, 32),
                               __z3_context.bv_val(1, 32));
  } else if (info->op == fsize) {
    // file size
    z3::symbol symbol = __z3_context.str_symbol("fsize");
    z3::sort sort = __z3_context.bv_sort(info->size);
    z3::expr base = __z3_context.constant(symbol, sort);
    tsize_cache[label] = 1; // lazy init
    // don't cache because of deps
    if (info->op1.i) {
      // minus the offset stored in op1
      z3::expr offset = __z3_context.bv_val((uint64_t)info->op1.i, info->size);
      return base - offset;
    } else {
      return base;
    }
  }

  // common ops
  u8 size = info->size;
  // size for concat is a bit complicated ...
  if (info->op == Concat && info->l1 == 0) {
    assert(info->l2 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l2)->size;
  }
  z3::expr op1 = __z3_context.bv_val((uint64_t)info->op1.i, size);
  if (info->l1 >= CONST_OFFSET) {
    op1 = serialize(info->l1, deps, mode).simplify();
  } else if (info->size == 1) {
    op1 = __z3_context.bool_val(info->op1.i == 1);
  }
  if (info->op == Concat && info->l2 == 0) {
    assert(info->l1 >= CONST_OFFSET);
    size = info->size - get_label_info(info->l1)->size;
  }
  z3::expr op2 = __z3_context.bv_val((uint64_t)info->op2.i, size);
  if (info->l2 >= CONST_OFFSET) {
    std::unordered_set<u32> deps2;
    op2 = serialize(info->l2, deps2, mode).simplify();
    deps.insert(deps2.begin(),deps2.end());
  } else if (info->size == 1) {
    op2 = __z3_context.bool_val(info->op2.i == 1);
  }
  // update tree_size
  tsize_cache[label] = tsize_cache[info->l1] + tsize_cache[info->l2];

  switch((info->op & 0xff)) {
    // llvm doesn't distinguish between logical and bitwise and/or/xor
    case And:     return cache_expr(label, info->size != 1 ? (op1 & op2) : (op1 && op2), deps, mode);
    case Or:      return cache_expr(label, info->size != 1 ? (op1 | op2) : (op1 || op2), deps, mode);
    case Xor:     return cache_expr(label, op1 ^ op2, deps, mode);
    case Shl:     return cache_expr(label, z3::shl(op1, op2), deps, mode);
    case LShr:    return cache_expr(label, z3::lshr(op1, op2), deps, mode);
    case AShr:    return cache_expr(label, z3::ashr(op1, op2), deps, mode);
    case Add:     return cache_expr(label, op1 + op2, deps, mode);
    case Sub:     return cache_expr(label, op1 - op2, deps, mode);
    case Mul:     return cache_expr(label, op1 * op2, deps, mode);
    case UDiv:    return cache_expr(label, z3::udiv(op1, op2), deps, mode);
    case SDiv:    return cache_expr(label, op1 / op2, deps, mode);
    case URem:    return cache_expr(label, z3::urem(op1, op2), deps, mode);
    case SRem:    return cache_expr(label, z3::srem(op1, op2), deps, mode);
    // relational
    case ICmp:    return cache_expr(label, get_cmd(op1, op2, info->op >> 8), deps, mode);
    // concat
    case Concat: {
      // bool→bv1 (ICmp children produce booleans, concat needs bitvectors)
      if (op1.is_bool())
        op1 = z3::ite(op1, __z3_context.bv_val(1, 1), __z3_context.bv_val(0, 1));
      if (op2.is_bool())
        op2 = z3::ite(op2, __z3_context.bv_val(1, 1), __z3_context.bv_val(0, 1));

      u32 w1 = op1.get_sort().bv_size();
      u32 w2 = op2.get_sort().bv_size();
      u32 total = info->size;

      if (w1 + w2 != total && total > 0) {
        // Compute expected l1 width from its label info size; for __taint_union_load
        // Concats, each l2 is one byte (8 bits) and l1 is the accumulation.
        u32 l1_info_size = (info->l1 != 0 && info->l1 >= CONST_OFFSET)
                           ? get_label_info(info->l1)->size : 0;
        u32 need_w1 = (l1_info_size > 0 && l1_info_size < total)
                      ? l1_info_size
                      : (total > 8 ? total - 8 : total / 2);
        u32 need_w2 = total - need_w1;
        if (need_w1 == 0) need_w1 = 1;
        if (need_w2 == 0) need_w2 = 1;

        if (w1 != need_w1) {
          if (w1 > need_w1) op1 = op1.extract(need_w1 - 1, 0);
          else              op1 = z3::zext(op1, need_w1 - w1);
        }
        if (w2 != need_w2) {
          if (w2 > need_w2) op2 = op2.extract(need_w2 - 1, 0);
          else              op2 = z3::zext(op2, need_w2 - w2);
        }
      }

      return cache_expr(label, z3::concat(op2, op1), deps, mode);
    }
    default:
      Printf("FATAL: unsupported op: %u\n", info->op);
      throw z3::exception("unsupported operator");
      break;
  }
  // should never reach here
  Die();
}

static void generate_input(z3::model &m) {
  char path[PATH_MAX];
  internal_snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
                    __instance_id, __session_id, __current_index++);
  fd_t fd = OpenFile(path, WrOnly);
  if (fd == kInvalidFd) {
    throw z3::exception("failed to open new input file for write");
  }

  if (!tainted.is_stdin) {
    if (!WriteToFile(fd, tainted.buf, tainted.size)) {
      throw z3::exception("failed to copy original input\n");
    }
  } else {
    // FIXME: input is stdin
    throw z3::exception("original input is stdin");
  }
  AOUT("generate #%d output\n", __current_index - 1);

  // from qsym
  unsigned num_constants = m.num_consts();
  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int offset = name.to_int();
      u8 value = (u8)e.get_numeral_int();
      AOUT("offset %lld = %x\n", offset, value);
      internal_lseek(fd, offset, SEEK_SET);
      WriteToFile(fd, &value, sizeof(value));
    } else { // string symbol
      if (!name.str().compare("fsize")) {
        off_t size = (off_t)e.get_numeral_int64();
        if (size > tainted.size) { // grow
          internal_lseek(fd, size, SEEK_SET);
          u8 dummy = 0;
          WriteToFile(fd, &dummy, sizeof(dummy));
        } else {
          AOUT("truncate file to %lld\n", size);
          internal_ftruncate(fd, size);
        }
        // don't remember size constraints
        throw z3::exception("skip fsize constraints");
      }
    }
  }

  CloseFile(fd);
}

// assumes under try-catch and the global solver __z3_solver already has nested context
static bool __solve_expr(z3::expr &e) {
  bool ret = false;
  // set up local optmistic solver
  z3::solver opt_solver = z3::solver(__z3_context, "QF_BV");
  opt_solver.set("timeout", 1000U);
  opt_solver.add(e);
  z3::check_result res = opt_solver.check();
  if (res == z3::sat) {
    // optimistic sat, check nested
    __z3_solver.push();
    __z3_solver.add(e);
    res = __z3_solver.check();
    if (res == z3::sat) {
      z3::model m = __z3_solver.get_model();
      generate_input(m);
      ret = true;
    } else {
    #if OPTIMISTIC
      z3::model m = opt_solver.get_model();
      generate_input(m);
    #endif
    }
    // reset
    __z3_solver.pop();
  }
  return ret;
}

static void __solve_cond(dfsan_label label, z3::expr &result, bool add_nested, void *addr) {
  if (__solved_labels.count(label) != 0) 
    return;

  try {
    std::unordered_set<dfsan_label> inputs;
    begin_load_expr_dep_collection();
    z3::expr cond = serialize(label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();
    expand_transitive_input_slice(inputs);

#if 0
    if (get_label_info(label)->tree_size > 50000) {
      // don't bother?
      throw z3::exception("formula too large");
    }
#endif

    // collect additional input deps
    std::vector<dfsan_label> worklist;
    worklist.insert(worklist.begin(), inputs.begin(), inputs.end());
    while (!worklist.empty()) {
      auto off = worklist.back();
      worklist.pop_back();

      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto i : deps->input_deps) {
          if (inputs.insert(i).second)
            worklist.push_back(i);
        }
      }
    }

    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    expr_set_t added;
    assert_recorded_path_constraints(label, added, true);
    for (auto &expr : load_expr_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }
    assert(__z3_solver.check() == z3::sat);
    
    z3::expr e = (cond != result);
    if (__solve_expr(e)) {
      AOUT("branch solved\n");
    } else {
      AOUT("branch not solvable @%p\n", addr);
      //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
      //AOUT("  tree_size = %d", __dfsan_label_info[label].tree_size);
    }

    // nested branch
    if (add_nested) {
      for (auto off : inputs) {
        auto c = get_branch_dep(off);
        if (c == nullptr) {
          c = new branch_dep_t();
          set_branch_dep(off, c);
        }
        if (c == nullptr) {
          Report("WARNING: out of memory\n");
        } else {
          c->input_deps.insert(inputs.begin(), inputs.end());
          c->expr_deps.insert(cond == result);
          c->expr_deps.insert(load_expr_deps.begin(), load_expr_deps.end());
          c->cond_directions[label] = result.is_true();
        }
      }
    }

    // mark as flipped
    __solved_labels.insert(label);
  } catch (z3::exception e) {
    Report("WARNING: solving error: %s @%p\n", e.msg(), addr);
  }

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__taint_trace_cmp(dfsan_label op1, dfsan_label op2, u32 size, u32 predicate,
                  u64 c1, u64 c2, u64 cid) {
  if ((op1 == 0 && op2 == 0))
    return 0;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, cid});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, cid}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return 0;
  }

  AOUT("recording cmp: %u %u %u %d %llu %llu 0x%llx @%p\n",
       op1, op2, size, predicate, c1, c2, (unsigned long long)cid, addr);

  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2, cid);
  record_branch_inputs(temp, eval_cmp_taken(predicate, size, c1, c2), cid);
  return temp;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, u8 r, u64 cid) {
  if (label == 0)
    return;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, cid});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, cid}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return;
  }

  AOUT("recording cond: %u %u 0x%x 0x%llx %p %u\n",
       label, r, __taint_trace_callstack, (unsigned long long)cid, addr,
       itr->second);

  record_branch_inputs(label, r != 0, cid);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_begin_value_solver_capture(void) {
  for (auto dep : __branch_deps) {
    delete dep;
  }
  __branch_deps.clear();
  __recorded_branches.clear();
  __recorded_branch_seq = 0;
  __branches.clear();
  deps_cache.clear();
  expr_cache.clear();
  input_seed.clear();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_begin_value_query_capture(void) {
  dfsan_begin_value_solver_capture();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_set_value_query_relaxation_profile(unsigned profile) {
  if (profile > 3) {
    return 0;
  }
  __value_query_relaxation_profile = profile;
  return 1;
}

static void copy_solve_error(const char *message, char *error,
                             uptr error_capacity);

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_get_value_query_seed(dfsan_label label, u64 *out_value,
                           dfsan_solve_assignment *assignments,
                           uptr assignment_capacity, uptr *assignment_count,
                           char *error, uptr error_capacity) {
  std::vector<dfsan_solve_assignment> seed_assignments;
  if (assignment_count != nullptr) {
    *assignment_count = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }
  try {
    __z3_solver.reset();
    std::unordered_set<u32> inputs;
    begin_load_expr_dep_collection();
    z3::expr value = serialize(label, inputs, SerializeMode::Solve);
    take_load_expr_deps();
    if (!value.is_bv() || value.get_sort().bv_size() > 64) {
      copy_solve_error("seed target is not a supported bit-vector", error,
                       error_capacity);
      return -1;
    }
    for (auto offset : inputs) {
      auto found = input_seed.find(offset);
      if (found == input_seed.end()) {
        copy_solve_error(("missing concrete seed for input offset " +
                          std::to_string(offset)).c_str(), error, error_capacity);
        return -1;
      }
      std::string name = "symfit_input_" + std::to_string(offset);
      z3::expr input = __z3_context.constant(
          __z3_context.str_symbol(name.c_str()), __z3_context.bv_sort(8));
      __z3_solver.add(input == __z3_context.bv_val(found->second, 8));
      dfsan_solve_assignment assignment = {};
      assignment.offset = offset;
      assignment.value = found->second;
      seed_assignments.push_back(assignment);
    }
    if (__z3_solver.check() != z3::sat) {
      copy_solve_error("concrete seed is not satisfiable", error, error_capacity);
      return -1;
    }
    z3::expr evaluated = __z3_solver.get_model().eval(value, true);
    uint64_t raw = 0;
    if (!Z3_get_numeral_uint64(evaluated.ctx(), evaluated, &raw)) {
      copy_solve_error("cannot evaluate concrete seed target", error, error_capacity);
      return -1;
    }
    std::sort(seed_assignments.begin(), seed_assignments.end(),
              [](const dfsan_solve_assignment &lhs,
                 const dfsan_solve_assignment &rhs) {
                return lhs.offset < rhs.offset;
              });
    if (out_value != nullptr) {
      *out_value = raw;
    }
    if (assignment_count != nullptr) {
      *assignment_count = seed_assignments.size();
    }
    if (assignments != nullptr) {
      uptr count = std::min<uptr>(assignment_capacity, seed_assignments.size());
      for (uptr i = 0; i < count; i++) {
        assignments[i] = seed_assignments[i];
      }
    }
    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE size_t
dfsan_get_nested_constraint_count(dfsan_label label) {
  std::vector<dfsan_label> labels;

  if (!collect_nested_constraint_labels(label, labels)) {
    return 0;
  }
  return labels.size();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_get_branch_direction(dfsan_label label, uint8_t *taken) {
  bool direction = false;

  if (!get_branch_direction(label, &direction)) {
    return 0;
  }
  if (taken != nullptr) {
    *taken = direction ? 1 : 0;
  }
  return 1;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE size_t
dfsan_get_nested_constraints(dfsan_label label, dfsan_label *out, size_t capacity) {
  std::vector<dfsan_label> labels;

  if (!collect_nested_constraint_labels(label, labels)) {
    return 0;
  }
  if (out != nullptr && capacity != 0) {
    size_t n = std::min(capacity, labels.size());
    for (size_t i = 0; i < n; ++i) {
      out[i] = labels[i];
    }
  }
  return labels.size();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE size_t
dfsan_get_nested_constraint_directions(dfsan_label label, uint8_t *out, size_t capacity) {
  std::vector<dfsan_label> labels;
  std::vector<uint8_t> directions;

  if (!collect_nested_constraint_labels(label, labels, &directions)) {
    return 0;
  }
  if (out != nullptr && capacity != 0) {
    size_t n = std::min(capacity, directions.size());
    for (size_t i = 0; i < n; ++i) {
      out[i] = directions[i];
    }
  }
  return directions.size();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE size_t
dfsan_format_simplified_expression(dfsan_label label, char *out, size_t capacity) {
  std::unordered_set<u32> deps;
  std::string rendered;

  try {
    z3::expr simplified = serialize(label, deps, SerializeMode::Format).simplify();
    rendered = format_simplified_expr(simplified, 0);
  } catch (z3::exception const &) {
    return 0;
  }

  size_t needed = rendered.size();
  if (out != nullptr && capacity != 0) {
    size_t n = std::min(capacity - 1, needed);
    internal_memcpy(out, rendered.data(), n);
    out[n] = '\0';
  }
  return needed;
}

static void copy_solve_error(const char *message, char *error,
                             uptr error_capacity) {
  if (error == nullptr || error_capacity == 0) {
    return;
  }
  uptr n = internal_strlen(message);
  if (n >= error_capacity) {
    n = error_capacity - 1;
  }
  internal_memcpy(error, message, n);
  error[n] = '\0';
}

static z3::expr direction_expr(const z3::expr &cond, bool taken) {
  if (cond.is_bool()) {
    return cond == __z3_context.bool_val(taken);
  }
  if (cond.is_bv()) {
    return cond == __z3_context.bv_val(taken ? 1 : 0,
                                       cond.get_sort().bv_size());
  }
  throw z3::exception("path constraint is neither bool nor bit-vector");
}

static void append_model_assignments(z3::model &model,
                                     std::vector<dfsan_solve_assignment> &out) {
  unsigned num_constants = model.num_consts();

  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = model.get_const_decl(i);
    z3::symbol name = decl.name();

    z3::expr value = model.get_const_interp(decl);
    uint64_t raw = 0;
    if (!Z3_get_numeral_uint64(value.ctx(), value, &raw)) {
      continue;
    }

    dfsan_solve_assignment assignment = {};
    if (name.kind() == Z3_INT_SYMBOL) {
      assignment.offset = static_cast<uint64_t>(name.to_int());
    } else {
      std::string text = name.str();
      static const std::string prefix = "symfit_input_";
      if (text.compare(0, prefix.size(), prefix) != 0 ||
          text.size() == prefix.size()) {
        continue;
      }
      char *end = nullptr;
      unsigned long long offset =
          std::strtoull(text.c_str() + prefix.size(), &end, 10);
      if (end == nullptr || *end != '\0') {
        continue;
      }
      assignment.offset = static_cast<uint64_t>(offset);
    }
    assignment.value = static_cast<uint8_t>(raw & 0xff);
    out.push_back(assignment);
  }

  std::sort(out.begin(), out.end(),
            [](const dfsan_solve_assignment &lhs,
               const dfsan_solve_assignment &rhs) {
              return lhs.offset < rhs.offset;
            });
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_solve_path_constraint(dfsan_label label, u8 desired_taken,
                            dfsan_solve_assignment *assignments,
                            uptr assignment_capacity,
                            uptr *assignment_count,
                            dfsan_solve_assumption *assumptions,
                            uptr assumption_capacity,
                            uptr *assumption_count,
                            char *error, uptr error_capacity) {
  std::vector<dfsan_label> nested_labels;
  std::vector<uint8_t> nested_directions;
  std::vector<dfsan_solve_assignment> solved_assignments;
  std::vector<dfsan_solve_assumption> solve_assumptions;
  expr_set_t added;

  if (assignment_count != nullptr) {
    *assignment_count = 0;
  }
  if (assumption_count != nullptr) {
    *assumption_count = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }

  if (!dfsan_is_branch_condition_label(label)) {
    copy_solve_error("label is not a branch-condition label", error,
                     error_capacity);
    return -1;
  }

  try {
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    begin_solve_assumption_collection();

    std::unordered_set<u32> root_inputs;
    begin_load_expr_dep_collection();
    z3::expr root = serialize(label, root_inputs, SerializeMode::Solve);
    expr_set_t root_load_deps = take_load_expr_deps();
    __z3_solver.add(direction_expr(root, desired_taken != 0));
    for (auto &expr : root_load_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }

    collect_nested_constraint_labels(label, nested_labels, &nested_directions);
    for (size_t i = 0; i < nested_labels.size() && i < nested_directions.size(); i++) {
      if (nested_labels[i] == label) {
        continue;
      }
      std::unordered_set<u32> nested_inputs;
      begin_load_expr_dep_collection();
      z3::expr nested = serialize(nested_labels[i], nested_inputs,
                                  SerializeMode::Solve);
      expr_set_t nested_load_deps = take_load_expr_deps();
      z3::expr direction = direction_expr(nested, nested_directions[i] != 0);
      if (added.insert(direction).second) {
        __z3_solver.add(direction);
      }
      for (auto &expr : nested_load_deps) {
        if (added.insert(expr).second) {
          __z3_solver.add(expr);
        }
      }
    }

    z3::check_result result = __z3_solver.check();
    solve_assumptions = take_solve_assumptions();
    if (result == z3::unsat) {
      if (assumption_count != nullptr) {
        *assumption_count = solve_assumptions.size();
      }
      return 0;
    }
    if (result != z3::sat) {
      copy_solve_error("solver returned unknown", error, error_capacity);
      return -2;
    }

    z3::model model = __z3_solver.get_model();
    append_model_assignments(model, solved_assignments);

    if (assignment_count != nullptr) {
      *assignment_count = solved_assignments.size();
    }
    if (assumption_count != nullptr) {
      *assumption_count = solve_assumptions.size();
    }
    if (assignments != nullptr && assignment_capacity != 0) {
      uptr n = std::min<uptr>(assignment_capacity, solved_assignments.size());
      for (uptr i = 0; i < n; i++) {
        assignments[i] = solved_assignments[i];
      }
    }
    if (assumptions != nullptr && assumption_capacity != 0) {
      uptr n = std::min<uptr>(assumption_capacity, solve_assumptions.size());
      for (uptr i = 0; i < n; i++) {
        assumptions[i] = solve_assumptions[i];
      }
    }
    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    take_solve_assumptions();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

// Copies at most (capacity - 1) bytes of `text` into `out`, always
// nul-terminating when a buffer is supplied. Reports the untruncated length
// via `*out_len` regardless of whether it fit, mirroring the query-length /
// fill two-pass convention used by dfsan_get_nested_constraints() and
// dfsan_solve_path_constraint(): callers probe with out == nullptr,
// capacity == 0 first, then allocate exactly *out_len + 1 and call again.
static void copy_solve_text(const std::string &text, char *out,
                            uptr capacity, uptr *out_len) {
  if (out_len != nullptr) {
    *out_len = text.size();
  }
  if (out == nullptr || capacity == 0) {
    return;
  }
  uptr n = text.size();
  if (n >= capacity) {
    n = capacity - 1;
  }
  internal_memcpy(out, text.data(), n);
  out[n] = '\0';
}

static std::string hex_u64(u64 value) {
  std::ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

static void append_json_string(std::ostringstream &out,
                               const std::string &value) {
  out << '"';
  for (char ch : value) {
    unsigned char uch = static_cast<unsigned char>(ch);
    switch (ch) {
    case '\\': out << "\\\\"; break;
    case '"': out << "\\\""; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (uch < 0x20) {
        out << "\\u00";
        const char *hex = "0123456789abcdef";
        out << hex[(uch >> 4) & 0xf] << hex[uch & 0xf];
      } else {
        out << ch;
      }
    }
  }
  out << '"';
}

static void append_input_array(std::ostringstream &out,
                               const std::unordered_set<u32> &inputs) {
  std::vector<u32> sorted(inputs.begin(), inputs.end());
  std::sort(sorted.begin(), sorted.end());
  out << '[';
  for (size_t i = 0; i < sorted.size(); i++) {
    if (i != 0) {
      out << ',';
    }
    out << sorted[i];
  }
  out << ']';
}

static std::unordered_set<u32> label_inputs_or_throw(dfsan_label label) {
  std::unordered_set<u32> inputs;
  serialize(label, inputs, SerializeMode::Format);
  return inputs;
}

static std::vector<size_t>
select_relevant_branch_events(dfsan_label target_label,
                              std::unordered_set<u32> &relevant_inputs,
                              std::vector<std::unordered_set<u32>> &branch_inputs) {
  std::vector<uint8_t> selected(__recorded_branches.size(), 0);
  std::vector<size_t> order;
  bool changed = true;

  branch_inputs.resize(__recorded_branches.size());
  while (changed) {
    changed = false;
    for (size_t i = 0; i < __recorded_branches.size(); i++) {
      if (selected[i] || __recorded_branches[i].label == target_label) {
        continue;
      }
      if (branch_inputs[i].empty()) {
        branch_inputs[i] = label_inputs_or_throw(__recorded_branches[i].label);
      }
      if (!inputs_overlap(relevant_inputs, branch_inputs[i])) {
        continue;
      }

      selected[i] = 1;
      order.push_back(i);
      for (auto input : branch_inputs[i]) {
        if (relevant_inputs.insert(input).second) {
          changed = true;
        }
      }
    }
  }
  std::sort(order.begin(), order.end());
  return order;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_export_value_solver(dfsan_label label, char *json_out,
                          uptr json_capacity, uptr *json_len,
                          char *error, uptr error_capacity) {
  if (json_len != nullptr) {
    *json_len = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }
  if (label == 0) {
    copy_solve_error("label is zero", error, error_capacity);
    return -1;
  }

  try {
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    begin_solve_assumption_collection();

    std::unordered_set<u32> target_inputs;
    begin_load_expr_dep_collection();
    z3::expr target = serialize(label, target_inputs, SerializeMode::Solve);
    expr_set_t target_load_deps = take_load_expr_deps();
    if (!target.is_bv()) {
      take_solve_assumptions();
      copy_solve_error("target label is not a bit-vector", error,
                       error_capacity);
      return -1;
    }

    // Reject unsound value solver exports

    std::unordered_set<u32> relevant_inputs = target_inputs;
    std::vector<std::unordered_set<u32>> branch_inputs;
    std::vector<size_t> selected =
        select_relevant_branch_events(label, relevant_inputs, branch_inputs);

    std::unordered_map<dfsan_label, recorded_branch_t> selected_directions;
    for (auto idx : selected) {
      const auto &event = __recorded_branches[idx];
      auto inserted = selected_directions.emplace(event.label, event);
      if (!inserted.second && inserted.first->second.taken != event.taken) {
        take_solve_assumptions();
        std::ostringstream message;
        message << "conflicting recorded directions for label "
                << hex_u64(event.label) << " at " << hex_u64(event.pc)
                << " (seq " << inserted.first->second.seq << " and "
                << event.seq << ')';
        copy_solve_error(message.str().c_str(), error, error_capacity);
        return -1;
      }
    }


    expr_set_t added;
    for (auto &expr : target_load_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }

    for (auto idx : selected) {
      const auto &event = __recorded_branches[idx];
      std::unordered_set<u32> deps;
      begin_load_expr_dep_collection();
      z3::expr cond = serialize(event.label, deps, SerializeMode::Solve);
      expr_set_t load_deps = take_load_expr_deps();
      z3::expr assertion = direction_expr(cond, event.taken);
      __z3_solver.add(assertion);
      for (auto &expr : load_deps) {
        if (added.insert(expr).second) {
          __z3_solver.add(expr);
        }
      }
    }

    z3::expr target_sym =
        __z3_context.constant(__z3_context.str_symbol("symfit_target"),
                              target.get_sort());
    __z3_solver.add(target_sym == target);

    z3::check_result raw_result = __z3_solver.check();
    if (raw_result != z3::sat) {
      take_solve_assumptions();
      std::string message =
          raw_result == z3::unsat ? "value-solver path is unsat"
                                  : "value-solver path is unknown";
      copy_solve_error(message.c_str(), error, error_capacity);
      return -1;
    }

    __z3_solver.push();
    for (auto offset : relevant_inputs) {
      auto seed = input_seed.find(offset);
      if (seed == input_seed.end()) {
        __z3_solver.pop();
        take_solve_assumptions();
        std::string message =
            "missing concrete seed for input offset " + std::to_string(offset);
        copy_solve_error(message.c_str(), error, error_capacity);
        return -1;
      }
      std::string name = "symfit_input_" + std::to_string(offset);
      z3::expr input = __z3_context.constant(
          __z3_context.str_symbol(name.c_str()), __z3_context.bv_sort(8));
      __z3_solver.add(input == __z3_context.bv_val(seed->second, 8));
    }
    z3::check_result seed_result = __z3_solver.check();
    __z3_solver.pop();
    if (seed_result != z3::sat) {
      take_solve_assumptions();
      std::string message =
          seed_result == z3::unsat ? "value-solver seed is unsat"
                                   : "value-solver seed is unknown";
      copy_solve_error(message.c_str(), error, error_capacity);
      return -1;
    }

    std::vector<dfsan_solve_assumption> assumptions =
        take_solve_assumptions();
    std::string smt2 = __z3_solver.to_smt2();

    std::ostringstream json;
    json << "{\"export_kind\":\"value_solver_export\",";
    json << "\"complete\":true,";
    json << "\"target\":{\"label\":";
    append_json_string(json, hex_u64(label));
    json << ",\"symbol\":\"symfit_target\",\"size\":"
         << target.get_sort().bv_size() << ",\"input_offsets\":";
    append_input_array(json, target_inputs);
    json << "},\"path\":{\"selection\":\"fixed_point_transitive_input_overlap\",";
    json << "\"recorded_branch_count\":" << __recorded_branches.size() << ',';
    json << "\"constraint_count\":" << selected.size() << ',';
    json << "\"relevant_input_offsets\":";
    append_input_array(json, relevant_inputs);
    json << ",\"constraints\":[";
    for (size_t n = 0; n < selected.size(); n++) {
      const auto &event = __recorded_branches[selected[n]];
      if (n != 0) {
        json << ',';
      }
      json << "{\"seq\":" << event.seq << ",\"pc\":";
      append_json_string(json, hex_u64(event.pc));
      json << ",\"label\":";
      append_json_string(json, hex_u64(event.label));
      json << ",\"taken\":" << (event.taken ? "true" : "false");
      json << ",\"input_offsets\":";
      append_input_array(json, branch_inputs[selected[n]]);
      json << '}';
    }
    json << "]},\"assumptions\":[";
    for (size_t i = 0; i < assumptions.size(); i++) {
      const auto &assumption = assumptions[i];
      if (i != 0) {
        json << ',';
      }
      json << "{\"kind\":\"concretized_symbolic_load\",\"load_label\":";
      append_json_string(json, hex_u64(assumption.load_label));
      json << ",\"addr_label\":";
      append_json_string(json, hex_u64(assumption.addr_label));
      json << ",\"concrete_address\":";
      append_json_string(json, hex_u64(assumption.concrete_addr));
      json << ",\"concrete_value\":";
      append_json_string(json, hex_u64(assumption.concrete_value));
      json << ",\"pc\":";
      append_json_string(json, hex_u64(assumption.pc));
      json << ",\"size\":" << assumption.size << '}';
    }
    json << "],\"smt2\":";
    append_json_string(json, smt2);
    json << '}';

    copy_solve_text(json.str(), json_out, json_capacity, json_len);
    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    take_solve_assumptions();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

// Rebuilds the __z3_solver context for `label` exactly as
// dfsan_solve_path_constraint() does -- root constraint plus every nested
// condition on the path, in the same direction they were actually taken,
// plus their load-expr dependencies -- then renders it as text instead of
// (or in addition to) solving for byte assignments. Two independent
// caller-selectable outputs:
//
//   smt2_out       -- __z3_solver.to_smt2(), the raw constraint set. Valid
//                      whether the result is sat or unsat.
//   evaluated_out   -- one line per assertion, each with its value under the
//                      model substituted in (assertion.to_string() ++
//                      " evaluates to " ++ model.eval(assertion).to_string()).
//                      Only meaningful on sat; left empty (len 0) on unsat,
//                      since there is no model to evaluate against. Skipped
//                      entirely when want_evaluated == 0, so a caller that
//                      only wants the raw SMT2 doesn't pay for the model
//                      walk.
//
// Same two-pass buffer convention as the rest of this file: call once with
// {smt2,evaluated}_out == nullptr and the matching capacity == 0 to learn
// the required lengths via *{smt2,evaluated}_len, allocate, then call again
// to fill. Truncates safely (rather than failing) if a supplied buffer is
// smaller than the current length, since in principle the two calls could
// race a concurrent RPC on the same label -- callers should treat a
// returned *len >= capacity they supplied as "read again, bigger buffer."
//
// Returns: 1 sat (both outputs populated per want_evaluated), 0 unsat
// (smt2_out populated, evaluated_out empty), -1 error, -2 solver returned
// unknown. Matches dfsan_solve_path_constraint()'s return convention.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_get_path_constraint_text(dfsan_label label, u8 desired_taken,
                               u8 want_evaluated,
                               char *smt2_out, uptr smt2_capacity,
                               uptr *smt2_len,
                               char *evaluated_out, uptr evaluated_capacity,
                               uptr *evaluated_len,
                               char *error, uptr error_capacity) {
  if (smt2_len != nullptr) {
    *smt2_len = 0;
  }
  if (evaluated_len != nullptr) {
    *evaluated_len = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }

  if (!dfsan_is_branch_condition_label(label)) {
    copy_solve_error("label is not a branch-condition label", error,
                     error_capacity);
    return -1;
  }

  try {
    expr_set_t added;
    std::vector<dfsan_label> nested_labels;
    std::vector<uint8_t> nested_directions;

    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);

    struct timespec ts_start, ts_step;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    std::unordered_set<u32> root_inputs;
    begin_load_expr_dep_collection();
    z3::expr root = serialize(label, root_inputs, SerializeMode::Solve);
    expr_set_t root_load_deps = take_load_expr_deps();
    __z3_solver.add(direction_expr(root, desired_taken != 0));
    for (auto &expr : root_load_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_step);
    double root_ms = (ts_step.tv_sec - ts_start.tv_sec) * 1000.0 +
                     (ts_step.tv_nsec - ts_start.tv_nsec) / 1e6;
    fprintf(stderr, "[SOLVER-DIAG] label=%u root_serialize=%.1fms "
            "root_inputs=%zu load_deps=%zu\n",
            label, root_ms, root_inputs.size(), root_load_deps.size());

    if (!collect_nested_constraint_labels(label, nested_labels, &nested_directions)) {
      copy_solve_error("label has no recorded branch history", error,
                       error_capacity);
      return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_step);
    double collect_ms = (ts_step.tv_sec - ts_start.tv_sec) * 1000.0 +
                        (ts_step.tv_nsec - ts_start.tv_nsec) / 1e6;
    fprintf(stderr, "[SOLVER-DIAG] label=%u collect_nested=%.1fms "
            "nested_count=%zu\n",
            label, collect_ms, nested_labels.size());

    for (size_t i = 0; i < nested_labels.size() && i < nested_directions.size(); i++) {
      if (nested_labels[i] == label) {
        continue;
      }
      struct timespec ts_nest;
      clock_gettime(CLOCK_MONOTONIC, &ts_nest);

      std::unordered_set<u32> nested_inputs;
      begin_load_expr_dep_collection();
      z3::expr nested = serialize(nested_labels[i], nested_inputs,
                                  SerializeMode::Solve);
      expr_set_t nested_load_deps = take_load_expr_deps();
      z3::expr direction = direction_expr(nested, nested_directions[i] != 0);
      if (added.insert(direction).second) {
        __z3_solver.add(direction);
      }
      for (auto &expr : nested_load_deps) {
        if (added.insert(expr).second) {
          __z3_solver.add(expr);
        }
      }

      struct timespec ts_nest_end;
      clock_gettime(CLOCK_MONOTONIC, &ts_nest_end);
      double nest_ms = (ts_nest_end.tv_sec - ts_nest.tv_sec) * 1000.0 +
                       (ts_nest_end.tv_nsec - ts_nest.tv_nsec) / 1e6;
      if (nest_ms > 100.0) {
        fprintf(stderr, "[SOLVER-DIAG] label=%u nested[%zu]=%u "
                "serialize=%.1fms inputs=%zu load_deps=%zu\n",
                label, i, nested_labels[i], nest_ms,
                nested_inputs.size(), nested_load_deps.size());
      }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_step);
    double nested_ms = (ts_step.tv_sec - ts_start.tv_sec) * 1000.0 +
                       (ts_step.tv_nsec - ts_start.tv_nsec) / 1e6;
    fprintf(stderr, "[SOLVER-DIAG] label=%u all_nested_serialized=%.1fms "
            "total_assertions=%u\n",
            label, nested_ms, __z3_solver.assertions().size());

    z3::check_result result = __z3_solver.check();

    clock_gettime(CLOCK_MONOTONIC, &ts_step);
    double solve_ms = (ts_step.tv_sec - ts_start.tv_sec) * 1000.0 +
                      (ts_step.tv_nsec - ts_start.tv_nsec) / 1e6;
    fprintf(stderr, "[SOLVER-DIAG] label=%u solve=%.1fms result=%s\n",
            label, solve_ms,
            result == z3::sat ? "sat" : result == z3::unsat ? "unsat" : "unknown");

    // Raw SMT2 is available regardless of sat/unsat -- it describes the
    // constraint set itself, not a solution to it.
    copy_solve_text(__z3_solver.to_smt2(), smt2_out, smt2_capacity, smt2_len);

    if (result == z3::unsat) {
      return 0;
    }
    if (result != z3::sat) {
      copy_solve_error("solver returned unknown", error, error_capacity);
      return -2;
    }

    if (want_evaluated != 0) {
      z3::model model = __z3_solver.get_model();
      z3::expr_vector assertions = __z3_solver.assertions();
      std::string evaluated;
      for (unsigned i = 0; i < assertions.size(); i++) {
        evaluated += assertions[i].to_string();
        evaluated += " evaluates to ";
        try {
          evaluated += model.eval(assertions[i], true).to_string();
        } catch (z3::exception &e) {
          evaluated += "[eval error: ";
          evaluated += e.msg();
          evaluated += "]";
        }
        evaluated += "\n";
      }
      copy_solve_text(evaluated, evaluated_out, evaluated_capacity,
                      evaluated_len);
    }

    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

// Feasibility check against the current __z3_solver context (which must already
// hold the path constraints). Uses push/pop so that context is preserved across
// the many queries of a min/max binary search -- unlike the top-level solves,
// which reset() on every call. No input-generation side effect (cf.
// __solve_expr). A solver timeout ("unknown") is raised rather than silently
// treated as infeasible, so a range query fails loud instead of returning a
// wrong capability number.
static bool __query_feasible(z3::expr &e) {
  __z3_solver.push();
  __z3_solver.add(e);
  z3::check_result res = __z3_solver.check();
  __z3_solver.pop();
  if (res == z3::unknown) {
    throw z3::exception("solver returned unknown during range query");
  }
  return res == z3::sat;
}

// Capability range query: the min/max of an arbitrary *value* label (an OOB
// offset, length, or payload byte) subject to the recorded path constraints.
// This is KOOBE's findMinMax primitive (util.cpp:339) ported onto SymSan's
// serialize(): set up the path-constraint context once (same slicing as
// __solve_gep), then binary-search value <= K with push/pop. Unlike
// dfsan_solve_path_constraint, it deliberately does NOT require a
// branch-condition label -- ranging a value expression is exactly what that
// gate forbids. Unsigned semantics. lo_bound/hi_bound bound the search window
// (hi_bound == 0 means "up to the value's full bit-width max"). `base` is
// subtracted from the reported min/max so a caller can get reach directly
// (e.g. OOB offset relative to the object base); base must be <= the true min,
// or the unsigned subtraction underflows. Returns 1 on success, negative on
// error.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_query_value_range(dfsan_label label, uint64_t lo_bound, uint64_t hi_bound,
                        uint64_t base, uint64_t *out_seed,
                        uint64_t *out_min, uint64_t *out_max,
                        uptr *assumption_count, char *error,
                        uptr error_capacity) {
  if (assumption_count != nullptr) {
    *assumption_count = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }
  if (label == 0) {
    copy_solve_error("label is zero", error, error_capacity);
    return -1;
  }

  try {
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    begin_solve_assumption_collection();

    struct timespec ts_vr_start, ts_vr_step;
    clock_gettime(CLOCK_MONOTONIC, &ts_vr_start);

    // 1. Serialize the value expression, collecting its input deps and any
    //    symbolic-load equality constraints (load_expr_deps).
    std::unordered_set<u32> inputs;
    begin_load_expr_dep_collection();
    z3::expr val = serialize(label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();

    clock_gettime(CLOCK_MONOTONIC, &ts_vr_step);
    double vr_ser_ms = (ts_vr_step.tv_sec - ts_vr_start.tv_sec) * 1000.0 +
                       (ts_vr_step.tv_nsec - ts_vr_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVRANGE-DIAG] label=%u serialize=%.1fms "
            "inputs=%zu load_deps=%zu\n",
            label, vr_ser_ms, inputs.size(), load_expr_deps.size());

    if (!val.is_bv()) {
      take_solve_assumptions();
      copy_solve_error("value label is not a bit-vector", error,
                       error_capacity);
      return -1;
    }
    unsigned width = val.get_sort().bv_size();
    if (width > 64) {
      take_solve_assumptions();
      copy_solve_error("value wider than 64 bits is unsupported", error,
                       error_capacity);
      return -1;
    }

    expr_set_t added;
    size_t vr_path_asserted = 0;
    if (__value_query_relaxation_profile <= 1) {
      vr_path_asserted = assert_recorded_path_constraints(label, added, false,
                                       __value_query_relaxation_profile == 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_vr_step);
    double vr_path_ms = (ts_vr_step.tv_sec - ts_vr_start.tv_sec) * 1000.0 +
                        (ts_vr_step.tv_nsec - ts_vr_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVRANGE-DIAG] label=%u path_constraints=%.1fms "
            "asserted=%zu added_set=%zu relaxation=%u\n",
            label, vr_path_ms, vr_path_asserted, added.size(),
            __value_query_relaxation_profile);

    if (__value_query_relaxation_profile <= 2) {
      for (auto &e : load_expr_deps) {
        if (added.insert(e).second) {
          __z3_solver.add(e);
        }
      }
    }

    // 3. Anchor on a concrete model of the constrained value (KOOBE getValue).
    fprintf(stderr, "[QVRANGE-DIAG] label=%u assertions=%u calling anchor check()\n",
            label, __z3_solver.assertions().size());

    if (__z3_solver.check() != z3::sat) {
      take_solve_assumptions();
      copy_solve_error("path constraints are unsatisfiable", error,
                       error_capacity);
      return -3;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_vr_step);
    double vr_anchor_ms = (ts_vr_step.tv_sec - ts_vr_start.tv_sec) * 1000.0 +
                          (ts_vr_step.tv_nsec - ts_vr_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVRANGE-DIAG] label=%u anchor_check=%.1fms\n",
            label, vr_anchor_ms);
    z3::expr v64 = (width < 64) ? z3::zext(val, 64 - width) : val;
    z3::model model = __z3_solver.get_model();
    z3::expr cexpr = model.eval(v64, true);
    uint64_t concrete = 0;
    Z3_get_numeral_uint64(cexpr.ctx(), cexpr, &concrete);

    uint64_t width_max = (width >= 64) ? UINT64_MAX : ((1ULL << width) - 1ULL);
    if ((hi_bound != 0 && lo_bound > hi_bound) || concrete < lo_bound ||
        (hi_bound != 0 && concrete > hi_bound)) {
      take_solve_assumptions();
      copy_solve_error("bounded query excludes the seed endpoint", error,
                       error_capacity);
      return -1;
    }

    // 4. Binary search for min: smallest K with (value <= K) still feasible.
    uint64_t lo = lo_bound;
    uint64_t hi = (hi_bound != 0 && hi_bound < concrete) ? hi_bound : concrete;
    while (lo < hi) {
      uint64_t mid = lo + (hi - lo) / 2;
      z3::expr e = z3::ule(v64, __z3_context.bv_val(mid, 64));
      if (__query_feasible(e)) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    uint64_t min_val = lo;

    // 5. Binary search for max: largest K such that (value <= K) is valid
    //    (KOOBE mustBeTrue) == (value > K) infeasible.
    lo = (lo_bound != 0 && lo_bound > concrete) ? lo_bound : concrete;
    hi = (hi_bound != 0 && hi_bound < width_max) ? hi_bound : width_max;
    while (lo < hi) {
      uint64_t mid = lo + (hi - lo) / 2;
      z3::expr e = z3::ugt(v64, __z3_context.bv_val(mid, 64));
      if (!__query_feasible(e)) {
        hi = mid;
      } else {
        lo = mid + 1;
      }
    }
    uint64_t max_val = lo;

    if (min_val < lo_bound || (hi_bound != 0 && max_val > hi_bound) ||
        min_val > max_val || base > min_val) {
      take_solve_assumptions();
      copy_solve_error("range endpoints violate the requested bounds", error,
                       error_capacity);
      return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_vr_step);
    double vr_total_ms = (ts_vr_step.tv_sec - ts_vr_start.tv_sec) * 1000.0 +
                         (ts_vr_step.tv_nsec - ts_vr_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVRANGE-DIAG] label=%u total=%.1fms "
            "min=0x%llx max=0x%llx\n",
            label, vr_total_ms,
            (unsigned long long)(min_val - base),
            (unsigned long long)(max_val - base));

    std::vector<dfsan_solve_assumption> assumptions = take_solve_assumptions();
    if (assumption_count != nullptr) {
      *assumption_count = assumptions.size();
    }
    if (out_min != nullptr) {
      *out_min = min_val - base;
    }
    if (out_seed != nullptr) {
      *out_seed = concrete - base;
    }
    if (out_max != nullptr) {
      *out_max = max_val - base;
    }
    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    take_solve_assumptions();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

// Interval value query: constrain value to [minimum, maximum] (inclusive) and
// solve. When minimum == maximum this is an equality check; when they differ it
// samples one satisfying value from the interval. Returns 1 (sat), 0 (unsat),
// negative on error.
static int
query_value_interval(dfsan_label label, u64 minimum, u64 maximum,
                     u64 *out_value, dfsan_solve_assignment *assignments,
                     uptr assignment_capacity, uptr *assignment_count,
                     uptr *assumption_count, char *error, uptr error_capacity) {
  std::vector<dfsan_solve_assignment> solved_assignments;

  if (assignment_count != nullptr) {
    *assignment_count = 0;
  }
  if (assumption_count != nullptr) {
    *assumption_count = 0;
  }
  if (error != nullptr && error_capacity != 0) {
    error[0] = '\0';
  }
  if (label == 0) {
    copy_solve_error("label is zero", error, error_capacity);
    return -1;
  }

  try {
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    begin_solve_assumption_collection();

    struct timespec ts_eq_start, ts_eq_step;
    clock_gettime(CLOCK_MONOTONIC, &ts_eq_start);

    std::unordered_set<u32> inputs;
    begin_load_expr_dep_collection();
    z3::expr val = serialize(label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();

    clock_gettime(CLOCK_MONOTONIC, &ts_eq_step);
    double eq_ser_ms = (ts_eq_step.tv_sec - ts_eq_start.tv_sec) * 1000.0 +
                       (ts_eq_step.tv_nsec - ts_eq_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVINTERVAL-DIAG] label=%u min=0x%llx max=0x%llx "
            "serialize=%.1fms inputs=%zu load_deps=%zu\n",
            label, (unsigned long long)minimum, (unsigned long long)maximum,
            eq_ser_ms, inputs.size(), load_expr_deps.size());

    if (!val.is_bv()) {
      take_solve_assumptions();
      copy_solve_error("value label is not a bit-vector", error,
                       error_capacity);
      return -1;
    }
    unsigned width = val.get_sort().bv_size();
    if (width > 64) {
      take_solve_assumptions();
      copy_solve_error("value wider than 64 bits is unsupported", error,
                       error_capacity);
      return -1;
    }

    expr_set_t added;
    size_t path_asserted = 0;
    if (__value_query_relaxation_profile <= 1) {
      path_asserted = assert_recorded_path_constraints(label, added, false,
                                       __value_query_relaxation_profile == 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_eq_step);
    double eq_path_ms = (ts_eq_step.tv_sec - ts_eq_start.tv_sec) * 1000.0 +
                        (ts_eq_step.tv_nsec - ts_eq_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVINTERVAL-DIAG] label=%u path_constraints=%.1fms "
            "asserted=%zu added_set=%zu relaxation=%u\n",
            label, eq_path_ms, path_asserted, added.size(),
            __value_query_relaxation_profile);

    if (__value_query_relaxation_profile <= 2) {
      for (auto &e : load_expr_deps) {
        if (added.insert(e).second) {
          __z3_solver.add(e);
        }
      }
    }

    if (minimum > maximum) {
      take_solve_assumptions();
      copy_solve_error("candidate interval has invalid bounds", error,
                       error_capacity);
      return -1;
    }
    // Constrain the value to the requested singleton or sampling interval.
    z3::expr v64 = (width < 64) ? z3::zext(val, 64 - width) : val;
    __z3_solver.add(z3::uge(
        v64, __z3_context.bv_val(static_cast<uint64_t>(minimum), 64)));
    __z3_solver.add(z3::ule(
        v64, __z3_context.bv_val(static_cast<uint64_t>(maximum), 64)));

    fprintf(stderr, "[QVINTERVAL-DIAG] label=%u total_assertions=%u "
            "calling check()\n",
            label, __z3_solver.assertions().size());

    z3::check_result result = __z3_solver.check();

    clock_gettime(CLOCK_MONOTONIC, &ts_eq_step);
    double eq_solve_ms = (ts_eq_step.tv_sec - ts_eq_start.tv_sec) * 1000.0 +
                         (ts_eq_step.tv_nsec - ts_eq_start.tv_nsec) / 1e6;
    fprintf(stderr, "[QVINTERVAL-DIAG] label=%u solve=%.1fms result=%s\n",
            label, eq_solve_ms,
            result == z3::sat ? "sat" : result == z3::unsat ? "unsat" : "unknown");
    std::vector<dfsan_solve_assumption> assumptions = take_solve_assumptions();
    if (assumption_count != nullptr) {
      *assumption_count = assumptions.size();
    }
    if (result == z3::unsat) {
      return 0;
    }
    if (result != z3::sat) {
      copy_solve_error("solver returned unknown", error, error_capacity);
      return -2;
    }

    z3::model model = __z3_solver.get_model();
    if (out_value != nullptr) {
      z3::expr evaluated = model.eval(v64, true);
      uint64_t raw = 0;
      if (!Z3_get_numeral_uint64(evaluated.ctx(), evaluated, &raw)) {
        copy_solve_error("solver model omitted candidate value", error,
                         error_capacity);
        return -1;
      }
      *out_value = raw;
    }
    append_model_assignments(model, solved_assignments);
    if (assignment_count != nullptr) {
      *assignment_count = solved_assignments.size();
    }
    if (assignments != nullptr && assignment_capacity != 0) {
      uptr n = std::min<uptr>(assignment_capacity, solved_assignments.size());
      for (uptr i = 0; i < n; i++) {
        assignments[i] = solved_assignments[i];
      }
    }
    return 1;
  } catch (z3::exception const &e) {
    take_load_expr_deps();
    take_solve_assumptions();
    copy_solve_error(e.msg(), error, error_capacity);
    return -1;
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_query_value_eq(dfsan_label label, uint64_t target,
                     dfsan_solve_assignment *assignments,
                     uptr assignment_capacity, uptr *assignment_count,
                     uptr *assumption_count, char *error, uptr error_capacity) {
  return query_value_interval(label, target, target, nullptr, assignments,
                              assignment_capacity, assignment_count,
                              assumption_count, error, error_capacity);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_query_value_candidate(dfsan_label label, u64 minimum,
                            u64 maximum, u64 *out_value,
                            dfsan_solve_assignment *assignments,
                            uptr assignment_capacity, uptr *assignment_count,
                            uptr *assumption_count, char *error,
                            uptr error_capacity) {
  return query_value_interval(label, minimum, maximum, out_value, assignments,
                              assignment_capacity, assignment_count,
                              assumption_count, error, error_capacity);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_indcall(dfsan_label label) {
  if (label == 0)
    return;

  AOUT("tainted indirect call target: %d\n", label);
}

// assumes under try-catch and the global solver already has context
static void __solve_gep(z3::expr &index, uint64_t lb, uint64_t ub, uint64_t step, void *addr) {

  // enumerate indices
  for (uint64_t i = lb; i < ub; i += step) {
    z3::expr idx = __z3_context.bv_val(i, 64);
    z3::expr e = (index == idx);
    if (__solve_expr(e))
      AOUT("\tindex == %lld feasible\n", i);
  }

  // check feasibility for OOB
  if (flags().trace_bounds) {
    // upper bound
    z3::expr u = __z3_context.bv_val(ub, 64);
    z3::expr e = z3::uge(index, u);
    if (__solve_expr(e))
      AOUT("\tindex >= %lld solved @%p\n", ub, addr);
    else
      AOUT("\tindex >= %lld not possible\n", ub);

    // lower bound
    if (lb == 0) {
      e = (index < 0);
    } else {
      z3::expr l = __z3_context.bv_val(lb, 64);
      e = z3::ult(index, l);
    }
    if (__solve_expr(e))
      AOUT("\tindex < %lld solved @%p\n", lb, addr);
    else
      AOUT("\tindex < %lld not possible\n", lb);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_gep(dfsan_label ptr_label, uint64_t ptr, dfsan_label index_label, int64_t index,
                  uint64_t num_elems, uint64_t elem_size, int64_t current_offset) {
  if (index_label == 0)
    return;

  if (__solved_labels.count(index_label) != 0) 
    return;

  if (__buffers.count(ptr) != 0)
    return;

  AOUT("tainted GEP index: %lld = %d, ne: %lld, es: %lld, offset: %lld\n",
      index, index_label, num_elems, elem_size, current_offset);

  void *addr = __builtin_return_address(0);
  u8 size = get_label_info(index_label)->size;
  try {
    std::unordered_set<dfsan_label> inputs;
    begin_load_expr_dep_collection();
    z3::expr i = serialize(index_label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();
    z3::expr r = __z3_context.bv_val(index, size);
    // set up the global solver with nested constraints
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    expr_set_t added;
    assert_recorded_path_constraints(index_label, added, false, false);
    for (auto &expr : load_expr_deps) {
      if (added.insert(expr).second) {
        __z3_solver.add(expr);
      }
    }
    assert(__z3_solver.check() == z3::sat);

    // first, check against fixed array bounds if available
    z3::expr idx = z3::zext(i, 64 - size);
    if (num_elems > 0) {
      __solve_gep(idx, 0, num_elems, 1, addr);
    } else {
      dfsan_label_info *bounds = get_label_info(ptr_label);
      // if the array is not with fixed size, check bound info
      if (bounds->op == Alloca) {
        z3::expr es = __z3_context.bv_val(elem_size, 64);
        z3::expr co = __z3_context.bv_val(current_offset, 64);
        if (bounds->l2 == 0) {
          // only perform index enumeration and bound check
          // when the size of the buffer is fixed
          z3::expr p = __z3_context.bv_val(ptr, 64);
          z3::expr np = idx * es + co + p;
          __solve_gep(np, (uint64_t)bounds->op1.i, (uint64_t)bounds->op2.i, elem_size, addr);
        } else {
          // if the buffer size is input-dependent (not fixed)
          // check if over flow is possible
          std::unordered_set<dfsan_label> dummy;
          z3::expr bs = serialize(bounds->l2, dummy, SerializeMode::Solve); // size label
          if (bounds->l1) {
            dummy.clear();
            z3::expr be = serialize(bounds->l1, dummy, SerializeMode::Solve); // elements label
            bs = bs * be;
          }
          z3::expr e = z3::ugt(idx * es * co, bs);
          if (__solve_expr(e))
            AOUT("index >= buffer size feasible @%p\n", addr);
        }
      }
    }

    // always preserve
    for (auto off : inputs) {
      auto c = get_branch_dep(off);
      if (c == nullptr) {
        c = new branch_dep_t();
        set_branch_dep(off, c);
      }
      if (c == nullptr) {
        Report("WARNING: out of memory\n");
      } else {
        c->input_deps.insert(inputs.begin(), inputs.end());
        c->expr_deps.insert(i == r);
        c->expr_deps.insert(load_expr_deps.begin(), load_expr_deps.end());
      }
    }

    // mark as visited
    __solved_labels.insert(index_label);
  } catch (z3::exception e) {
    Report("WARNING: index solving error: %s @%p\n", e.msg(), __builtin_return_address(0));
  }

  __buffers.insert(ptr);

}

static void __add_constraints(dfsan_label label) {
  if (label == 0)
    return;

  if (__solved_labels.count(label) != 0)
    return;

  try {
    std::unordered_set<dfsan_label> inputs;
    begin_load_expr_dep_collection();
    z3::expr cond = serialize(label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();
    for (auto off : inputs) {
      auto c = get_branch_dep(off);
      if (c == nullptr) {
        c = new branch_dep_t();
        set_branch_dep(off, c);
      }
      if (c == nullptr) {
        Report("WARNING: out of memory\n");
      } else {
        c->input_deps.insert(inputs.begin(), inputs.end());
        c->expr_deps.insert(cond);
        c->expr_deps.insert(load_expr_deps.begin(), load_expr_deps.end());
      }
    }
  } catch (z3::exception e) {
    Report("WARNING: adding constraints error: %s\n", e.msg());
  }

  __solved_labels.insert(label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_offset(dfsan_label offset_label, int64_t offset, unsigned size) {
  dfsan_label_info *info = get_label_info(offset_label);
  dfsan_label sc = dfsan_union(offset_label, 0, (bveq << 8) | ICmp, size, 0, offset, info->pc);
  __add_constraints(sc);
}

extern "C" void InitializeSolver() {
  __output_dir = flags().output_dir;
  __instance_id = flags().instance_id;
  __session_id = flags().session_id;
}
