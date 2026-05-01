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
static std::unordered_map<dfsan_label, u64> __branch_order;
static u64 __next_branch_order = 1;
typedef std::pair<u32, void*> trace_context;
struct context_hash {
  std::size_t operator()(const trace_context &context) const {
    return std::hash<u32>{}(context.first) ^ std::hash<void*>{}(context.second);
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
static std::vector<branch_dep_t*> __branch_deps;

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
  std::unordered_set<u32> inputs;

  if (!dfsan_is_branch_condition_label(label)) {
    return false;
  }

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &) {
    return false;
  }

  for (auto off : inputs) {
    auto deps = get_branch_dep(off);
    if (deps == nullptr) {
      continue;
    }
    auto it = deps->cond_directions.find(label);
    if (it != deps->cond_directions.end()) {
      if (taken != nullptr) {
        *taken = it->second;
      }
      return true;
    }
  }

  return false;
}

static void record_branch_inputs(dfsan_label label, bool taken) {
  std::unordered_set<u32> inputs;

  if (!dfsan_is_branch_condition_label(label)) {
    return;
  }

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &) {
    return;
  }

  if (__branch_order.count(label) == 0) {
    __branch_order[label] = __next_branch_order++;
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
                                             std::vector<uint8_t> *directions = nullptr) {
  std::unordered_set<u32> inputs;
  std::vector<dfsan_label> ordered;
  std::unordered_set<dfsan_label> seen;
  std::vector<dfsan_label> worklist;
  u64 root_order = UINT64_MAX;

  if (!dfsan_is_branch_condition_label(label)) {
    return false;
  }
  auto root_order_it = __branch_order.find(label);
  if (root_order_it != __branch_order.end()) {
    root_order = root_order_it->second;
  }

  try {
    serialize(label, inputs, SerializeMode::Format);
  } catch (z3::exception const &) {
    return false;
  }

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
    for (const auto &entry : deps->cond_directions) {
      dfsan_label cond_label = entry.first;
      auto order_it = __branch_order.find(cond_label);
      if (order_it == __branch_order.end() || order_it->second >= root_order) {
        continue;
      }
      if (cond_label != label && seen.insert(cond_label).second) {
        ordered.push_back(cond_label);
      }
    }
  }

  std::sort(ordered.begin(), ordered.end(),
            [](dfsan_label lhs, dfsan_label rhs) {
              return __branch_order[lhs] < __branch_order[rhs];
            });
  if (directions != nullptr) {
    directions->clear();
    directions->reserve(ordered.size());
    for (auto cond_label : ordered) {
      bool taken = false;
      if (!get_branch_direction(cond_label, &taken)) {
        taken = false;
      }
      directions->push_back(taken ? 1 : 0);
    }
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
    // caching is not super helpful
    return __z3_context.constant(symbol, sort);
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
      u64 offset = get_label_info(info->l1)->op1.i;
      z3::symbol symbol = __z3_context.int_symbol(offset);
      z3::sort sort = __z3_context.bv_sort(8);
      out = __z3_context.constant(symbol, sort);
      deps.insert(offset);
      for (u32 i = 1; i < info->l2; i++) {
        symbol = __z3_context.int_symbol(offset + i);
        out = z3::concat(__z3_context.constant(symbol, sort), out);
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
    if (info->l2 == 0 || info->size != 1) {
      throw z3::exception("invalid Not operation");
    }
    z3::expr e = serialize(info->l2, deps, mode);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    if (!e.is_bool()) {
      throw z3::exception("Only LNot should be recorded");
    }
    return cache_expr(label, !e, deps, mode);
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
    case Concat:  return cache_expr(label, z3::concat(op2, op1), deps, mode); // little endian
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

  bool pushed = false;
  try {
    std::unordered_set<dfsan_label> inputs;
    begin_load_expr_dep_collection();
    z3::expr cond = serialize(label, inputs, SerializeMode::Solve);
    expr_set_t load_expr_deps = take_load_expr_deps();

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
    // 2. add constraints
    expr_set_t added;
    for (auto off : inputs) {
      //AOUT("adding offset %d\n", off);
      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto &expr : deps->expr_deps) {
          if (added.insert(expr).second) {
            //AOUT("adding expr: %s\n", expr.to_string().c_str());
            __z3_solver.add(expr);
          }
        }
      }
    }
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
                  u64 c1, u64 c2, u32 cid) {
  if ((op1 == 0 && op2 == 0))
    return 0;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, addr});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, addr}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return 0;
  }

  AOUT("recording cmp: %u %u %u %d %llu %llu 0x%x @%p\n",
       op1, op2, size, predicate, c1, c2, cid, addr);

  dfsan_label temp = dfsan_union(op1, op2, (predicate << 8) | ICmp, size, c1, c2, cid);
  record_branch_inputs(temp, eval_cmp_taken(predicate, size, c1, c2));
  return temp;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__taint_trace_cond(dfsan_label label, u8 r, u32 cid) {
  if (label == 0)
    return;

  void *addr = __builtin_return_address(0);
  auto itr = __branches.find({__taint_trace_callstack, addr});
  if (itr == __branches.end()) {
    itr = __branches.insert({{__taint_trace_callstack, addr}, 1}).first;
  } else if (itr->second < MAX_BRANCH_COUNT) {
    itr->second += 1;
  } else {
    return;
  }

  AOUT("recording cond: %u %u 0x%x 0x%x %p %u\n",
       label, r, __taint_trace_callstack, cid, addr, itr->second);

  record_branch_inputs(label, r != 0);
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

    if (name.kind() != Z3_INT_SYMBOL) {
      continue;
    }

    z3::expr value = model.get_const_interp(decl);
    uint64_t raw = 0;
    if (!Z3_get_numeral_uint64(value.ctx(), value, &raw)) {
      continue;
    }

    dfsan_solve_assignment assignment = {};
    assignment.offset = static_cast<uint64_t>(name.to_int());
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

    // set up the global solver with nested constraints
    __z3_solver.reset();
    __z3_solver.set("timeout", 5000U);
    expr_set_t added;
    for (auto off : inputs) {
      auto deps = get_branch_dep(off);
      if (deps != nullptr) {
        for (auto &expr : deps->expr_deps) {
          if (added.insert(expr).second) {
            __z3_solver.add(expr);
          }
        }
      }
    }
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
