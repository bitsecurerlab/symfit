#include "defs.h"
#include "debug.h"
#include "version.h"

#include "dfsan/dfsan.h"

#include <z3++.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "pc_tracker.h" // Defined for JSON PC constraint logger

// Defines for MCP integration
#include <mutex>
#include <thread>
#include <sstream>
#include <iomanip>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace __dfsan;

#define OPTIMISTIC 1

#undef AOUT
# define AOUT(...)                                      \
  do {                                                  \
    printf(__VA_ARGS__);                                \
  } while(false)

bool print_debug = true;
static dfsan_label_info *__dfsan_label_info;
static char *input_buf;
static size_t input_size;

// Support functions/structures for MCP integration follow

static std::unordered_map<uint64_t, unsigned char> pc_verdict;
static std::mutex pc_verdict_mutex;
static uint32_t g_max_label_seen = 0;

extern std::atomic<uint32_t> __dfsan_last_label; // For label count retrieval
// Do we need these #defines? These should be ...optional

#define VERDICT_NONE 0
#define VERDICT_BLACKLIST 1
#define VERDICT_PENDING 2

// Recent constraint circular buffer
//#define RECENT_WINDOW 10;
static const unsigned char RECENT_WINDOW = 10; // Is that enough types in a single definition?
static std::array<std::pair<uint64_t, std::string>, RECENT_WINDOW> recent_constraints;
static size_t recent_head  = 0;
static size_t recent_count = 0;

struct TriggerPacket {
    uint64_t    pc;
    uint32_t    label;
    uint32_t    label_count;
    std::vector<std::pair<uint64_t, std::string>> recent_constraints;
    std::string smt2;           // full SMT2, may be large
    std::string smt2_truncated; // last N assertions only
};

static std::string json_escape(const std::string &s) {
    std::string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

static std::string serialize_trigger_packet(const TriggerPacket &packet) {
    std::ostringstream j;

    j << "{\n";
    j << "  \"trigger\": \"unsat_constraint\",\n";
    j << "  \"pc\": \"0x" << std::hex << packet.pc << "\",\n";
    j << "  \"label\": " << std::dec << packet.label << ",\n";
    j << "  \"label_count\": " << packet.label_count << ",\n";

    // Recent constraints array
    j << "  \"recent_constraints\": [\n";
    for (size_t i = 0; i < packet.recent_constraints.size(); i++) {
        const auto &entry = packet.recent_constraints[i];
        j << "    {\n";
        j << "      \"pc\": \"0x" << std::hex << entry.first << "\",\n";
        j << "      \"constraint\": \""
          << json_escape(entry.second) << "\"\n";
        j << "    }";
        if (i + 1 < packet.recent_constraints.size()) j << ",";
        j << "\n";
    }
    j << "  ],\n";

    j << "  \"smt2\": \"" << json_escape(packet.smt2) << "\",\n";
    j << "  \"smt2_truncated\": \""
      << json_escape(packet.smt2_truncated) << "\"\n";
    j << "}\n";

    return j.str();
}

void send_task(int ip_addr, unsigned short port, std::string message) {
    std::vector<char> buf(message.size() + 4);
    uint32_t net_len = htonl(message.size());
    memcpy(buf.data(), &net_len, 4);
    memcpy(buf.data() + 4, message.c_str(), message.size());

    int socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = ip_addr;
    connect(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr));
    send(socket_desc, buf.data(), buf.size(), 0);
    close(socket_desc);
}

std::string truncate_smt2(const std::string &smt2, size_t keep_last_n) {
    // Find where assertions start
    size_t first_assert = smt2.find("(assert");
    if (first_assert == std::string::npos)
        return smt2;  // no assertions, return as-is

    std::string header = smt2.substr(0, first_assert);

    // Collect positions of all assertions
    std::vector<size_t> assert_positions;
    size_t pos = first_assert;
    while (pos != std::string::npos) {
        assert_positions.push_back(pos);
        pos = smt2.find("(assert", pos + 1);
    }

    // If we have fewer than keep_last_n, return full string
    if (assert_positions.size() <= keep_last_n)
        return smt2;

    // Take from the Nth-from-last assertion onward
    size_t start = assert_positions[assert_positions.size() - keep_last_n];
    return header + smt2.substr(start);
}

void apply_verdict(uint64_t pc, unsigned char flags) {
    std::lock_guard<std::mutex> lock(pc_verdict_mutex);
    if (flags == VERDICT_NONE) {
        pc_verdict.erase(pc);
    } else {
        pc_verdict[pc] = flags;
    }
}

/* Definitions for JSON PC constraint logger */

// Global PC tracker
static PCTracker* g_pc_tracker = nullptr;

/* End definitions for JSON PC constraint logger */

dfsan_label_info* __dfsan::get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

// Helper: Check if a number is a "suspicious" slab size
bool is_slab_size(uint64_t val) {
    if (val == 0) return false;
    // Power of 2 check (8, 16, 32, 64...)
    if ((val & (val - 1)) == 0) return true;
    // Check for common non-power-of-2 slabs (e.g., 96, 192) which are 1.5x a power of 2
    if ((val % 8) == 0 && val < 4096) return true;
    return false;
}

// The core detector
bool is_allocator_constraint(z3::expr e) {
    if (!e.is_app()) return false;

    Z3_decl_kind kind = e.decl().decl_kind();

    // 1. Unwrap Boolean wrappers (NOT, AND)
    if (kind == Z3_OP_NOT) {
        return is_allocator_constraint(e.arg(0));
    }
    if (kind == Z3_OP_AND || kind == Z3_OP_OR) {
        for (unsigned i = 0; i < e.num_args(); i++) {
            if (is_allocator_constraint(e.arg(i))) return true;
        }
        return false;
    }

    // 2. Look for Comparisons
    bool is_comparison = (kind == Z3_OP_ULEQ || kind == Z3_OP_ULT ||
                          kind == Z3_OP_UGEQ || kind == Z3_OP_UGT ||
                          kind == Z3_OP_SLEQ || kind == Z3_OP_SLT ||
                          kind == Z3_OP_EQ);

    if (!is_comparison) return false;

    z3::expr lhs = e.arg(0);
    z3::expr rhs = e.arg(1);

    // 3. Normalize: Ensure Constant is on the RHS
    if (lhs.is_numeral() && !rhs.is_numeral()) {
        z3::expr temp = lhs; lhs = rhs; rhs = temp;
    }

    // 4. Check the RHS (The Limit)
    uint64_t limit_val = 0;
    if (rhs.is_numeral()) {
        // FIX: Call takes no arguments, returns value
        limit_val = rhs.get_numeral_uint64();

        if (!is_slab_size(limit_val)) {
            return false;
        }
    } else {
        return false;
    }

    // 5. Check the LHS (The Size Calculation)
    if (!lhs.is_app()) return false;

    // Check for Multiplication (size * element_size)
    if (lhs.decl().decl_kind() == Z3_OP_BMUL) {
        z3::expr mul_arg1 = lhs.arg(0);
        z3::expr mul_arg2 = lhs.arg(1);

        uint64_t mul_const = 0;
        bool found_mul_const = false;

        // FIX: Check args and get value directly
        if (mul_arg1.is_numeral()) {
            mul_const = mul_arg1.get_numeral_uint64();
            found_mul_const = true;
        } else if (mul_arg2.is_numeral()) {
            mul_const = mul_arg2.get_numeral_uint64();
            found_mul_const = true;
        }

        if (found_mul_const) {
            // Heuristic match found: (Variable * Const) compared to SlabSize
            return true;
        }
    }

    return false;
}

// End selective constraint dropping helper code

/* Unordered set for internal map */
// This is necessary for applications where AFL trace maps are inappropriate,
// such as incorporating the solver with a kernel.

static std::unordered_set<uint64_t> solved_branches;

// for output
static const char* __output_dir = ".";
static u32 __instance_id = 0;
static u32 __session_id = 0;
static u32 __current_index = 0;
static z3::context __z3_context;
static z3::solver __z3_solver(__z3_context, "QF_BV");

// caches
static std::unordered_map<dfsan_label, u32> tsize_cache;
static std::unordered_map<dfsan_label, std::unordered_set<u32> > deps_cache;
static std::unordered_map<dfsan_label, z3::expr> expr_cache;
static std::unordered_map<dfsan_label, memcmp_msg*> memcmp_cache;

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

struct labeltuple_hash {
  std::size_t operator()(const std::tuple<uint32_t, uint32_t> &x) const {
    return std::get<0>(x) ^ std::get<1>(x);
  }
};
typedef std::unordered_set<std::tuple<uint32_t, uint32_t>, labeltuple_hash> labeltuple_set_t;

typedef std::unordered_set<z3::expr, expr_hash, expr_equal> expr_set_t;

typedef struct {
  expr_set_t expr_deps;
  // labeltuple_set_t label_tuples;
  std::unordered_set<dfsan_label> input_deps;
} branch_dep_t;
static std::vector<branch_dep_t*> __branch_deps;

labeltuple_set_t added_label;

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

static z3::expr read_concrete(dfsan_label label, u16 size) {
  auto itr = memcmp_cache.find(label);
  if (itr == memcmp_cache.end()) {
    throw z3::exception("cannot find memcmp content");
  }

  memcmp_msg *mmsg = itr->second;
  z3::expr val = __z3_context.bv_val(mmsg->content[0], 8);
  for (u8 i = 1; i < size; i++) {
    val = z3::concat(__z3_context.bv_val(mmsg->content[i], 8), val);
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
      AOUT("FATAL: unsupported predicate: %u\n", predicate);
      throw z3::exception("unsupported predicate");
      break;
  }
  // should never reach here
  Die();
}

static inline z3::expr cache_expr(dfsan_label label, z3::expr const &e, std::unordered_set<u32> &deps) {
  expr_cache.insert({label,e});
  deps_cache.insert({label,deps});
  return e;
}

static inline z3::expr cache_expr_only(dfsan_label label, z3::expr const &e) {
  expr_cache.insert({label,e});
  return e;
}

static z3::expr serialize(dfsan_label label, std::unordered_set<u32> &deps) {
  if (label < CONST_OFFSET || label == kInitializingLabel) {
    AOUT("WARNING: invalid label: %d\n", label);
    throw z3::exception("invalid label");
  }

  dfsan_label_info *info = get_label_info(label);
  AOUT("%u = (l1:%u, l2:%u, op:%u, size:%u, op1:%llu, op2:%llu)\n",
       label, info->l1, info->l2, info->op, info->size, info->op1.i, info->op2.i);

  auto expr_itr = expr_cache.find(label);
  if (expr_itr != expr_cache.end()) {
    auto deps_itr = deps_cache.find(label);
    deps.insert(deps_itr->second.begin(), deps_itr->second.end());
    return expr_itr->second;
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
    u64 offset = get_label_info(info->l1)->op1.i;
    z3::symbol symbol = __z3_context.int_symbol(offset);
    z3::sort sort = __z3_context.bv_sort(8);
    z3::expr out = __z3_context.constant(symbol, sort);
    deps.insert(offset);
    for (u32 i = 1; i < info->l2; i++) {
      symbol = __z3_context.int_symbol(offset + i);
      out = z3::concat(__z3_context.constant(symbol, sort), out);
      deps.insert(offset + i);
    }
    tsize_cache[label] = 1; // lazy init
    return cache_expr(label, out, deps);
  } else if (info->op == ZExt) {
    z3::expr base = serialize(info->l1, deps);
    if (base.is_bool()) // dirty hack since llvm lacks bool
      base = z3::ite(base, __z3_context.bv_val(1, 1),
                           __z3_context.bv_val(0, 1));
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::zext(base, info->size - base_size), deps);
  } else if (info->op == SExt) {
    z3::expr base = serialize(info->l1, deps);
    u32 base_size = base.get_sort().bv_size();
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, z3::sext(base, info->size - base_size), deps);
  } else if (info->op == Trunc) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract(info->size - 1, 0), deps);
  } else if (info->op == Extract) {
    z3::expr base = serialize(info->l1, deps);
    tsize_cache[label] = tsize_cache[info->l1]; // lazy init
    return cache_expr(label, base.extract((info->op2.i + info->size) - 1, info->op2.i), deps);
  } else if (info->op == Not) {
    if (info->l2 == 0 || info->size != 1) {
      throw z3::exception("invalid Not operation");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    if (!e.is_bool()) {
      throw z3::exception("Only LNot should be recorded");
    }
    return cache_expr(label, !e, deps);
  } else if (info->op == Neg) {
    if (info->l2 == 0) {
      throw z3::exception("invalid Neg predicate");
    }
    z3::expr e = serialize(info->l2, deps);
    tsize_cache[label] = tsize_cache[info->l2]; // lazy init
    return cache_expr(label, -e, deps);
  } else if (info->op == Ite) {
    z3::expr cond = serialize(info->l1, deps);
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
                      deps);
  }
  // higher-order
  else if (info->op == fmemcmp) {
    z3::expr op1 = (info->l1 >= CONST_OFFSET) ? serialize(info->l1, deps) :
                   read_concrete(label, info->size); // memcmp size in bytes
    if (info->l2 < CONST_OFFSET) {
      throw z3::exception("invalid memcmp operand2");
    }
    z3::expr op2 = serialize(info->l2, deps);
    tsize_cache[label] = 1; // lazy init
    z3::expr e = z3::ite(op1 == op2, __z3_context.bv_val(0, 32),
                                     __z3_context.bv_val(1, 32));
    return cache_expr(label, e, deps);
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
    op1 = serialize(info->l1, deps).simplify();
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
    op2 = serialize(info->l2, deps2).simplify();
    deps.insert(deps2.begin(),deps2.end());
  } else if (info->size == 1) {
    op2 = __z3_context.bool_val(info->op2.i == 1);
  }
  // update tree_size
  tsize_cache[label] = tsize_cache[info->l1] + tsize_cache[info->l2];

  switch((info->op & 0xff)) {
    // llvm doesn't distinguish between logical and bitwise and/or/xor
    case And:     return cache_expr(label, info->size != 1 ? (op1 & op2) : (op1 && op2), deps);
    case Or:      return cache_expr(label, info->size != 1 ? (op1 | op2) : (op1 || op2), deps);
    case Xor:     return cache_expr(label, op1 ^ op2, deps);
    case Shl:     return cache_expr(label, z3::shl(op1, op2), deps);
    case LShr:    return cache_expr(label, z3::lshr(op1, op2), deps);
    case AShr:    return cache_expr(label, z3::ashr(op1, op2), deps);
    case Add:     return cache_expr(label, op1 + op2, deps);
    case Sub:     return cache_expr(label, op1 - op2, deps);
    case Mul:     return cache_expr(label, op1 * op2, deps);
    case UDiv:    return cache_expr(label, z3::udiv(op1, op2), deps);
    case SDiv:    return cache_expr(label, op1 / op2, deps);
    case URem:    return cache_expr(label, z3::urem(op1, op2), deps);
    case SRem:    return cache_expr(label, z3::srem(op1, op2), deps);
    // relational
    case ICmp:    return cache_expr(label, get_cmd(op1, op2, info->op >> 8), deps);
    // concat
    case Concat:  return cache_expr(label, z3::concat(op2, op1), deps); // little endian
    default:
      AOUT("FATAL: unsupported op: %u\n", info->op);
      throw z3::exception("unsupported operator");
      break;
  }
  // should never reach here
  Die();
}

static void generate_input(z3::model &m) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "%s/id-%d-%d-%d", __output_dir,
           __instance_id, __session_id, __current_index++);
  int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    throw z3::exception("failed to open new input file for write");
  }

  if (write(fd, input_buf, input_size) == -1) {
    throw z3::exception("failed to copy original input\n");
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
      AOUT("offset %d = %x\n", offset, value);
      lseek(fd, offset, SEEK_SET);
      write(fd, &value, sizeof(value));
    } else { // string symbol
      if (!name.str().compare("fsize")) {
        off_t size = (off_t)e.get_numeral_int64();
        if (size > input_size) { // grow
          lseek(fd, size, SEEK_SET);
          u8 dummy = 0;
          write(fd, &dummy, sizeof(dummy));
        } else {
          AOUT("truncate file to %ld\n", size);
          ftruncate(fd, size);
        }
        // don't remember size constraints
        throw z3::exception("skip fsize constraints");
      }
    }
  }

  close(fd);
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

int sym_count = 0;

static void __solve_cond(dfsan_label label, u8 r, bool add_nested, u64 addr) {

  // BUGFIX: Don't try to solve for label 0

  if (label == 0) {
      printf("DEBUG: Label is 0! Let's not solve for this.\n");
      return;
  }
  if (label > g_max_label_seen) g_max_label_seen = label;
  std::lock_guard<std::mutex> lock(pc_verdict_mutex);
  if (pc_verdict.count(addr)) {
    // These've been commented out for future expansion; for the moment, if there's a map entry, we skip.
    /*
    unsigned char verdict = 0;
    verdict = pc_verdict[addr];
    if ((verdict & 1) || (verdict & 2)) { // If verdict is blacklisted or pending
    */
      if (print_debug) {
        AOUT("[FILTERED PC] Skipping function at 0x%llx\n", addr);
      }
    return;
    /*
    }
    */
  }

  z3::expr result = __z3_context.bool_val(r != 0);

  bool pushed = false;
  try {
    std::unordered_set<dfsan_label> inputs;
    z3::expr cond = serialize(label, inputs);

    // ===== NEW: Filter concrete/trivial branches =====
    /*
    if (cond.is_true() || cond.is_false()) {
        if (print_debug) {
            AOUT("[CONCRETE] Branch at PC 0x%llx simplified to: %s\n",
                 addr, cond.is_true() ? "true" : "false");
        }
        return;  // Don't add constraint
    }
    */
    if (cond.is_true()) {
        if (print_debug) {
            AOUT("[CONCRETE] Branch at PC 0x%llx always true, skipping\n", addr);
        }
        return;
    }

    if (cond.is_false()) {
        if (print_debug) {
            AOUT("[CONCRETE] Branch at PC 0x%llx always false (contradiction)\n", addr);
        }
        // Fire a telemetry event — this is a genuine unsatisfiable constraint
            char jsonbuffer[512];
            snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
                "{"
                "\"source\": \"fgtest\","
                "\"trigger\": \"unsat_constraint\","
                "\"pc\": \"0x%llx\","
                "\"reason\": \"expression_simplified_to_false\","
                "\"constraint\": \"%s\""
                "}",
                addr, "false");
            //telemetry_send(jsonbuffer);
            //send_task(inet_addr("127.0.0.1"), 23100, std::string(jsonbuffer));
            std::thread t1(send_task, inet_addr("127.0.0.1"), 23100, std::string(jsonbuffer));
            t1.detach();
        return;
    }
    // ================================================

    //AOUT("\n%s\n", __z3_solver.to_smt2().c_str());
    AOUT("sym branch: 0x%llx constraint: %s, add_nested: %d\n", addr, cond.to_string().c_str(), add_nested);
    if(is_allocator_constraint(cond)) {
        printf("ALLOCATOR_DEBUG: This looks like an allocator constraint! Returning...\n");

        std::string raw_constraint = cond.to_string();
        std::string escaped_constraint;
        escaped_constraint.reserve(raw_constraint.size());
        for (char c : raw_constraint) {
            switch (c) {
                case '"':  escaped_constraint += "\\\""; break;
                case '\\': escaped_constraint += "\\\\"; break;
                case '\n': escaped_constraint += "\\n";  break;
                case '\r': escaped_constraint += "\\r";  break;
                case '\t': escaped_constraint += "\\t";  break;
                default:   escaped_constraint += c;      break;
            }
        }

        char jsonbuffer[768];
        snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
            "{"
            "\"source\": \"fgtest\","
            "\"trigger\": \"filtered_constraint\","
            "\"pc\": \"0x%llx\","
            "\"reason\": \"allocator_heuristic\","
            "\"constraint\": \"%s\""
            "}",
            //addr, cond.to_string().c_str());
            addr, escaped_constraint.c_str());
        std::thread t1(send_task, inet_addr("127.0.0.1"), 23100,
                       std::string(jsonbuffer));
        t1.detach();
        return;
    }

    recent_constraints[recent_head] = {addr, cond.to_string()};
    recent_head = (recent_head + 1) % RECENT_WINDOW;
    if (recent_count < RECENT_WINDOW) recent_count++;

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
    
    z3::check_result checked_result = __z3_solver.check();

    if (checked_result == z3::unsat) {
        if (!pc_verdict.count(addr)) {
            TriggerPacket unsat_packet;
            unsat_packet.pc          = addr;
            unsat_packet.label       = label;
            //unsat_packet.label_count = (uint32_t)dfsan_get_label_count();
            unsat_packet.label_count = g_max_label_seen;
            unsat_packet.smt2        = __z3_solver.to_smt2();
            unsat_packet.smt2_truncated = truncate_smt2(unsat_packet.smt2, 15);

            for (size_t i = 0; i < recent_count; i++) {
                size_t idx = (recent_head - recent_count + i + RECENT_WINDOW) % RECENT_WINDOW;
                unsat_packet.recent_constraints.push_back(recent_constraints[idx]);
            }

            std::string json_serialized = serialize_trigger_packet(unsat_packet);

            // Anonymously scoped lock
            {
                std::lock_guard<std::mutex> lock(pc_verdict_mutex);
                pc_verdict[addr] = VERDICT_PENDING;
            }

            std::string payload = json_serialized;
            std::thread t1(send_task, inet_addr("127.0.0.1"), 23100, payload); // TO DO: Don't hardcode this
            t1.detach();
        }
    }
    
    // ==== PC TRACKING WITH MODEL ====
    if (g_pc_tracker && g_pc_tracker->is_tracked(addr)) {
        std::ofstream* log = g_pc_tracker->get_log(addr);

        *log << "--- Constraint at PC 0x" << std::hex << addr << " ---\n";
        *log << "Timestamp: " << std::dec << time(NULL) << "\n";
        *log << "Branch taken: " << (r ? "true" : "false") << "\n";
        *log << "Constraint: " << cond.to_string() << "\n";

        if (checked_result == z3::sat) {
            z3::model mod = __z3_solver.get_model();

            *log << "\n=== CONSTRAINTS WITH VALUES ===\n";
            z3::expr_vector assertions = __z3_solver.assertions();
            for (unsigned i = 0; i < assertions.size(); i++) {
                try {
                    z3::expr evaluated = mod.eval(assertions[i], true);
                    *log << "  " << assertions[i].to_string()
                         << " evaluates to " << evaluated.to_string() << "\n";
                } catch (z3::exception &e) {
                    *log << "  [eval error: " << e.msg() << "]\n";
                }
            }
        } else if (checked_result == z3::unsat) {
            *log << "\n=== PATH IS UNSATISFIABLE ===\n";
        }

        *log << "\nCurrent solver state (SMT2):\n";
        *log << __z3_solver.to_smt2() << "\n";

        log->flush();
    }
    
    if (print_debug) {
        AOUT("\n=== CONSTRAINTS (Original) ===\n");
        AOUT("%s\n", __z3_solver.to_smt2().c_str());

        //z3::check_result checked_result = __z3_solver.check();
        AOUT("\n=== SOLVER RESULT: %s ===\n",
             checked_result == z3::sat ? "SAT" :
             checked_result == z3::unsat ? "UNSAT" : "UNKNOWN");

        if (checked_result == z3::sat) {
            z3::model mod = __z3_solver.get_model();

            AOUT("\n=== SOLUTION (Human-Readable) ===\n");
            // ...
            for (unsigned i = 0; i < mod.size(); i++) {
              z3::func_decl v = mod[i];
              AOUT("  %s = %s\n",
                   v.name().str().c_str(),
                   mod.get_const_interp(v).to_string().c_str());
            }

            AOUT("\n=== CONSTRAINTS WITH VALUES ===\n");
            z3::expr_vector assertions = __z3_solver.assertions();
            for (unsigned i = 0; i < assertions.size(); i++) {
              z3::expr evaluated = mod.eval(assertions[i], true);
              AOUT("  %s evaluates to %s\n",
                   assertions[i].to_string().c_str(),
                   evaluated.to_string().c_str());
            }
        } else if (checked_result == z3::unsat) {
            AOUT("\n=== PATH IS UNSATISFIABLE ===\n");
            AOUT("This branch cannot be taken with the accumulated constraints.\n");

            // Optionally: print unsat core
            //if (print_debug > 1) {
                z3::expr_vector core = __z3_solver.unsat_core();
                AOUT("\n=== UNSAT CORE (%u constraints) ===\n", core.size());
                for (unsigned i = 0; i < core.size(); i++) {
                    AOUT("[%u] %s\n", i, core[i].to_string().c_str());
                }
            //}
        }

        AOUT("====================================\n\n");
    }
    
    // assert(__z3_solver.check() == z3::sat);

    z3::expr e = (cond != result);
    // disable sovling
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
          AOUT("WARNING: out of memory\n");
        } else {
          c->input_deps.insert(inputs.begin(), inputs.end());
          c->expr_deps.insert(cond == result);
        }
      }
    }

  } catch (z3::exception e) {
    AOUT("WARNING: solving error: %s @%p\n", e.msg(), addr);
  }

}

// assumes under try-catch and the global solver already has context
static void __solve_gep(z3::expr &index, uint64_t lb, uint64_t ub, uint64_t step, void *addr) {

  // enumerate indices
  for (uint64_t i = lb; i < ub; i += step) {
    z3::expr idx = __z3_context.bv_val(i, 64);
    z3::expr e = (index == idx);
    if (__solve_expr(e))
      AOUT("\tindex == %ld feasible\n", i);
  }

  // check feasibility for OOB
  // upper bound
  z3::expr u = __z3_context.bv_val(ub, 64);
  z3::expr e = z3::uge(index, u);
  if (__solve_expr(e))
    AOUT("\tindex >= %ld solved @%p\n", ub, addr);
  else
    AOUT("\tindex >= %ld not possible\n", ub);

  // lower bound
  if (lb == 0) {
    e = (index < 0);
  } else {
    z3::expr l = __z3_context.bv_val(lb, 64);
    e = z3::ult(index, l);
  }
  if (__solve_expr(e))
    AOUT("\tindex < %ld solved @%p\n", lb, addr);
  else
    AOUT("\tindex < %ld not possible\n", lb);
}

static void __handle_gep(dfsan_label ptr_label, uptr ptr,
                         dfsan_label index_label, int64_t index,
                         uint64_t num_elems, uint64_t elem_size,
                         int64_t current_offset, void* addr) {

  AOUT("tainted GEP index: %ld = %d, ne: %ld, es: %ld, offset: %ld\n",
      index, index_label, num_elems, elem_size, current_offset);

  u8 size = get_label_info(index_label)->size;
  try {
    std::unordered_set<dfsan_label> inputs;
    z3::expr i = serialize(index_label, inputs);
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
          z3::expr bs = serialize(bounds->l2, dummy); // size label
          if (bounds->l1) {
            dummy.clear();
            z3::expr be = serialize(bounds->l1, dummy); // elements label
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
        AOUT("WARNING: out of memory\n");
      } else {
        c->input_deps.insert(inputs.begin(), inputs.end());
        c->expr_deps.insert(i == r);
      }
    }

  } catch (z3::exception e) {
    AOUT("WARNING: index solving error: %s @%p\n", e.msg(), __builtin_return_address(0));
  }

}

int main(int argc, char* const argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: %s target | Please be sure to define SYMCC_INPUT_FILE\n", argv[0]);
    exit(1);
  }

  char *program = argv[1];
  char *target = argv[2];
  //char *input = argv[3];

  // setup output dir
  char *options = getenv("TAINT_OPTIONS");
  //char *output = strstr(options, "output_dir=");
  char *output = getenv("SYMCC_OUTPUT_DIR"); // Reverted to older method of invocation
  char *input = getenv("SYMCC_INPUT_FILE");
  if (output) {
    output += 11; // skip "output_dir="
    char *end = strchr(output, ':'); // try ':' first, then ' '
    if (end == NULL) end = strchr(output, ' ');
    size_t n = end == NULL? strlen(output) : (size_t)(end - output);
    __output_dir = strndup(output, n);
  }
  
  const char* pc_config = getenv("SYMSAN_PC_CONFIG");

  if (input == NULL) {
      fprintf(stderr, "ERROR: Cannot read SYMCC_INPUT_FILE environment variable! Exiting...\n");
      exit(1);
  }
  if (strcmp(input, "stdin") != 0) {
      // load input file
      struct stat st;
      int fd = open(input, O_RDONLY);
      if (fd == -1) {
        fprintf(stderr, "Failed to open input file: %s\n", strerror(errno));
        exit(1);
      }
      fstat(fd, &st);
      input_size = st.st_size;
      input_buf = (char *)mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (input_buf == (void *)-1) {
        fprintf(stderr, "Failed to map input file: %s\n", strerror(errno));
        exit(1);
      }
  }
  
  if (pc_config != NULL) {
    fprintf(stderr, "\n=== PC Tracking Configuration ===\n");
    g_pc_tracker = new PCTracker();

    if (g_pc_tracker->load_config(pc_config)) {
        // Initialize log files
        const char* constraint_dir = getenv("SYMSAN_CONSTRAINT_DIR");
        if (constraint_dir == NULL) {
            constraint_dir = "constraints";  // Default
        }

        if (g_pc_tracker->init_log_files(constraint_dir)) {
            fprintf(stderr, "✓ PC tracking enabled\n");
        } else {
            fprintf(stderr, "WARNING: Failed to initialize constraint logs\n");
            delete g_pc_tracker;
            g_pc_tracker = nullptr;
        }
    } else {
        fprintf(stderr, "WARNING: PC tracking disabled (no valid config)\n");
        delete g_pc_tracker;
        g_pc_tracker = nullptr;
    }
    fprintf(stderr, "=================================\n\n");
  }

  // setup shmem and pipe
  int shmid = shmget(IPC_PRIVATE, 0xc00000000,
    O_CREAT | SHM_NORESERVE | S_IRUSR | S_IWUSR);
  if (shmid == -1) {
    fprintf(stderr, "Failed to get shmid: %s\n", strerror(errno));
    exit(1);
  }
  // This will occasionally fail to deallocate correctly and create a pretty nasty RAM crunch!
  // Let's stop that.
  //shmctl(shmid, IPC_RMID, NULL);

  __dfsan_label_info = (dfsan_label_info *)shmat(shmid, NULL, SHM_RDONLY);
  if (__dfsan_label_info == (void *)-1) {
    fprintf(stderr, "Failed to map shm(%d): %s\n", shmid, strerror(errno));
    exit(1);
  }

  int pipefds[2];
  if (pipe(pipefds) != 0) {
    fprintf(stderr, "Failed to create pipe fds: %s\n", strerror(errno));
    exit(1);
  }

  // prepare the env and fork
  int length = snprintf(NULL, 0, "taint_file=%s:shm_id=%d:pipe_fd=%d:debug=1",
                        input, shmid, pipefds[1]);
  options = (char *)malloc(length + 1);
  snprintf(options, length + 1, "taint_file=%s:shm_id=%d:pipe_fd=%d:debug=1",
           input, shmid, pipefds[1]);

  int pid = fork();
  if (pid < 0) {
    fprintf(stderr, "Failed to fork: %s\n", strerror(errno));
    exit(1);
  }

  if (pid == 0) {
    close(pipefds[0]); // close the read fd
    setenv("TAINT_OPTIONS", options, 1);
    char* args[argc];
    // This new fixed argument size invocation was causing problems with... pretty much anything that used more than a single argument
    /*
    args[0] = program;
    args[1] = target;
    args[2] = input;
    args[3] = NULL;
    */
    for (int i = 0; i < argc-1; i++) {
        args[i] = argv[i+1];
    }
    args[argc-1] = NULL;
    execv(program, args);
    exit(0);
  }

  close(pipefds[1]);

  pipe_msg msg;
  gep_msg gmsg;
  dfsan_label_info *info;
  size_t msg_size;
  memcmp_msg *mmsg = nullptr;

  while (read(pipefds[0], &msg, sizeof(msg)) > 0) {
    // solve constraints
    switch (msg.msg_type) {
      case cond_type:
        //__solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, (void*)msg.addr);
        //__solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, msg.id);
        // TO DO: Uncomment the C-style comments for the uninteresting branch filtering
        if (solved_branches.insert(msg.id).second) { // This should return true only if it's a new branch
            __solve_cond(msg.label, msg.result, msg.flags & F_ADD_CONS, msg.id);
        }
        else {
            if (print_debug) {
                printf("DEBUG: Not solving for uninteresting branch 0x%lx\n", msg.id);
                char jsonbuffer[256];
                snprintf(jsonbuffer, sizeof(jsonbuffer) - 1,
                    "{"
                    "\"source\": \"fgtest\","
                    "\"trigger\": \"duplicate_branch\","
                    "\"pc\": \"0x%lx\""
                    "}",
                    msg.id);
                std::thread t1(send_task, inet_addr("127.0.0.1"), 23100,
                               std::string(jsonbuffer));
                t1.detach();
            }
        }
        break;
      case gep_type:
        if (read(pipefds[0], &gmsg, sizeof(gmsg)) != sizeof(gmsg)) {
          fprintf(stderr, "Failed to receive gep msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != gmsg.index_label) {
          fprintf(stderr, "Incorrect gep msg: %d vs %d\n", msg.label, gmsg.index_label);
          break;
        }
        __handle_gep(gmsg.ptr_label, gmsg.ptr, gmsg.index_label, gmsg.index,
                     gmsg.num_elems, gmsg.elem_size, gmsg.current_offset, (void*)msg.addr);
        break;
      case memcmp_type:
        info = get_label_info(msg.label);
        // if both operands are symbolic, no content to be read
        if (info->l1 != CONST_LABEL && info->l2 != CONST_LABEL)
          break;
        msg_size = sizeof(memcmp_msg) + msg.result;
        mmsg = (memcmp_msg*)malloc(msg_size); // not freed until terminate
        if (read(pipefds[0], mmsg, msg_size) != msg_size) {
          fprintf(stderr, "Failed to receive memcmp msg: %s\n", strerror(errno));
          break;
        }
        // double check
        if (msg.label != mmsg->label) {
          fprintf(stderr, "Incorrect memcmp msg: %d vs %d\n", msg.label, mmsg->label);
          break;
        }
        // save the content
        memcmp_cache[msg.label] = mmsg;
        break;
      case fsize_type:
        break;
      default:
        break;
    }
  }

  wait(NULL);
  exit(0);
}
