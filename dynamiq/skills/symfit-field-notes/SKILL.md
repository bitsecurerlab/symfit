---
name: symfit-field-notes
description: Hard-won operational gotchas for SymFit (softmmu + linux-user), the Dynamiq front end, and Android/Cuttlefish targets. Read BEFORE starting an analysis session; every item below cost real time to discover and several produced confident WRONG answers.
---

# SymFit Field Notes

Companion to `dynamiq-scripting` and `dynamiq-mcp`. Those describe what the API
*offers*; this describes what actually happens, and the specific ways a session
goes wrong. Each item is something that was measured, not inferred.

**The meta-lesson first:** on these targets, a plausible-looking *positive*
result is more often instrumentation error than target behaviour. Three times in
one session a "finding" was the harness: a crash that was a shim, a breakpoint
that fired 12 times, a sweep that looked like a breakthrough. **Sanity-check
every positive against a bound you can derive independently** (e.g. "the victim
has 48 streams, so it cannot make 16,531 calls").

---

## 0. Enumerate the API before concluding a capability is missing

**Do this in the first 30 seconds of every session.** It is cheap and it would
have prevented several confident wrong conclusions recorded elsewhere in this
file.

```python
s = attach()
print(s.capabilities())                              # engine-declared
print(s.get_state()["result"]["rpc_capabilities"])   # per-method, more precise
import inspect
for m in sorted(d for d in dir(s) if not d.startswith("_")):
    print(m, inspect.signature(getattr(s, m)))       # 65 methods on this build
```

### The mistake this encodes

A previous session searched for `set_breakpoints`, did not find it, and wrote
down *"system mode has no breakpoints"*. The capability was there the whole
time under different names. One missing name was generalised into a missing
feature, and the breakpoint route was abandoned for a whole session on that
basis. **A name you cannot find is evidence about the name, not about the
engine.**

The same error shape recurs: an absent *spelling* read as an absent *feature*.
Compare the `taint_file=1 taint_file_name=...` trap in section 4 -- a silent
no-op because only `taint_file=<abs path>` is wired up.

### What is actually present on this build (softmmu, attached)

**Breakpoints: measured, and subtler than either naive answer.** In system mode
the engine's `set_breakpoints` RPC **is genuinely unsupported** --
`bp_add` returns `unsupported: set_breakpoints is not supported in system mode`.
So "no breakpoints in system mode" was right about the RPC. But
`break_at_addresses(["0x..."])` **works**, because it is built on
`run_until_any_address`, which is supported. Use that directly.

Do **not** use `bp_add` + `bp_run`. Read `dynamiq/session.py`:

```python
def bp_add(...):
    if value not in self.breakpoints:
        self.breakpoints.append(value)       # mutates the client list FIRST
    armed = self._sync_backend_breakpoints() # then the backend error escapes

def bp_run(...):
    if not self.breakpoints: raise InvalidStateError("no breakpoints configured")
    return self.break_at_addresses([...])    # -> run_until_any_address
```

`bp_add` records the address locally and *then* raises, leaving the session
holding a breakpoint the engine never armed (`armed: False` at best). A
subsequent `bp_run` then succeeds -- via `run_until_any_address`, not via
breakpoints. It looks like working breakpoint support and is not. If you wrap
calls in a try/except that swallows errors, you will conclude breakpoints work
in system mode. **Report as an SDK bug: partial state mutation before a failing
arm, plus a `bp_run` that silently substitutes a different mechanism.**

`capabilities()` does not report a breakpoint capability at all. It reports
`watchpoints: true`, but `watch()` builds a client-side list by the same
pattern, so treat that as unverified until a watchpoint is seen to fire.

Symbolic/solver surface, well beyond `query_value_range`:

| Method                                                                     | Use                                                                            |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `symbolize_memory(addr, size, name)`                                       | taint a *buffer*, not just a register                                          |
| `read_symbolic_memory(addr, size)`                                         | read labels back **out of memory** -- the tool for aliasing/overwrite dataflow |
| `write_memory`                                                             | craft a condition instead of waiting for it                                    |
| `query_value_eq(label, target)`                                            | "can this be exactly X" -- constructive reachability                           |
| `query_value_range(label, lo, hi)`                                         | **pass real bounds** (see below)                                               |
| `get_symbolic_expression`, `path_constraint_closure`                       | what the engine knows about a label                                            |
| `get_path_constraint_smt2`, `export_value_solver`, `solve_path_constraint` | auditable solver artefacts                                                     |
| `set_constraint_pc_filter([{start,end}])`                                  | **RPC-side** constraint scoping                                                |
| `trace_region(start, end)`, `trace_start(event_types, address_ranges)`     | scoped tracing                                                                 |

Reported **absent** on this build, so do not design around them:
`disassemble`, `list_memory_maps`, `trace_memory`, `trace_branch`,
`trace_syscall`. (Read instruction bytes with `read_memory` -- 256 bytes per
call -- and disassemble them host-side.)

### `query_value_range` is SEED-ANCHORED -- phrase the window accordingly

Signature: `query_value_range(label, lo=0, hi=0, base=0, relaxation="auto")`.
Called bare you get only the *global* range (for an unconstrained value, the
unsurprising `0 .. 0xffffffffffffffff`). Passing real bounds gives far more:
seven candidates (`seed`, `minimum`, `maximum`, `sample-1..4`), each with
**per-byte assignments naming the contributing input bytes**
(`symfit_input_24` ...). That is byte-level provenance from a ~30 ms solver
query -- the same question a taint census answers only after a whole run.

**The trap:** the bounded query is anchored to the *current concrete value*. If
your window excludes it, every relaxation profile fails with

```
"error": "bounded query excludes the seed endpoint"
```

and you get a meaningless `min = max = 0`. A bracket *around* a target (e.g.
`lo=0x90, hi=0x100` to test 152) is therefore **unanswerable by construction,
not unreachable** -- an easy false negative to misreport as a finding.

Correct phrasing: window from below the seed **out to** the target.

```python
r = s.query_value_range(label, lo=0, hi=TARGET)["result"]
# max == TARGET  -> TARGET is reachable
# max <  TARGET  -> max IS the true upper bound
```

Also note the seed is whatever the guest happened to be doing, so it varies
between runs (observed `0x4` and `0x74` on consecutive runs at the same PC).
Read it from the register before choosing bounds; never hardcode a window.

### Value labels and branch labels are different things

`get_path_constraint_smt2`, `get_path_constraint_evaluated` and
`solve_path_constraint` all reject a label from `symbolize_register` with
`invalid_params: label is not a branch-condition label`. They want a **branch**
label, which comes from `recent_path_constraints()` -- those entries carry
`op: "ICmp"`, a `pc`, `taken`, and a rendered `expression` such as
`((((input(24)) >> 0) & 0x1) == false)`. For *value* reasoning use
`query_value_range` / `query_value_eq` / `export_value_solver` instead;
`export_value_solver` returns checkable SMT2 plus `constraint_count` and
`recorded_branch_count`, which is the artefact worth putting in a report.

### Budget for navigation, not for reasoning

Measured on a live kernel site (`binder_transaction+0x1008`, `-smp 8`):

| Operation                                      | Time                            |
| ---------------------------------------------- | ------------------------------- |
| `pause`, `get_registers`, `symbolize_register` | 1-4 ms                          |
| `query_value_range` (bounded)                  | 8-104 ms                        |
| `export_value_solver`                          | 7 ms                            |
| **reaching the site**                          | **41 s / 55 s / 174 s / 207 s** |

Engine RSS ~5.2 GB baseline. Arrival costs 10^3-10^4x any query made once
there, and varies 5x run to run with ambient guest load. **Design sessions to
arrive once and ask many questions**, and never estimate a session from query
latency.

### `set_constraint_pc_filter` is the scoping knob that actually exists

The CLI `taint_filter_ranges` is broken (section 4), and unscoped constraint
collection is what drove the engine to ~49 GiB and an OOM kill. Before
symbolizing anything on a busy kernel path, scope collection to the function
under study:

```python
s.set_constraint_pc_filter([{"start": hex(FN), "end": hex(FN + 0x2000)}])
# ... symbolize, query ...
s.clear_constraint_pc_filter()
```

Treat the "taint does not scale" entries in this file as **conditional on not
having used this filter**, not as settled engine limits.

### Separate two categories when reporting engine problems

Several items once written up as *engine limitations* were operator error --
not knowing the API. When reporting upstream, label each finding as either
**(a) measured engine defect** or **(b) we used it wrong**. Conflating them
wastes maintainer time and damages the credibility of the real defects.

---

## 1. Pick the right mode first. This dominates everything else.

**If the target is a userspace library, use linux-user, not softmmu.** Nearly
every problem in a system-mode session against a userspace target is an artifact
of running a whole guest:

| symptom                                                                                                      | real cause                                                                                                                |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| after `symbolize_memory`, the guest stops progressing (900 s to not advance 61 instructions, ends in kernel) | symbolic mode slows the **entire VM**; one userspace process never gets scheduled far enough. No scheduler in linux-user. |
| the target process takes SIGSEGV when you stop it                                                            | stopping a process inside a live guest. User mode probes *before* the load and avoids the hazard.                         |
| minutes per iteration                                                                                        | boot/snapshot/restore costs. linux-user is seconds.                                                                       |

Breakpoints and `read_memory` **do** work reliably in softmmu (matched in 1.5 s
and 79 s on two runs). It is specifically *symbolize-then-resume* that collapses.
So softmmu is fine for concrete inspection; avoid it for symbolic runs.

## 2. Attach and timeout hygiene (softmmu)

- `ScriptSession(launch=False)` must set **both** timeouts. Passing only
  `instrumentation_rpc_timeout` leaves `qmp_timeout` at a default far too short
  for a `savevm` on a 4096M guest. Use `rpc_timeout=900, qmp_timeout=600`
  (matching `koobe_analysis.py`'s `make_session`).
- **A QMP timeout is not a cancel.** The engine keeps working. Issuing the next
  RPC into a mid-`savevm` engine **kills the engine process** and loses the
  guest. Treat a QMP timeout as "still busy": re-query status and wait.
- `close()` does **not** resume the guest. It leaves it paused, adb unreachable.
  Recover with a QMP `cont`.
- **Never leave a guest paused.** Android tolerates a long pause very badly
  (`hrtimer: interrupt took 31758240 ns`, watchdogs all firing on resume). A
  guest left paused ~2 h needed a full snapshot restore.
- A dead engine leaves orphaned `launch_cvd`/`run_cvd` holding the flock on
  `emulator.lock`; `snapshot.py restore` then fails with "A VM is already
  running". Kill those first.

## 3. Breakpoints: step off, and verify the match

- **`advance(mode="continue")` / `run_until_address` returns IMMEDIATELY when
  the PC already sits on a breakpoint.** A loop without an explicit
  single-step-off never progresses. Symptom: the same breakpoint "firing" N
  times with identical registers. This produced a wrong reachability conclusion
  ("site never reached") that was actually "we never left the first hit".
- `run_until_address` returning does **not** mean it matched. Check
  `matched or matched_address == X or pc == X`.

## 4. Taint: two silent failure modes

- **libc `memcpy` does not propagate dfsan taint.** Measured at one compare
  site: via glibc SIMD `memcpy` the register was concrete (label 0x0) with **0**
  constraints; via a byte-by-byte `volatile` loop it was symbolic
  (`concat(0, input(0))`) with **4**. It is not enough to byte-loop your own
  code — if the target library memcpy's your buffer onward (e.g. BASS core into
  a plugin buffer), resolve `memcpy`/`memmove`/`memset` **and the `_chk`
  variants** to byte loops too. Symptom: a census reporting zero constraints for
  *everything*, including fields you know are checked.
- **Do not `take_snapshot` during a taint run.** Taints do not survive a
  snapshot (per the engine author). A snapshot right after `symbolize_memory`
  silently discards the labels and every later step records nothing — a false
  negative that reads exactly like "taint does not propagate".

## 5. `cmp` + `csel` checks: visible to the engine, invisible to the RPC

On AArch64 a `cmp` emits no TCG `setcond` (it updates the NZCV globals);
`b.cond` becomes `brcond` and `csel` becomes `movcond`. So recorded constraints
sit at **branch** addresses, never at the `cmp`.

`tcg_gen_movcond_i32/i64` (`tcg/tcg-op.c:1153`, `:3036`), gated on
`second_ccache_flag`, **deliberately emit a `setcond` for symbolic effect** and
movcond the expression registers. So for a `csel`:

- the ICmp label **with its PC is created**, and the selected expression *is*
  propagated — the engine is NOT blind
- but the setcond's result temp is freed and never feeds a `brcond`, so
  `symsan_trace_cond_internal` never fires -> **no path constraint**
- `recent_symbolic_pcs` looks like the right field but is a **client-side
  reshape of the path-constraint response** (`qemu_user_instrumented.py:575`) —
  same data, no new information
- the **telemetry stream is the route**: `__taint_union` emits a
  `label_creation` event carrying op and pc for every label, including the ones
  a `csel`'s setcond creates. The engine-side sender is implemented and works
  (it has been used during KOOBE script development).
  **What is missing is only a consumer in the Dynamiq Python layer** — grep for
  "telemetry" across the package returns nothing. This is a front-end gap, not
  an abandoned feature; an earlier gdb-based client design is what lapsed.
  Launch the engine with `-symfit-telemetry <ip:port>` (see
  `koobe_analysis.py`'s `qemu_args`) and consume the JSON yourself, or reuse an
  existing standalone listener. Do **not** expect the Python SDK to surface it.

### CONFIRMED: both csel checks DO produce ICmp labels

Measured 2026-10-29 on libbass_ape.so's APE header parse, taint introduced with
`symbolize_memory` over the 76 header bytes, labels read from `labels.dmp`:

```
0x1d7d8  magic              (branch) FOUND x1
0x1d840  channels [1,32]    (CSEL)   FOUND x1   <- RPC census said NO COMPARE
0x1dad0  blocksPerFrame !=0 (branch) FOUND x1
0x1db1c  finalFrameBlocks   (CSEL)   FOUND x2   <- RPC census said NO COMPARE
```

So the census is **9/9 correct** on that header once you read the labels instead
of the path constraints. The two "missed" fields were an artifact of the API
choice, not an engine blind spot. The only *real* taint blind spot is item 4's
libc `memcpy`, which is a harness obligation.

### Recipe: get labels.dmp in linux-user (four non-obvious steps)

Everything below is required; omit any one and you get a silent empty dump.

1. **`-symfit-telemetry` is SYSTEM-MODE ONLY** (parsed in `vl.c`, absent from
   `linux-user/main.c`): `qemu: unknown option 'symfit-telemetry'`. So in
   linux-user, `labels.dmp` is the only route to these labels.
2. **linux-user bypasses `atexit`.** `linux-user/syscall.c:285` is
   `_syscall1(int, exit_group, int, error_code)` and `:9352` is
   `return get_errno(exit_group(arg1))`. `_syscall1` expands to a libc
   `syscall(__NR_exit_group, ...)`, so neither `exit()` nor `_exit()` runs and
   DFSan's `dump_labels_at_exit` handler never fires. (It *does* fire if the
   engine dies during option parsing via `exit(1)` -- which is the only reason
   the dump is ever seen by accident.)
3. **Interpose libc `syscall()` in the ENGINE process.**
   `syscall@GLIBC_2.17` is an imported (UND) symbol in the engine, so
   `LD_PRELOAD` works. Route `__NR_exit_group` (94 on arm64) and `__NR_exit`
   (93) through `exit()`. See `tools/exitfix.c` and `tools/engine-wrap.sh`;
   point `qemu_user_path` at the wrapper. Note `dfsan_dump_labels` is **not**
   exported, so you cannot call it directly -- you must make `atexit` run.
4. **Release the terminal pause.** With an RPC session attached,
   `linux-user/syscall.c:9348` has `ia_rpc_pause_on_exit()` hold the engine in a
   terminal pause at guest exit rather than terminating
   (`termination_kind: "exit_group"`). `ScriptSession.close()` only drops
   sockets, so the engine sits paused and is then killed. Issue the raw RPC
   **`close`** (valid only during terminal pause) to let it fall through to
   `exit_group` -> interposer -> `exit()` -> dump:
   ```python
   be = sess.session.backend
   be._response(be._require_rpc().request("close", {}, timeout=60.0))
   ```

Parse with `tools/census_labels_dmp.py --bias <load bias>`; `ICmp` is **op 28**
with the predicate packed as `(predicate << 8) | 28`.

### Bonus: linux-user has MORE capabilities than softmmu
The linux-user `capabilities` response reports `trace_branch: True`,
`disassemble: True`, `list_memory_maps: True` -- all **False** in softmmu. Check
`capabilities` per mode rather than assuming parity.

### Other routes, for reference

Harder than it looks. Three routes, with their real constraints:

- **Telemetry** is the system-mode route and works there. Wire format:
  **4-byte big-endian length, then UTF-8 JSON** (not line-delimited -- a naive
  reader gets garbage). Working listener + analyser in `tools/`. The engine-side
  sender is implemented and maintained; only a Python-layer consumer is missing.
- **`labels.dmp`** (`TAINT_OPTIONS=dump_labels_at_exit=<path>`) contains
  `<label> (<l1> <l2> <op> <size> <pc>)` for every label, so ICmp labels and
  their PCs are in it. `ICmp` is **op 28**, with the compare predicate packed as
  `(predicate << 8) | 28`. Parser: `tools/census_labels_dmp.py`.
  **But**: the dump is an `atexit` handler inside the DFSan runtime, so it only
  fires when (a) DFSan was actually initialised -- a plain linux-user run with no
  symbolic activity produces no dump and no INFO line at all -- and (b) the
  ENGINE exits on its own. `ScriptSession.close()` kills it first, so the dump
  never happens. Note the flag's compiled default is a hardcoded
  `/home/aerwi002/labels.dmp`, a host path that may not exist in a container.
- **`taint_file=<path>`** is a real DFSan flag, but it did **not** take effect
  through QEMU's syscall path -- expected, since DFSan is linked into the engine
  and a guest `read` is not intercepted by its libc hooks. Introduce taint with
  `symbolize_memory` instead.

**Consequence:** a census built on `recent_path_constraints` alone will report
"NO COMPARE" for every `csel`-based check. Either consume telemetry, or treat a
negative as a lead, never a proof. Clang emits
`cmp`+`csel` readily for `if (cond) ret = ERRCODE;` — exactly how validation is
written — so the gap lands on the construct you care about. Corroborate every
negative with a concrete parameter sweep.

Also watch the `sub w8,w8,#1; cmp w8,#0x1f` idiom: a two-sided range check
([1,32]) as one unsigned compare against 31. Grepping for the upper bound finds
nothing.

**Do not test select-propagation on a select whose operands are both concrete.**
Probing `x0` after `csel w0, w8, w0, hi` is uninformative — both operands are
constants, so it reads concrete either way regardless of taint.

## 6. What SymFit is actually good at here

Measured over a full day on a stripped proprietary codec:

- **Good: dataflow.** It derived `total = final + (frames-1)*bpf` from the
  binary, byte-indexed (`concat(input(63),input(62)) + ...`), and proved via
  `query_value_range` that the reachable range was the full 32-bit space with
  **zero assumptions**. That is faster and more reliable than hand-tracing.
- **Weak: generating valid inputs.** `query_value_eq` returned arithmetically
  correct witnesses that were **invalid inputs**, because downstream validation
  wasn't in the constraint set (it ran after the break point, and one check was
  a `csel`). Solve-then-verify; never assume a witness parses.
- **Absent: reachability and allocator provenance.** "Is this site reachable",
  "which object does this address belong to", "is this pointer writable" —
  all answered by breakpoints, interposers and `/proc/self/maps`, never by the
  symbolic machinery. These were the questions that actually decided things.

Use it for "which input bytes reach this value and what can it be". Do not use
it for "is this reachable" or "where does this land".

**Highest-value front-end change, from this session:** a telemetry consumer in
the Python layer. The engine already emits everything needed to census
`csel`-based bounds checks; the only reason today's census was wrong on two of
nine fields is that the SDK exposes only the branch-constraint view.

## 7. Android/Cuttlefish targets: build harnesses without an NDK

Host clang accepts `--target=aarch64-linux-android21`; only linking an
*executable* needs NDK crt objects, and a **shared library needs none**.

```sh
adb pull /system/lib64/libc.so ; adb pull /system/lib64/libdl.so
clang --target=aarch64-linux-android21 -shared -fPIC -nostdlib \
      h.c libc.so libdl.so -o h.so
# work goes in __attribute__((constructor))
LD_LIBRARY_PATH=/data/local/tmp/x LD_PRELOAD=/data/local/tmp/x/h.so \
  /system/bin/sh -c true
```

The real Android linker is live, so `dlopen()` of app-private libraries works and
**no bionic shims are needed**. Compare with a hand-rolled host mmap loader,
which needs all of: `__sF` (bionic's stdin/stdout/stderr are FILE *objects*, not
pointers — a dummy makes glibc printf fault in
`__printf_buffer_flush_to_file`, which looks exactly like a target crash),
`pthread_cond_t` alignment (bionic 4-byte vs glibc 8-byte + 64-bit LSE atomics
-> `ldadda` -> **SIGBUS/BUS_ADRALN**; fix by storing only a pointer to an aligned
cond), FORTIFY `_chk` wrappers (builtins can't be taken by address), and
byte-loop copies for taint.

**Bonus: free interposition.** Anything the preloaded `.so` defines wins over
the target's import. Defining `av_fast_realloc` intercepted every call from a
dlopen'd `libavformat.so`; recover the real one with
`dlsym(dlopen("libavutil.so", RTLD_NOW), "av_fast_realloc")`.

A static *glibc* binary from host gcc does run on Android and is fine for
self-contained tests, but it cannot `dlopen` bionic libraries (two libcs).

### Manual ELF loader pitfalls (if you must)
- Mapping `p_memsz` bytes **from the file** puts the `.bss` tail past EOF; the
  first touch raises **SIGBUS**. Map file-backed only to `p_filesz`, then an
  anonymous tail to `p_memsz`.
- AArch64 reloc types: `ABS64=257`, `GLOB_DAT=1025`, `JUMP_SLOT=1026`,
  `RELATIVE=1027`. (1024 is `COPY`.)
- Run `DT_INIT_ARRAY` or proprietary libraries will misbehave subtly.

## 8. Allocator provenance on Android — use the platform, not guesswork

The expensive questions are "what object is this address in" and "is it
writable". Answer them directly:

- **`/proc/self/maps` from inside the process.** This immediately identified a
  blocking crash as a write into `libavcodec.so`'s **`r--p`** mapping — i.e. a
  write to read-only `.rodata`, not an unmapped address. Mask the **TBI tag**
  first: Scudo-tagged pointers like `0xb400007b64a7c810` are really
  `0x7b64a7c810`, and an unmasked lookup reports UNMAPPED.
- **`malloc_iterate` / `malloc_disable` / `malloc_enable` /
  `malloc_backtrace` / `malloc_usable_size`** are exported from bionic
  (`LIBC_Q`). That is live-allocation enumeration with sizes — effectively the
  ASan-style provenance capability, already shipped.
- **Scudo segregates by size class.** An 8 KB buffer can never neighbour a
  1048-byte allocation. Growing one buffer to reach a victim is futile; you must
  place an allocation **in the victim's size class**. Per-process
  `libc.debug.malloc.options=guard_page backtrace` and
  `libc.debug.gwp_asan.sample_rate.<pkg>` are settable and catch the *fault*,
  but give no provenance across an OOB read.

- **`malloc_iterate` has no ordering and no provenance.** It answers "what is
  next to this address *now*", never "who allocated it, and before or after the
  victim ran". That distinction is usually the whole question. Interpose the
  target's **own allocator wrappers** instead and tag each record with a phase
  (which open/parse was running). For FFmpeg: `av_malloc`, `av_mallocz`,
  `av_calloc`, `av_realloc` — free via `LD_PRELOAD`, since library-to-library
  calls go through the PLT while libavutil's internal calls bind directly, which
  is exactly the filter you want.
  Two self-inflicted failures to expect: a fixed-size trace buffer will be
  **exhausted by the noisy phase** (16 donors x 32 streams x 64 timestamps =
  exactly 32768 records, and the victim's allocations are silently dropped) —
  filter by the size class you care about; and a prefix test like
  `mode[0]=='a' && mode[1]=='l'` matches both `all` and `alt`.
- **Scudo's chunk grid is deterministic; measure it before grooming.** Within a
  size class, chunks sit on a **fixed stride**, contiguous and gapless (measured:
  **1104 bytes** for FFmpeg's 864/880/1048 objects, 28 chunks, no holes). What is
  randomised is which *object type* lands in a chunk, plus region base. So print
  sorted consecutive deltas first: one repeated delta means stop sweeping
  parameters and start doing arithmetic.
  Corollary that invalidates most naive grooming: Scudo serves *fresh* chunks by
  **bump allocation**, so anything allocated before the victim occupies a strictly
  lower run and **can never be adjacent** (measured: 0 in-window, not "rarely").
  Free it first and the victim re-allocates the *identical addresses*.
- **There is no uninitialized-heap residue on this image.** Scudo zeroes every
  chunk on allocation (MTE's `stzg` tags and zeroes in one instruction, so it is
  free). Measured: 256 chunks filled with `0xAA`, freed, re-allocated — **256 of
  256 returned at the freed addresses, none held a single non-zero byte**. Kill
  any plan that depends on stale bytes, including `av_realloc`'s non-zeroing
  growth, which reads as zero because the allocator already zeroed it. Also
  `malloc_usable_size` returns the *requested* size, not the class stride.
  **The control matters more than the result here:** always verify the
  re-allocations landed on the *freed addresses*. Without that check, "all zero"
  is equally consistent with having been served fresh bump space, and you would
  report a platform property you never measured.
- **Check reach before placement.** On an index-walk overflow, the attacker's
  reachable offset set may be tiny and fixed by constants they do not control. In
  the VobSub case the queue stride (32), the chunk stride (1104) and the context
  size (1048) conspire so that the **first OOB slot past the context lands exactly
  on the next chunk's base**, where offset +0 is always a non-NULL class pointer —
  fatal either as a write to `.data.rel.ro` or as a realloc of a non-heap pointer
  (Scudo tag check). 12/12 trials died there. Three usable slots, and the first
  attacker-populated one was 35 slots further on. No grooming strategy could have
  mattered. Compute the reachable offset set **before** investing in placement.

## 8b. Whole-run taint census from the CLI — no RPC session needed

This is now the preferred way to enumerate every tainted compare in a run,
including the decode path and including `csel` sites the RPC cannot see.

```
echo x | APE_BYTE_COPY=1 \
  TAINT_OPTIONS="taint_file=/abs/path/to/input dump_labels_at_exit=/tmp/x.dmp" \
  ./engine-wrap.sh ./harness /abs/path/to/input
```

- **`taint_file=<ABSOLUTE path>` is the correct spelling.** `taint_file=1
  taint_file_name=<path>` is a **silent no-op** — the run completes, DFSan prints
  `dumping labels to ...`, and the file is **0 bytes**. So is a relative path.
  Nothing warns you; you just get an empty census and conclude "no taint
  reaches here", which is wrong. Always check the dump is non-empty before
  interpreting it.
- **`TAINT_OPTIONS` overrides the compile-time dump path.** The hardcoded
  `$HOME/labels.dmp` is not a constraint — pass
  `dump_labels_at_exit=<writable path>`. Confirm by timestamp, not existence:
  stale 0-byte `labels.dmp` files from earlier runs sit around and are very easy
  to misattribute to the run you just did.
- `engine-wrap.sh` must supply `LD_PRELOAD=exitfix.so`: linux-user exits via
  `exit_group`, which bypasses DFSan's `atexit` hook. You will see
  `[exitfix] syscall(94) -> exit(0) so atexit runs` when it is working.
- **Prefer CLI over an RPC session for a whole-run census.** With a session
  attached, `ia_rpc_pause_on_exit` holds a terminal pause and closing the
  session can kill the engine before the dump runs — in one attempt
  `symbolize_memory` succeeded and *no dump file was produced at all*.
- `taint_filter_ranges` could not be made to work: `a-b` is silently ignored
  (identical label count to unfiltered) and `[a,b]` killed the engine with no
  dump. Do not rely on it; filter after the fact instead (below).

### Per-compare input-byte provenance, from the dump alone

`labels.dmp` leaf labels map **1:1 to input bytes: label k <-> byte k-1**.
Verify it per run — the count of `op==0` leaf lines should equal the input
length exactly (measured: 4172 leaves for a 4172-byte file). Then resolve each
ICmp label's `(l1, l2)` tree down to leaves to get the exact file bytes each
compare depends on. This beats the RPC route: no `get_symbolic_expression` call
per constraint, and it still sees `csel` sites.

Opcode encoding, confirmed in `symsan/runtime/dfsan/dfsan.cpp`:
`get_op_name(op & 0xff, op >> 8)` (line 232), `case 28: ICmp` (line 235), and
`dfsan_union(..., (predicate << 8) | ICmp, ...)` (line 1555). Note a predicate
of **0** means *"no predicate recorded"* (line 215), not "equality" — in the
runs here every site reported 0, so this build does not give you the comparison
direction.

### Taint the SMALLEST input that reaches the check — byte-copy mode OOMs fast

A **4172-byte** tainted input in byte-copy mode got the engine **OOM-killed at
~51 GB** (`memory.events: oom_kill 1`, `memory.peak` ~51e9). Nothing times out
and nothing is logged by the engine: the shell just reports `Killed` and no dump
appears, which looks exactly like the earlier "no dump" failures. Check
`memory.events` before blaming the dump path.

Cause: every tainted input byte propagating through the library's own buffering
multiplies the label graph. Byte-loop copies (needed to preserve taint at all)
make it worse, because each byte becomes an individually tracked union.

Mitigation, in order:
1. **Shrink the input file**, not the taint config. `taint_filter_ranges` does
   not work, so a minimal input is the only reliable way to bound the tainted
   region. For a container format, strip the payload and keep only the
   headers/index the checks read: here 52+24+16 = **92 bytes** instead of 4172,
   a ~45x reduction in tainted input, and the header compares all still execute
   during stream-create.
2. **Make the small input WELL-FORMED.** Shrinking a container file to 92 bytes
   made things *worse*: a degenerate index (all seek-table entries equal to EOF,
   from an `i*0` typo) sent the parser into a zero-length read loop that
   re-tainted every pass. Labels passed **1,074,287 from 92 tainted bytes**,
   `[DIAG-LOAD-L2-ZERO]` flooded stderr, and the **engine** SIGSEGV'd
   (`pc=0x0`, engine-range `caller=`; the harness's own fault handler never
   fired, which is how you tell an engine crash from a guest one). Fixing the
   index *appeared* to drop the diagnostic count to 213 -- but that run was
   truncated by a timeout, and with a real budget the well-formed input reaches
   **1,075,943 labels and OOMs at ~49 GiB** anyway. **Never read a counter from
   a run that was killed; it is not a converged total.** The degenerate index
   was a real bug but not the cause, so the label-scale behaviour remains
   open -- test the input before reporting upstream, but do not clear the
   engine on truncated evidence either.
3. Only then consider raising memory — and on a shared host, do not: a 51 GB
   spike is antisocial when ~80 other users are on the box.

### The byte-copy trap will catch you twice

The taint-preserving byte-loop env knob (`APE_BYTE_COPY=1` in that harness) is
easy to drop when you port a driver from RPC to CLI. Do that and SIMD `memcpy`
silently strips taint mid-dataflow: the census came back claiming **not one
plugin compare depended on the header fields**, when the in-guest sweep had
already proved those fields are validated. The giveaway is a census that
contradicts behaviour you have already measured — treat that as instrumentation
failure first, target behaviour second.

## 8c. Pick the instrument to match the question

Several hours went into tracing dataflow to three code sites that, measured with
one breakpoint, **never execute**. The question had been "which input bytes
reach this site" when it was really "what value does this site see" -- and those
need different tools.

| question                               | instrument                            |
| -------------------------------------- | ------------------------------------- |
| which input bytes does this check read | taint + `labels.dmp`                  |
| what value does this site see          | **breakpoint + `get_registers()`**    |
| does this site execute at all          | **breakpoint + a CONTROL breakpoint** |

Breakpoints need no taint, no shadow memory, no byte-copy knob and no dump, so
they run at full engine speed. Reach for them first when the question is about a
value or about reachability.

**A control breakpoint is mandatory.** A miss proves nothing unless something
you know must fire does fire. One run reported "stopped before hitting any
requested breakpoint" and was uninterpretable; adding a control at an address
read from disassembly (which every accepted input must execute) made the result
conclusive -- the control fired with the exact predicted register value, then
the process ran to `exit_group` without touching the three sites under test.
Report the terminal state (`termination_kind`) too, so "ran to completion
without hitting it" is distinguishable from "stopped early for another reason".

**Taint does not scale through a decode loop.** On an audio codec, **76 tainted
bytes produced 693,319 labels** and no dump: header values flow into the decode
buffers across 64 KB output calls. Parse paths census fine; decode paths do not.
Do not keep re-configuring -- change instrument.

Two `dynamiq` API notes that each cost a run: the method is `get_registers()`,
not `registers()`; and the terminal pause is released by the **raw** RPC
`sess._session.backend._rpc_request("close")` -- `sess.close()` tears the engine
down, so DFSan's `atexit` dump never runs and you get no labels file at all.

**Check the instrument is pointed at the target before believing an empty
result.** Five consecutive censuses came back empty because the harness defaults
to `BASS_APE_StreamCreateFile` (BASS opens the file itself) rather than
`...StreamCreateFileUser` (reads through the harness buffer that
`symbolize_memory` had tainted). Every one of those runs printed
`APE_StreamCreateFile=` in its first lines. A passing leaf-count assertion only
proves taint was *introduced*; it says nothing about whether the code under test
ever reads that memory.

## 9. Misc traps that cost real time

- `kernel-log-pipe` and `logcat-pipe` in the Cuttlefish instance dir are
  **FIFOs**. `tail -c` on them blocks forever. Read `logs/kernel.log` instead.
- Never pipe a long background command through `tail`/`head` — it buffers until
  EOF, so you fly blind. Redirect to a file and read that.
- `pgrep -f` / `pkill -f` **match your own shell**, because the pattern appears
  in your own command line. This killed the controlling shell twice. Use
  `pgrep -x`, a bracket trick (`'repea[t].sh'`), or match on `/proc` and exclude
  `$$`. Note `comm` is truncated to 15 chars, so `pgrep -x symfit-system-a`.
- Do **not** copy host shared libraries into a container's system paths.
  `docker cp` does not dereference symlinks, producing self-referential links;
  every new process then dies with exit 135 mid-run. Use a private directory and
  an explicit loader path.
- `nm -D` on a versioned library needs the `@@VER` suffix accounted for —
  grepping for a bare symbol name silently finds nothing
  (`avformat_open_input@@LIBAVFORMAT_61`).
- The engine binary is **stripped**: `nm` is useless on it. Use the RPC
  `capabilities` response to check whether optional features (e.g.
  `solve_path_constraints`) are linked, not symbol archaeology.
