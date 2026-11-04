# SymFit Shadow Memory Concurrency Design

Status: implementation design, not implemented. Source baseline: `f7794ed915`.

Baseline descriptions below refer to that revision. The current runtime now
supports native compiler artifacts through a separate linear-shadow mode, and
the LLVM pass's union-helper declarations match the updated runtime ABI.
SymFit emulator callers still use sparse pages. The 2-/4-vCPU regression tests
cover discovery, selection, register isolation, and VM run control; they do not
implement or validate the storage-concurrency design proposed here.

SymFit needs concurrent access to byte shadow memory without holding a lock
while constructing symbolic expressions. The proposed implementation separates
shadow storage from expression construction: loads copy labels into private
buffers, stores prepare labels in private buffers, and short spinlock critical
sections transfer those labels to or from shared storage.

The page directory uses sharded blocking mutexes because its `std::map` nodes
can allocate. Separate sharded spinlocks protect label contents. Stable page
pointers and a small positive lookup cache let frequently accessed pages bypass
the directory mutexes. This preserves parallel execution on different shards
while avoiding allocation, expression construction, and telemetry under a
spinlock.

This design makes shadow storage safe. It does not make a concrete guest memory
access and its separately generated shadow access one atomic operation, and it
does not establish that every other part of SymFit supports MTTCG.

## 1 Goals and scope

The implementation must:

- Prevent concurrent page-directory corruption and duplicate page publication.
- Prevent C++ data races on shadow labels, including concrete writes that clear
  labels and probes that decide whether a region is concrete.
- Provide coherent snapshots and commits for ordinary scalar shadow accesses,
  including accesses that cross host shadow-page boundaries.
- Keep symbolic expression construction, allocation, callbacks, and logging
  outside the label spinlocks.
- Preserve existing label expression semantics and public SymFit runtime APIs
  wherever those APIs can be made safe.
- Support both system-mode and user-mode callers of the shared runtime.
- Provide a testable storage component independently of QEMU and the runtime's
  fixed-address mappings.

The initial implementation does not introduce lock-free page reclamation,
reader-writer spinlocks, seqlock reads of non-atomic labels, or a new symbolic
memory model. Device DMA tracking, guest memory ordering, guest atomic
instructions, and concrete/shadow pairing require separate integration work.

## 2 Current behavior and problems

Relevant source locations are listed by symbol so the references survive edits.

| Location | Current behavior | Required change |
| --- | --- | --- |
| [dfsan.cpp](../symsan/runtime/dfsan/dfsan.cpp), `g_shadow_pages`, `shadow_for`, `getOrCreateShadow` | One unsynchronized `std::map`; raw label pointers escape | Encapsulate directory access and publication |
| Same file, `__taint_union_load` | Reads live labels while looking up label metadata and constructing unions | Build from a private label snapshot |
| Same file, `__taint_union_store` | Mixes writes with `Extract` expression creation | Prepare labels, then commit |
| Same file, `__dfsan_set_label`, `dfsan_add_label` | Direct pointer iteration and updates | Use range fill and conditional commit APIs |
| Same file, `dfsan_get_label`, `dfsan_region_is_concrete`, `dfsan_concrete_page` | Unsynchronized queries | Participate in the directory or data-lock protocol |
| [dfsan_custom.cpp](../symsan/runtime/dfsan/dfsan_custom.cpp) | Copy, move, string, and allocation wrappers directly copy or clear shadow pointers | Replace direct accesses with storage operations |
| [dfsan_interceptors.cpp](../symsan/runtime/dfsan/dfsan_interceptors.cpp), `ReleaseShadowMemoryPagesToOS` | Assumes a contiguous shadow address range | Audit reachability; remove or redesign that assumption |
| [tcg-runtime-symsan.c](../accel/tcg/tcg-runtime-symsan.c) | Guest and host helpers call the runtime APIs | Retain API usage; verify all access sizes and callers |
| [usertlb.c](../accel/tcg/usertlb.c) | Uses concreteness queries for fast paths | Preserve query semantics and audit cached conclusions |
| [ia-rpc-softmmu.c](../ia-rpc-softmmu.c) and [linux-user/ia-rpc.c](../linux-user/ia-rpc.c) | Inspect or update labels through runtime calls | Verify coverage and existing pause requirements |

There are also page-boundary defects that must be addressed while extracting
storage operations. The current union helpers compute the next shadow address
using `addr + n`, rather than the next page boundary. Some fast-path checks
still index the original page after crossing into another page. Set/add loops
assume adjacent application pages have adjacent shadow arrays. A load whose
first page is absent can return zero without examining a symbolic second page;
a clearing store can similarly miss a later allocated page.

The refactor must use a general range iterator instead of preserving these
assumptions. Fixes need explicit regression tests; unrelated expression
semantics should remain unchanged.

## 3 Consistency contract

### 3.1 Address identity

Key shadow pages by host application address, as the current runtime does.
Guest virtual addresses and vCPU identifiers must not be part of the key:
two guest aliases of the same host RAM need the same shadow bytes.

Keep the runtime shadow page size at `kPageSize`, currently 4096 application
bytes. This is distinct from a target's guest page size. A page contains 4096
32-bit labels, or 16 KiB of label storage.

### 3.2 Scalar operations

Set an initial `kAtomicShadowBytes` of 64 application bytes. This is a storage
policy, not a declaration that every expression builder supports 512-bit
expressions. Existing scalar guest helpers normally request at most eight
bytes; validate the complete caller inventory before relying on that bound.

For an operation at or below this limit:

- A snapshot observes one consistent set of byte labels.
- A commit publishes the entire prepared set to cooperating readers together.
- Both guarantees apply across page boundaries and shard collisions.
- A zero-size operation does nothing and never evaluates `addr + size - 1`.
- Missing pages read as zero and are not allocated by reads.
- Clearing absent pages does not allocate storage, but clearing must continue
  across the entire requested range.

Each snapshot or commit has a point during its locked copy at which the
operation can be considered to have occurred. Expression construction happens
after a load's snapshot and before a store's commit. Its completion order does
not determine shadow-memory ordering.

### 3.3 Larger operations

Use a maximum copy window of 4096 application bytes initially. A window touches
at most two shadow pages, but copies up to 16 KiB of labels. Treat this as a
benchmarkable starting point; it is not a proven optimal spinlock duration.

Bulk fills and copies commit window by window. They do not promise atomicity
over an arbitrary-sized region. Ordinary `memcpy`, `memmove`, and allocation
clears do not require such a promise. All windows still use the same locks as
scalar operations.

When an API needs a coherent read of a larger range, including
`dfsan_region_is_concrete`, use version validation across bounded snapshots as
specified in Section 9. Do not return a supposedly coherent result assembled
from unvalidated windows. A large store may be observed between its windows;
that is a permitted intermediate state of the bulk operation.

### 3.4 Concrete values remain separate

This sequence remains possible after the storage change:

```text
vCPU A: load concrete value X
vCPU B: store concrete value Y and commit label LY
vCPU A: snapshot label LY
```

The label snapshot is internally consistent, but it may not describe X.
Similarly, two concrete stores and their shadow commits can occur in different
orders. Do not advertise complete MTTCG symbolic correctness based on this
change. Preserving that pairing requires coordination around both operations,
including fault exits, atomic guest operations, and other RAM writers.

## 4 Storage layout

Introduce a private storage component, for example
`symsan/runtime/dfsan/shadow_memory.{h,cpp}`. It owns all mutable shadow labels.

Conceptual structures, with initialization adapted to the sanitizer runtime:

```cpp
constexpr size_t kShadowShardCount = 256;

struct ShadowPage {
    dfsan_label labels[kPageSize];
};

struct DirectoryShard {
    BlockingMutex mutex;
    std::map<uintptr_t, ShadowPage *> pages;
};

struct DataShard {
    StaticSpinMutex mutex;
    uint64_t version;  // Accessed only under this data mutex.
};
```

Place directory shards and data shards in separate arrays. Align each shard to
the supported host cache-line alignment, initially 64 bytes for the primary
x86-64 build. Verify actual sizes and alignment in a static assertion/test;
do not assume an alignment annotation makes the objects exactly 64 bytes.

Use one deterministic hash of the host page number for both directory and data
shard selection. Mix higher page-number bits before masking with
`kShadowShardCount - 1`, so regularly spaced allocations are less likely to
collide. Keep the hash internal and fixed for a process lifetime. Add tests for
deliberate collisions rather than depending on a particular workload's spread.

The 256-shard count is an initial tuning choice. It is not a performance claim.
Benchmark alternatives such as 64, 256, and 1024 with the same algorithm.

### 4.1 Why two kinds of lock

Allocating a shadow-page candidate before locking does not remove allocation
from `std::map::insert`: the map must also allocate a tree node. Therefore:

- Directory lookup and insertion use a blocking mutex. Map insertion may
  allocate while this mutex is held.
- Label copies use the existing sanitizer `StaticSpinMutex` and scoped guard.
- A data spinlock must never enclose map insertion or any allocator call.

This retains the existing map representation while fixing the expensive
critical section. A preallocated intrusive directory could remove map-node
allocation later, but is not required for the first implementation.

### 4.2 Page publication and lifetime

Allocate and zero a candidate `ShadowPage` outside every storage lock. Acquire
its directory mutex, recheck the map, and insert only if still absent. Release
the directory mutex before freeing an unused candidate. Treat allocation
failure according to the runtime's fatal-allocation policy; never silently
discard a nonzero label write.

Map insertion can allocate under its blocking mutex. The map and candidate
allocators must be uninstrumented and must not reenter shadow APIs. Verify
this property in the actual runtime build, including custom allocator wrappers.

Published pages are never freed, replaced, or erased during normal execution.
This follows the current grow-only directory model and makes cached pointers
safe. An unmap or allocation reuse clears labels; it does not retire the page.
Guest-memory lifecycle tracking is still necessary to avoid stale taint after
address reuse.

Publishing a zeroed page changes directory membership, but does not change
logical byte labels. Its first nonzero commit uses the data lock like every
other write. Only unpublished candidates can be initialized without that lock.

## 5 Lock ordering and lookup rules

### 5.1 Global lock order

For every multi-shard operation:

1. Acquire required directory mutexes in ascending shard index.
2. Acquire required data spinlocks in ascending shard index.
3. Release data spinlocks in reverse order.
4. Release directory mutexes in reverse order.

Deduplicate indices before acquiring locks. Two pages hashing to the same shard
must acquire that shard only once. A fixed bitset of 256 bits is sufficient to
represent a general shard set; scalar/window operations can use a small sorted
array. Build these sets outside locks.

Code holding a data spinlock must not acquire a directory mutex, perform page
creation, or call a public shadow API. Private locked helpers avoid accidental
recursive acquisition. The locks are deliberately non-recursive.

A directory holder may wait for a data spinlock. A data holder cannot wait for
a directory mutex, so this ordering does not create a directory/data cycle.
No external callback or QEMU mutex acquisition is permitted while either kind
of storage lock is held.

### 5.2 Lookup cache and the common path

Use a small fixed-size thread-local cache, initially 16 entries, mapping host
page bases to stable `ShadowPage *` values. Each entry is populated only from a
directory lookup protected by its mutex. Cache collisions replace entries.

Cache only positive results. Never cache absence: another vCPU can allocate a
shadow page immediately afterward. The cache stores page pointers, not label
contents or a claim that the page is concrete.

If every page of a snapshot has a positive cached pointer, acquire only the
data spinlocks and copy the labels. A prepared store whose pages are all known
also commits using only data spinlocks. Cache entries do not replace those
locks.

Land an uncached implementation first for validation, then add this cache as
a separate implementation step. Both paths must have identical semantics.

### 5.3 Missing pages need protection through the copy

The safe cold-read path is:

1. Acquire all relevant directory mutexes in sorted order.
2. Resolve every page, recording positive pointers and absent pages.
3. Acquire all relevant data spinlocks in sorted order.
4. Copy present labels and supply zeros for absent pages.
5. Release data locks, then directory locks.

Retaining the directory mutexes through the copy prevents an absent page from
being inserted and committed while the reader combines it with another page.
A naive design that resolves absence, drops the directory lock, and later
copies other pages can produce a cross-page combination that never existed.

Clearing a range with absent pages uses the same rule. Skip the absent pieces
under the directory protection, while clearing present pieces under data
locks. A later page insertion is ordered after that clear.

Readers using positive cached pointers do not need directory protection because
those pages cannot disappear. Writers that publish pages release their
directory mutexes before taking data locks; a reader can legitimately observe
the newly published page while it is still all zero.

Two cold-path optimizations preserve this protocol. If every page is present,
release all directory mutexes before acquiring data locks: all resolved pointers
are stable. If every page is absent, a read can supply zeros while holding only
the directory mutexes, and a clear can return without taking data locks. No
page can appear while those mutexes are held. The mixed present/absent case
retains the full protocol above. These optimizations matter for workloads with
mostly concrete memory and must have the same race tests as the general path.

## 6 Internal APIs

Keep the storage API separate from expression-building helpers. Proposed names
are illustrative; the contracts are required.

```cpp
// Caller provides private storage; count is in application bytes/labels.
void shadow_snapshot(uintptr_t addr, size_t count, dfsan_label *out);
void shadow_commit(uintptr_t addr, size_t count, const dfsan_label *in);
void shadow_fill(uintptr_t addr, size_t count, dfsan_label label);
void shadow_copy(uintptr_t dst, uintptr_t src, size_t count);
void shadow_move(uintptr_t dst, uintptr_t src, size_t count);
bool shadow_is_concrete(uintptr_t addr, size_t count);
bool shadow_page_exists(uintptr_t addr);

// A bounded conditional update; comparison and replacement share the locks.
bool shadow_compare_commit(uintptr_t addr, size_t count,
                           const dfsan_label *expected,
                           const dfsan_label *replacement);

// No access to the directory or live shadow labels in these functions.
dfsan_label build_load_expression(const dfsan_label *labels, size_t count);
void build_store_labels(dfsan_label value, size_t count, u64 pc,
                        dfsan_label *out);
```

Define explicit contracts for scalar, coherent large-read, and bulk-write
behavior rather than letting helper names imply arbitrary-sized atomicity.
`shadow_compare_commit` is bounded; bulk add operations repeat it per window.
Every buffer allocation and address-range validation occurs before locks.

Validate `count * sizeof(dfsan_label)` and address-range arithmetic for overflow.
Use page-sized pieces computed from the current cursor and remaining count;
do not calculate the next page using the operation's ending address. Reject
unsupported expression widths before truncating them into the existing `u16`
size fields. Storage operations must not inherit expression-width limits.

## 7 Load and store algorithms

### 7.1 Load snapshot and expression construction

```cpp
dfsan_label dfsan_read_label(const void *addr, size_t n)
{
    if (n == 0)
        return CONST_LABEL;

    // Stack storage for supported small reads; checked allocation otherwise.
    LabelBuffer labels(n);
    shadow_snapshot((uintptr_t)addr, n, labels.data());
    return build_load_expression(labels.data(), n);
}
```

`build_load_expression` preserves the existing constant, raw-input `Load`,
`Extract` reconstruction, concatenation, and zero-extension behavior. Every
label access comes from the private array, including fast-path predicates.
It must not call `shadow_for`, create pages, or recover application addresses
from a shadow pointer. It may allocate expression nodes and emit telemetry
because it holds no storage locks.

The initial refactor preserves current expression semantics even where they
could be improved. For example, changing how mixed concrete bytes contribute
values to expressions is separate work: a label snapshot alone is not a
snapshot of concrete memory.

### 7.2 Store preparation and commit

```cpp
void dfsan_store_label(dfsan_label value, void *addr, size_t n, u64 pc)
{
    if (n == 0)
        return;

    LabelBuffer labels(n);
    build_store_labels(value, n, pc, labels.data());
    shadow_commit((uintptr_t)addr, n, labels.data());
}
```

Preparation handles all existing store cases: concrete zero, bounds labels,
single-byte input labels, decomposition of `Load`, general `Extract`, and the
initializing sentinel where the existing ABI allows it. It depends on the
incoming value label, not the current destination labels.

Commit ensures pages needed for nonzero output exist before acquiring data
spinlocks. It then acquires the full data-lock set for a scalar operation and
copies all labels. A mixed zero/nonzero output must also clear any existing
destination pages corresponding to zero portions. Pages absent from zero
portions require the protected-missing-page path in Section 5.3.

Page preparation publishes only zeros. Other readers may observe those zeros
before the commit; the store has not occurred yet. Concurrent creators recheck
directory membership and use the single winning page.

### 7.3 Fill and telemetry

`dfsan_set_label` assigns the same label to every byte; it does not perform the
bit extraction of `dfsan_store_label`. Keep these operations distinct.

If telemetry needs to report only changed bytes, allocate event storage before
locking and record changed positions/old labels during the copy. Format and
send events after releasing all locks. Process bulk operations in bounded
windows to avoid an unbounded event buffer. Event arrival order across threads
is not the shadow commit order unless an explicit sequence field is added.

Never call `telemetry_send`, `AOUT`, expression formatting, or arbitrary logging
from a data-lock critical section. Emit label-creation events only after the
corresponding metadata is initialized; the current union code's ordering also
needs review if consumers can inspect a label when its event arrives.

## 8 Read modify write operations

`dfsan_add_label` cannot use an unconditional snapshot/compute/commit sequence:
that would overwrite a concurrent update. Use optimistic validation:

```cpp
for (;;) {
    shadow_snapshot(addr, n, old_labels);
    build_added_labels(old_labels, added_label, op, pc, new_labels);
    if (shadow_compare_commit(addr, n, old_labels, new_labels))
        break;
    backoff_outside_storage_locks();
}
```

Page preparation for replacement labels occurs before conditional commit's
data locks. Absent pages compare as zero. Under the full lock set, compare all
expected labels and either replace all labels or change none. Zero-only
missing pieces still use directory protection.

Comparing labels is sufficient for this operation if its result is purely a
function of the expected labels and fixed arguments, with immutable metadata.
An intervening change from A to B and back to A does not invalidate applying
that function to A. Operations whose semantics depend on intervening events
must validate versions instead.

The loop guarantees atomic updates on successful return but is not wait-free
or starvation-free. Begin yielding after a small bounded number of retries,
outside all locks, and measure retry counts. Do not fall back to expression
construction under a spinlock. A future blocking admission scheme would have
to cover every overlapping writer; a mutex taken only by `dfsan_add_label`
would not provide that exclusion.

Failed attempts can leave unused immutable expression nodes in the monotonic
label table. Do not recycle their IDs. Measure this growth and include a
contention test before enabling heavy use of this path.

## 9 Large snapshots and concreteness queries

Maintain a 64-bit version in each data shard. Every commit that changes labels
increments each affected shard's version under that shard's data lock. All
writers, including fills, copies, clears, conditional commits, and compatibility
wrappers, participate. Unchanged writes can skip increments. Zero-only page
publication does not change the logical labels and needs no increment.

An internal window-copy primitive acquires the necessary locks once and copies
at most `kShadowCopyWindowBytes` (initially 4096) application bytes. It does not
invoke version validation recursively. A coherent read that fits in one such
window can use that primitive directly, including the current 1024-byte
concreteness probes. The scalar atomicity guarantee is a minimum; this bounded
path provides the stronger guarantee for a whole window as well.

For a coherent read larger than one copy window:

1. Compute the unique shard set for the entire range outside locks.
2. Read each shard's version under its data lock, completing this pass before
   copying any labels.
3. Copy the range in bounded windows using that internal locked primitive.
4. After all copies finish, reread each version under its data lock.
5. Accept the private buffer only if every version matches; otherwise retry.

Matching versions show there were no changes in the covered shards throughout
the copy pass. Each shard's validation interval encloses that whole pass, even
though the version reads themselves are not simultaneous. Unrelated writes in
a colliding shard cause retries, not incorrect results. Version reads are
locked; this is not a seqlock allowing data races on ordinary label memory.

Version wrap must never make a changed range appear unchanged. Detect exhaustion
before wrapping and use a defined fatal diagnostic outside locks, or implement
a separately tested quiescent reset. Silent wrap is forbidden.

`shadow_is_concrete` uses one locked scan for regions fitting in a window and
validated window scans for larger ones. Finding a nonzero label can return false
immediately; returning true requires successful validation. It can scan without
allocating a full-range label buffer by retaining only versions and a bounded
window buffer. Under continuous writes a coherent large read may retry
indefinitely; callers requiring bounded inspection latency should pause guest
execution using the existing control mechanism.

A successful concrete query describes a past instant. It does not keep the
region concrete. Any user-TLB or translation optimization that caches the
result must have its own invalidation protocol; shadow locking does not supply
one automatically.

## 10 Bulk copy and direct pointer callers

`shadow_copy` snapshots a bounded source window, releases its locks, then
commits that private buffer to the destination. It does not hold source locks
while allocating destination pages. Source-read and destination-write phases
are separate operations, consistent with the bulk-copy contract.

`shadow_move` handles overlap by choosing the same forward/backward direction
as `memmove` and fully snapshotting each source window before overwriting any
part of that window. Compute overlapping ranges without integer overflow.
Small moves can snapshot the entire source into the stack buffer. Replace the
current unbounded variable-length stack array.

Do not expose a pointer to mutable label storage from the new public API.
`shadow_for()` returning a stable page address is not sufficient: every
dereference must still hold the appropriate data lock. Restrict any remaining
raw access to private locked helpers with a documented guard requirement.

Migrate direct accesses in `dfsan_custom.cpp`, including `memcpy`, `memmove`,
string copies, formatted-output label copying, allocation clears, and realloc
label copies. Reachability in today's system binary is not a reason to leave
an exported runtime entry point with an unsafe implementation.

The declaration of `dfsan_shadow_for` in the public header must be audited
against actual definitions and external consumers. Do not claim a synchronized
raw-pointer interface. If compatibility requires it, explicitly restrict it to
quiescent inspection and keep concurrent runtime code off that interface.

## 11 Expression metadata and compiler compatibility

### 11.1 Metadata publication is a prerequisite

A snapshot contains IDs, not copies of the expression DAG. The following must
hold for expression construction after releasing shadow locks:

- Published expression metadata is fully initialized and remains valid.
- IDs are not reused while snapshots can reference them.
- Metadata is immutable, or mutations have independent synchronization.
- All non-shadow handoffs of IDs use a valid publication mechanism.

The current union hash table uses atomic bucket publication, and its allocator
uses an atomic allocation cursor. Preserve those mechanisms and test their
interaction with parallel expression construction. Concurrent duplicate
expressions may receive different IDs; compare structural semantics in tests
unless uniqueness is explicitly guaranteed.

The global label counter advances before all metadata is initialized. Reading
that counter is not proof that every lower label is ready. Live RPC enumeration
needs a pause or an independent ready/publication protocol.

Bounds tracing violates a blanket immutability assumption today: allocation
metadata can be changed from `Alloca` to `Free` in custom wrappers, and stack
allocation metadata has global mutable state. Parallel bounds tracing must
remain unsupported until those paths gain a separate safe lifetime design.
Normal immutable expression support must not silently imply bounds support.

Audit concurrent expression diagnostics as well: static scratch buffers such
as unknown-operation name buffers must become thread-local or caller-owned if
they are reachable concurrently. Storage locks intentionally do not serialize
these functions.

### 11.2 Runtime helper ABI

Keep `dfsan_read_label`, `dfsan_store_label`, and `dfsan_set_label` callable by
existing SymFit helpers. Introduce new internal expression-only functions;
do not simply change an exported `__taint_union_*` signature to take a snapshot.

Audit both public and private headers. For example, `dfsan_add_label` currently
has different parameter lists in the public interface and private header.
Resolve callers and declarations together; do not use a prototype mismatch as
an implicit compatibility shim.

The compiler instrumentation in
[TaintPass.cpp](../symsan/instrumentation/TaintPass.cpp) currently derives direct
shadow addresses, emits direct zero-label stores and memory transfers, and
declares union helper signatures that differ from the application-address
helpers in this runtime source. The storage change must not assume those
compiler paths already obey the SymFit runtime ABI.

For compiler-generated code supported with this sparse runtime, change the
pass to call address-based runtime operations, including zero stores and memory
intrinsics, and make declarations match definitions. Rebuild instrumented
artifacts. Old direct-shadow instrumentation cannot be made safe merely by
locking the called union helpers. If that compiler integration ships separately,
state that the first release covers SymFit runtime callers only and explicitly
exclude old instrumented artifacts from concurrency support.

## 12 Initialization and process lifecycle

Use the bundled sanitizer mutex primitives rather than introducing a new
dependency on `std::mutex`. Verify constant/linker initialization for locks and
explicit initialization for maps and caches before the first shadow API call.
The runtime has a `.preinit_array` initializer, so ordinary C++ constructor
ordering must not be assumed to precede every runtime action.

Keep the storage implementation uninstrumented. Allocation and telemetry must
not recursively invoke it while its locks are held. Signal handlers must not
perform shadow operations; a spinlock is not async-signal-safe.

User-mode fork needs hooks coordinated with `fork_start`/`fork_end` in
[linux-user/main.c](../linux-user/main.c). Before the host fork, quiesce writers
and acquire all directory mutexes followed by all data locks in the standard
order. In the parent, release in reverse order. In the child, establish valid
child-owned mutex state using the supported sanitizer mutex lifecycle, clear
thread-local caches, and retain the inherited page directory and labels.
Do not merely reset locks in a child that may have inherited a half-mutated
map. Verify the ordering against QEMU's exclusive, mmap, CPU-list, and allocator
fork locks. The shadow hooks must not call back into those subsystems.

The fork freeze is an explicit lifecycle exception to the short-copy lock
duration: it occurs only after quiescing runtime users and must not run shadow
callbacks. Audit registered host atfork handlers as part of its lock-order
review. Do not reuse this mechanism for ordinary memory operations.

No storage guard crosses a guest memory access, QEMU exception, `longjmp`,
callback, or return to generated code. RAII cleanup does not run on `longjmp`;
keeping guards entirely inside ordinary storage operations is essential.

Process teardown may leave grow-only page storage to the operating system.
Any explicit destruction must occur after all users stop. A future reset,
snapshot restore, or page reclamation feature requires cache invalidation and
a new lifetime protocol before it can erase directory entries.

## 13 Implementation sequence

### Step 1 Establish semantic and caller baselines

Inventory every shadow-pointer dereference and exported entry point. Add
single-thread semantic cases for current valid load/store behavior, recording
structural expressions rather than incidental label IDs. Add failing cases
for the page-boundary defects described in Section 2.

Confirm the supported concurrent profile, especially bounds tracing, compiler
instrumentation, live label enumeration, and fork behavior. Keep unsupported
profiles explicit rather than hiding them behind the new storage lock.

### Step 2 Extract pure expression transformations

Move load assembly and store decomposition into helpers operating only on
private label arrays. Preserve externally visible signatures through wrappers.
Validate constants, input loads, extracts, extensions, PC attribution, and
sentinel handling before introducing concurrency.

### Step 3 Introduce synchronized storage

Add sharded directories, data locks, page lifetime rules, range iteration,
bounded snapshots and commits, and version counters. Begin without the lookup
cache. Migrate the normal read/store/set/query APIs in the same change so no
unlocked public path races with the new paths.

### Step 4 Close bypasses and lifecycle gaps

Migrate custom copy/clear callers and conditional add operations. Implement
validated large reads and overlap-safe moves. Wire fork hooks and audit
initialization. Resolve compiler ABI support or explicitly delimit the release
profile before claiming coverage.

### Step 5 Add the positive lookup cache

Add the bounded thread-local cache without changing storage semantics. Compare
cached and uncached runs, including concurrent first publication and deliberately
colliding addresses. Keep a test configuration that disables the cache.

### Step 6 Integrate and measure

Rebuild the runtime and all supported SymFit targets. Run storage concurrency
tests, expression regressions, existing system/user smoke tests, and focused
MTTCG workloads. Report shadow-storage results separately from known
concrete/shadow pairing and global execution-mode limitations.

## 14 Validation plan

### 14.1 Deterministic correctness tests

Create a standalone storage test target under `symsan/tests/` with build wiring
that can instrument the storage component independently. Add test-only barriers
outside production critical sections to control publication and retry races.

| Test | Required observation |
| --- | --- |
| Concurrent creation of one page | Exactly one page is published; writes to disjoint offsets survive; losing candidates are freed |
| Different pages and shards | Independent progress without shared map corruption |
| Different pages in one shard | Correct serialization and no duplicate lock acquisition |
| Repeated scalar A/B stores with readers | Every snapshot equals a complete A or B pattern, never a mixture |
| Cross-page scalar A/B stores | Same guarantee for distinct shards and for shard collisions |
| Opposite-direction cross-page operations | Finish without a lock-order deadlock |
| Absent first page and symbolic second page | Reads detect taint and clears reach the second page |
| Missing-page publication during a read | The read obeys the protected-absence protocol |
| Exact page endings and multiple pages | Correct offsets with no adjacent-allocation assumption |
| Zero-size and arithmetic overflow | No underflow, wrapped address, allocation overflow, or out-of-bounds access |
| Concurrent `add_label` and stores | Failed validation retries; successful update never overwrites an unobserved value |
| Forced validation failures | Backoff occurs outside locks; abandoned nodes are measured |
| Large read while labels move between windows | Validation prevents a false all-concrete result |
| Overlapping moves in both directions | Labels match `memmove` semantics across windows |
| Copy or clear of missing pages | Zero semantics and no unnecessary shadow-page allocation |
| Warm cache with concurrent writes | Cached pointers never bypass label locks |
| Fork during activity | Child and parent continue without inherited-lock deadlock or map corruption |

Add an instrumented allocator/telemetry test hook that fails if allocation,
expression construction, or event emission occurs while a data lock is held.
Use a debug thread-local lock-depth counter; do not add global counters to the
release hot path. Exercise constructor/startup and allocation-failure paths.

### 14.2 Sanitizers and expression tests

Run the standalone storage tests under ThreadSanitizer and AddressSanitizer in
separate builds. Ensure the selected mutex implementation is visible to TSan;
if sanitizer internals require a test adapter or annotations, document exactly
what is tested. The full runtime reserves fixed virtual address ranges that
may conflict with sanitizer runtimes, so a standalone pass is not evidence
that the entire SymFit process is race-free.

Expression tests should cover load/store round trips for 1, 2, 4, and 8 bytes,
unaligned accesses, raw input runs, `Extract` recombination, mixed symbolic and
zero bytes, extensions, and page boundaries. Compare valid cases with the
baseline. Test corrected boundary cases against their intended byte semantics.
Run parallel expression construction separately from storage tests to expose
metadata or diagnostic races that shadow locks cannot fix.

### 14.3 Integration checks

Use the existing build workflow in [build.sh](../build.sh) and existing
[system smoke tests](../tests/symfit/system/run_symfit_system_smoke.sh), plus the
relevant interactive expression and symbolic-memory tests. Record exact build
and invocation commands with the implementation results.

Add a focused multi-vCPU guest workload that actually starts and executes work
on all requested vCPUs. Merely launching with `-smp` is insufficient. Cover
disjoint pages, shared pages, synchronized symbolic handoff, concrete clears,
and cross-page labels with 1, 2, 4, and 8 vCPUs where supported. Shared concrete
memory tests must distinguish expected concrete/shadow pairing failures from
storage failures; the standalone tests provide the isolated storage oracle.

### 14.4 Performance experiments

Measure the following configurations with the same workload and host affinity:

- Existing runtime as a single-thread performance reference; its concurrent
  results are not a correctness baseline.
- New storage with lookup cache disabled and enabled.
- Several shard counts and bulk-window sizes.
- One thread, several threads on disjoint pages, one shared page, deliberate
  shard collisions, cold first touches, and mostly concrete memory.
- Storage-only copies and full expression-producing operations separately.

Record operations per second, median and tail latency, data-lock hold time,
contention, directory misses, cache hit rate, retry counts, and memory growth.
Collect detailed counters only in benchmark builds and aggregate per-thread
data after execution. Set a single-vCPU regression budget from these measured
baselines before accepting tuning changes. Do not promise a particular speedup
or nanosecond lock cost in advance.

## 15 Acceptance criteria and remaining work

The storage implementation is ready when all supported callers use its APIs;
deterministic and sanitizer tests pass; scalar range operations are coherent;
large coherent queries validate versions; and the data-lock instrumentation
finds no allocation, expression construction, callbacks, or telemetry inside
critical sections. Initialization, fork, zero clears, and missing-page behavior
must be covered, not left as assumptions.

Performance acceptance requires reported measurements and an agreed regression
budget. Correctness must not depend on the positive lookup cache, shard count,
or a particular host scheduling pattern.

Separate follow-up work remains for concrete/shadow pairing, guest atomics,
device writers, cached concreteness invalidation, bounds metadata lifetime,
and shared execution state such as `second_ccache_flag` and symbolic-load
metadata. These limitations should accompany the implementation's release
notes so shadow-memory safety is not confused with complete parallel symbolic
execution support.
