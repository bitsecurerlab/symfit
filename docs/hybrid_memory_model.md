# SymFit Hybrid Memory Model

## Design Draft v1

Status: proposed object-aware memory model, not an implemented capability.
The views and guarantees below describe this design's intended behavior.
Current SymFit runtime behavior and available RPC operations are documented in
[the interactive contract](interactive_scripting_contract.md); SMP control
regressions do not establish this proposal's symbolic-memory guarantees.

### Object-Aware Symbolic Memory with Byte-Accurate Fallback

## 1. Goal

Add support for symbolic memory addresses without replacing Symsan's existing
byte-level model.

The system should preserve structured pointer/object semantics when possible,
while always remaining correct under the existing byte-shadow semantics.

## 2. Core Design Principle

Every memory operation maintains two views at the same time:

- Byte view
  - canonical
  - always updated
  - always safe
- Object view
  - auxiliary
  - best-effort
  - may degrade at any time without affecting correctness

Byte semantics are authoritative. Object semantics never override them.

## 3. High-Level Architecture

```text
                   +----------------------+
                   |   Label DAG          |
                   | dfsan_label_info     |
                   | byte-level semantics |
                   +----------+-----------+
                              |
                +-------------+-------------+
                |                           |
     +----------------------+     +----------------------+
     | Byte Shadow Memory   |     | Object Metadata      |
     | addr -> dfsan_label  |     | label -> ObjView     |
     +----------------------+     +----------------------+
                                              |
                                   +----------+----------+
                                   | Object Store        |
                                   | object_id -> regions|
                                   +----------+----------+
                                              |
                                   +----------+----------+
                                   | Object Table        |
                                   | object_id -> state  |
                                   +---------------------+
```

## 4. Non-Goals

This design does not attempt to:

- replace `dfsan_label_info`
- change the union-table layout or hashing ABI
- make object semantics mandatory for execution
- guarantee precise pointer reasoning after arbitrary transformations

## 5. Ownership Split

### Symsan responsibilities

- maintain byte-accurate symbolic execution
- maintain side-table object metadata for labels
- maintain object store overlay
- propagate/degrade object views through operations
- use object-aware load/store logic when possible

### SymFit responsibilities

- observe execution events
- identify object creation and object lifetime
- create pointer provenance from runtime observations
- notify Symsan about:
  - object creation
  - object retirement
  - pointer-producing events

This means pointer provenance is injected from SymFit, not inferred from raw
DFSan labels alone.

## 6. Existing Byte Model

Unchanged:

```c
byte_shadow[address] = dfsan_label;
```

All loads/stores still succeed through this mechanism even if object semantics
are unavailable.

## 7. New Side Tables

### 7.1 Label Object Metadata

Object semantics are stored outside `dfsan_label_info`.

```c
enum ObjViewKind {
    OV_NONE,   // definitely no structured object meaning
    OV_PTR,    // structured pointer meaning
    OV_TOP     // pointer-like meaning existed but was degraded
};

enum ProvenanceKind {
    PV_PRECISE,
    PV_MERGED,
    PV_DEGRADED
};

struct PtrView {
    SmallObjSet objs;      // candidate object ids
    dfsan_label offset;    // symbolic offset label, or 0 for concrete-only
    int64_t concrete_offset;
    ProvenanceKind prov;
};

struct ObjView {
    ObjViewKind kind;
    union {
        PtrView ptr;
    };
};
```

Main table:

```c
label_objview[label] = ObjView
```

### 7.2 Object Table

Tracks logical objects observed by SymFit.

```c
enum ObjectKind {
    OBJ_STACK,
    OBJ_HEAP,
    OBJ_GLOBAL,
    OBJ_UNKNOWN
};

enum ObjectStateKind {
    OS_LIVE,
    OS_RETIRED
};

struct ObjectState {
    uint64_t object_id;
    uint64_t base_addr;
    uint64_t size;
    ObjectKind kind;
    ObjectStateKind state;
};
```

Main table:

```c
object_table[object_id] = ObjectState
```

### 7.3 Object Store

Overlay for structured memory contents.

```c
enum RegionStateKind {
    RS_STRUCTURED,
    RS_DEGRADED,
    RS_UNKNOWN
};

struct StoredValue {
    dfsan_label value_label;
    uint32_t bit_width;
};

struct RegionEntry {
    uint64_t start_offset;
    uint64_t end_offset;
    StoredValue value;
    RegionStateKind state;
};
```

Main structure:

```c
object_store[object_id] = interval_map<offset_range, RegionEntry>
```

## 8. API Between SymFit and Symsan

This is the intended integration boundary.

### Object lifecycle

```c
register_object(object_id, base_addr, size, kind)
retire_object(object_id)
```

### Pointer provenance injection

```c
assign_pointer_view(label, object_id, concrete_offset, offset_label, provenance)
assign_pointer_view_multi(label, object_ids[], concrete_offset, offset_label, provenance)
clear_pointer_view(label)
```

The exact API shape can change, but the model is:

- SymFit tells Symsan which labels represent structured pointers
- Symsan propagates that metadata after that point

## 9. Meaning of ObjView States

### `OV_NONE`

This label is treated as an ordinary bitvector with no object interpretation.

### `OV_PTR`

This label has structured pointer meaning:

- candidate object set
- symbolic or concrete offset
- provenance quality

### `OV_TOP`

This label may have originated from a pointer, but the analysis lost enough
structure that it can no longer safely reason about it as one.

This distinction matters:

- `OV_NONE` means "not a pointer"
- `OV_TOP` means "pointer semantics degraded"

## 10. Pointer Lifecycle

```text
precise -> merged -> degraded -> TOP
```

Typical triggers:

- path merge
- candidate object-set widening
- pointer mixed with unsupported arithmetic
- partial overwrite in memory
- conflicting structured and byte writes

## 11. Operation Semantics

Byte semantics remain unchanged. The rules below define only object-view
propagation.

### 11.1 Copy-like ops

Examples:

- bit-preserving move
- phi with identical incoming pointer views
- load from object store

Rule:

```c
result.obj_view = input.obj_view;
```

### 11.2 Add

| A | B | Result |
|---|---|---|
| PTR | BV | PTR(offset + B) |
| BV | PTR | PTR(offset + A) |
| PTR | PTR | OV_TOP |
| BV | BV | OV_NONE |

Constraints:

- width must match pointer width
- integer operand is interpreted as byte offset
- no source-level scaling semantics are assumed in v1

### 11.3 Sub

| A | B | Result |
|---|---|---|
| PTR | BV | PTR(offset - B) |
| PTR | PTR | OV_TOP |
| BV | BV | OV_NONE |

### 11.4 Casts

- `bitcast(ptr)` preserves `OV_PTR`
- width-preserving casts may preserve `OV_PTR`
- truncation of pointer width => `OV_TOP`
- extension from full-width pointer may preserve `OV_PTR`
- unsupported casts => `OV_TOP`

### 11.5 Extract

- extracting the full pointer-width slice may preserve `OV_PTR`
- partial extraction => `OV_TOP`

### 11.6 Concat

Default:

- result => `OV_TOP` if any operand was pointer-like

Optional future extension:

- reconstruct pointer if concat exactly reassembles a previously lowered pointer

v1 should not rely on concat reconstruction.

### 11.7 Bitwise / nonlinear ops

Examples:

- `and`, `or`, `xor`
- `mul`, `div`, `rem`
- shifts used on pointer values

Default:

```c
result.obj_view = OV_TOP;
```

This is conservative and should be the initial implementation.

### 11.8 Phi / Merge

If incoming pointer views are compatible:

- union object sets
- merge offset expressions if representable
- downgrade provenance to `PV_MERGED`

Otherwise:

- `OV_TOP`

Compatibility in v1 should be strict.

## 12. Load Semantics

### 12.1 Always perform byte load

Current logic remains authoritative:

- read byte shadow
- reconstruct DFSan label as today

This result is always available.

### 12.2 Attempt object-aware load

Object-aware load is attempted only if the address label has `OV_PTR`.

The engine:

1. reads address `ObjView`
2. enumerates candidate objects
3. resolves object-store location using object id + offset
4. checks region validity and width compatibility
5. if successful, returns structured stored label

### 12.3 Success conditions

Structured object-store load succeeds only if:

- address view is `OV_PTR`
- candidate object set is below a small cutoff
- selected object is live
- target region exists
- region state is `RS_STRUCTURED`
- requested width matches stored value width
- offset matching is exact or simple-affine in the supported form

### 12.4 Failure path

If any condition fails:

- return normal byte-level reconstructed label
- result object view becomes:
  - `OV_NONE` if no pointer meaning is recovered
  - possibly `OV_TOP` if the address was pointer-like but load recovery failed
    due to degradation

### 12.5 Result propagation

If structured load succeeds:

```c
result_label = stored_value.value_label;
result_obj_view = label_objview[result_label];
```

This is how spilled pointers recover their structured semantics.

## 13. Store Semantics

### 13.1 Always update byte shadow

This remains mandatory and canonical.

### 13.2 Attempt object-store update

If the destination address label has `OV_PTR`, attempt structured store into
object store.

Structured store succeeds only if:

- destination pointer resolves to a live object
- object candidate set is small enough
- offset is representable
- store width is supported
- overlapping region state permits replacement

On success:

```c
object_store[object_id][offset_range] = StoredValue{label, width}
state = RS_STRUCTURED
```

### 13.3 Degradation on writes

Degrade affected region if:

- partial overwrite of existing structured region
- overlapping byte-level store that cannot be represented structurally
- multi-object ambiguity
- unsupported offset form
- width mismatch against existing structured slot
- unknown external write

Then:

```c
region.state = RS_DEGRADED;
```

Byte semantics still remain correct.

## 14. Spilled Pointer Recovery

This is the main reason for the object store.

### Store path

A pointer-valued label with `OV_PTR` is written through a structured destination
pointer:

- byte shadow is updated
- object store records the stored label in the target object region

### Load path

Later, the same memory is loaded through a structured pointer:

- byte load is still available
- object-store lookup returns the original stored label if region state is
  still structured

Result:

- the loaded value regains the original `OV_PTR`

This is the intended mechanism for preserving pointer semantics across spills.

## 15. Degradation Rules

### 15.1 Value-level degradation

Set label view to `OV_TOP` when:

- pointer-pointer arithmetic occurs
- pointer goes through unsupported bitwise ops
- pointer width is partially truncated/extracted
- incompatible merge occurs

### 15.2 Region-level degradation

Set region state to `RS_DEGRADED` when:

- partial overwrite occurs
- overlapping store conflicts
- store target cannot be resolved precisely enough
- raw byte writes destroy structured interpretation

### 15.3 Recovery

In v1:

- degraded values do not recover automatically
- degraded regions do not recover automatically
- only explicit structured stores create fresh structured region entries again

## 16. Aliasing Policy

v1 should be strict.

If an address has multiple candidate objects:

- structured load/store is allowed only if all candidates agree in a trivially
  compatible way
- otherwise degrade or fall back

Initial recommendation:

- exact single-object match required for writes
- loads may allow very small candidate sets later, but not in the first
  implementation

## 17. Offset Model

v1 uses byte offsets only.

That means:

- no source-level field modeling
- no typed GEP semantics
- no element scaling semantics
- all pointer arithmetic is interpreted in bytes

This keeps the runtime model simple and aligned with actual memory layout.

## 18. Invariants

1. Byte shadow is always correct.
2. Object view never replaces byte semantics.
3. Object-store lookup is optional.
4. Any operation must still succeed when object metadata is absent.
5. Degradation never breaks execution.
6. Side tables may lose precision, but must never introduce unsound byte
   behavior.

## 19. Expected Benefits

This design should improve:

- symbolic reasoning over spilled/reloaded pointers
- address-aware load modeling
- memory-structure preservation across stack and heap accesses
- symbolic execution quality for pointer-heavy code

while preserving:

- existing Symsan execution
- current solver behavior as fallback
- robustness under unsupported cases

## 20. Known Open Questions

1. Should object-store entries require exact offset match, or support simple
   symbolic offset normalization?
2. How should stack objects be retired across frame unwinding in SymFit?
3. Do we want globals in v1, or only stack + heap?
4. Should object-store loads require a unique object candidate, or allow tiny
   compatible sets?
5. How should external/uninstrumented writes invalidate object-store regions?
6. Should pointer reconstruction from byte concat be postponed entirely to v2?

## 21. Suggested Implementation Order

### Phase 1

- add `label -> ObjView` side table
- add `object_id -> ObjectState`
- add integration API from SymFit

### Phase 2

- create pointer provenance from SymFit events
- propagate object views through simple ops:
  - copy
  - add
  - sub
  - casts
  - merge

### Phase 3

- add object store
- implement structured store path

### Phase 4

- implement structured load path
- support spilled pointer recovery

### Phase 5

- add degradation handling
- add strict aliasing policy
- refine solver integration if needed

## 22. One-Sentence Summary

SymFit and Symsan keep the existing byte-accurate symbolic memory model as the
source of truth, while adding a side-table object model and object-store
overlay that preserve structured pointer semantics across memory operations when
possible and degrade safely when not.
