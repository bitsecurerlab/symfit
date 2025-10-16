# Build Compatibility Patches for Ubuntu 22.04

This directory contains patches to fix build issues on Ubuntu 22.04 with modern toolchains.

## Patches

### 1. `symcc-llvm14-compat.patch`
Fixes LLVM 14 API compatibility issues in SymCC's QEMU backend.

**Changes:**
- Updates `APInt::toString()` calls to use the new LLVM 14 API
- Adds `#include <llvm/ADT/SmallString.h>` headers
- Affects: expr.h, range.h, expr.cpp in qsym backend

**Root Cause:** LLVM 14 changed `APInt::toString()` from returning a string to taking a `SmallVectorImpl<char>&` parameter.

### 2. `symsan-ubuntu22-compat.patch`
Fixes multiple compatibility issues in Symsan for Ubuntu 22.04.

**Changes:**
- Replaces deprecated glibc 2.33+ functions (`__xstat`, `__fxstat`, `__lxstat`)
- Switches from `libc++` to `libstdc++` to avoid libunwind linking issues
- Affects: dfsan_custom.cpp, solvers/CMakeLists.txt, driver/CMakeLists.txt

**Root Cause:** glibc 2.33+ removed the `__xstat` family of functions, and libc++ requires libunwind which isn't always properly installed.

## How to Apply

### Option 1: Manual Application (Recommended)

```bash
cd /path/to/symfit

# Apply SymCC patch
cd external/symcc
git apply ../../patches/symcc-llvm14-compat.patch

# Apply Symsan patch
cd ../symsan
git apply ../../patches/symsan-ubuntu22-compat.patch

# Return to root
cd ../..
```

### Option 2: Automated (add to build.sh)

Add this function to `build.sh` before the build steps:

```bash
apply_patches() {
  log "Applying compatibility patches..."

  if [ -f patches/symcc-llvm14-compat.patch ]; then
    cd "$SYMCC_SRC"
    if ! git apply --check ../../patches/symcc-llvm14-compat.patch 2>/dev/null; then
      log "SymCC patch already applied or conflicts exist"
    else
      git apply ../../patches/symcc-llvm14-compat.patch
      log "Applied SymCC LLVM 14 compatibility patch"
    fi
    cd "$ROOT"
  fi

  if [ -f patches/symsan-ubuntu22-compat.patch ]; then
    cd "$SYMSAN_SRC"
    if ! git apply --check ../../patches/symsan-ubuntu22-compat.patch 2>/dev/null; then
      log "Symsan patch already applied or conflicts exist"
    else
      git apply ../../patches/symsan-ubuntu22-compat.patch
      log "Applied Symsan Ubuntu 22.04 compatibility patch"
    fi
    cd "$ROOT"
  fi
}

# Call before building
apply_patches
```

## Reverting Patches

To revert the patches:

```bash
# Revert SymCC patch
cd external/symcc
git apply -R ../../patches/symcc-llvm14-compat.patch

# Revert Symsan patch
cd ../symsan
git apply -R ../../patches/symsan-ubuntu22-compat.patch
```

Or simply reset the submodules:

```bash
cd external/symcc && git checkout . && cd ../..
cd external/symsan && git checkout . && cd ../..
```

## Testing

After applying patches, verify the build works:

```bash
./build.sh
```

Expected output should end with:
```
[build] Done.
```

Verify artifacts are created:
```bash
ls -lh build/symfit-symsan/x86_64-linux-user/symqemu-x86_64
ls -lh build/symcc/symcc
ls -lh build/symsan/lib/symsan/libdfsan_rt-x86_64.a
```

## System Requirements

These patches are tested on:
- **OS:** Ubuntu 22.04 LTS
- **Compiler:** clang-12, gcc-11
- **LLVM:** 14.0.0
- **glibc:** 2.35+

## Upstreaming

These patches can potentially be submitted upstream to:
- SymCC: https://github.com/eurecom-s3/symcc
- Symsan: https://github.com/R-Fuzz/symsan

Consider creating pull requests if you'd like to contribute these fixes back to the community.
