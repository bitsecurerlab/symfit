# Patch Summary

## Overview
This directory contains patches to make SymFit buildable on Ubuntu 22.04 with LLVM 14 and glibc 2.35+.

## Files

- **`symcc-llvm14-compat.patch`** (84 lines)
  - Fixes LLVM 14 API compatibility in SymCC's qsym backend

- **`symsan-ubuntu22-compat.patch`** (59 lines)
  - Fixes glibc 2.33+ and toolchain compatibility in Symsan

- **`README.md`** - Detailed documentation
- **`apply-patches.sh`** - Automated patch application script
- **`PATCH_SUMMARY.md`** - This file

## Quick Start

### Apply Patches
```bash
cd /path/to/symfit
./patches/apply-patches.sh
```

### Build
```bash
./build.sh
```

### Verify
```bash
ls -lh build/symfit-symsan/x86_64-linux-user/symqemu-x86_64
ls -lh build/symcc/symcc
ls -lh build/symsan/lib/symsan/libdfsan_rt-x86_64.a
```

## Detailed Changes

### SymCC Patch (external/symcc/runtime/qsym_backend/qsym/)

**Files Modified:**
1. `qsym/pintool/expr.h`
2. `qsym/pintool/third_party/llvm/range.h`
3. `qsym/pintool/codegen/expr.cpp`

**Changes:**
- Added `#include <llvm/ADT/SmallString.h>` to all three files
- Replaced `value.toString(radix, signed)` with:
  ```cpp
  llvm::SmallString<64> Str;
  value.toString(Str, radix, signed, uppercase);
  // Use Str.c_str()
  ```

**Reason:** LLVM 14 changed `APInt::toString()` API from returning a string to using an output parameter.

### Symsan Patch (external/symsan/)

**Files Modified:**
1. `runtime/dfsan/dfsan_custom.cpp`
2. `driver/CMakeLists.txt`
3. `solvers/CMakeLists.txt`

**Changes:**

*dfsan_custom.cpp:*
- Line 89: `__xstat(vers, path, buf)` → `stat(path, buf)`
- Line 117: `__fxstat(vers, fd, buf)` → `fstat(fd, buf)`
- Line 144: `__lxstat(vers, path, buf)` → `lstat(path, buf)`

*CMakeLists.txt (both):*
- Removed `-stdlib=libc++` flag
- Added comment explaining the change

**Reason:**
- glibc 2.33+ removed `__xstat` family functions
- `libc++` dependency on libunwind causes linking issues; `libstdc++` works better

## Testing Status

✅ **Tested on:**
- Ubuntu 22.04.3 LTS
- clang-12, gcc-11
- LLVM 14.0.0
- glibc 2.35

✅ **Build artifacts verified:**
- symqemu-x86_64 (23 MB)
- symcc wrapper script
- libdfsan_rt-x86_64.a (2.4 MB)

## Reverting

To revert all patches:
```bash
cd external/symcc/runtime/qsym_backend/qsym
git checkout .

cd ../../../symsan
git checkout .
```

## Committing to Repository

Add patches to your SymFit repository:

```bash
git add patches/
git commit -m "Add compatibility patches for Ubuntu 22.04

- Fix LLVM 14 API compatibility in SymCC
- Fix glibc 2.33+ compatibility in Symsan
- Switch to libstdc++ to avoid libunwind issues

These patches enable building on Ubuntu 22.04 with modern toolchains."
```

## Future Considerations

1. **Upstreaming**: Consider submitting these fixes upstream to SymCC and Symsan projects
2. **Automation**: The patches are already applied in your working tree. Future clones will need to apply them.
3. **CI/CD**: Add patch application to your build pipeline
4. **Documentation**: Update main README to mention Ubuntu 22.04 compatibility

## Support

If you encounter issues:
1. Check that submodules are at the correct commit
2. Ensure patches apply cleanly with `git apply --check`
3. Verify no conflicts with other modifications
4. See `patches/README.md` for detailed troubleshooting
