[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# SymSan: Time and Space Efficient Concolic Execution via Dynamic Data-Flow Analysis

SymSan (Symbolic Sanitizer) is an efficient concolic execution engine based on the
Data-Flow Sanitizer (DFSan) framework. By modeling forward symbolic execution as
a dynamic data-flow analysis and leveraging the time and space efficient data-flow
tracking infrastructure from DFSan, SymSan imposes much lower runtime overhead
than previous symbolic execution engines.

Similar to other compilation-based symbolic executor like [SymCC](https://github.com/eurecom-s3/symcc),
SymSan uses compile-time `instrumentation` to insert symbolic execution logic into
the target program, and a `runtime` supporting library to maintain symbolic states
during execution.

To learn more, checkout our [paper](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-ju) at USENIX Security 2022.

## Building

Because SymSan leverages the shadow memory implementation from LLVM's sanitizers,
it has more strict dependency on the LLVM version. Right now only LLVM 12 is
tested.

### Build Requirements

- Linux-amd64 (Tested on Ubuntu 20.04)
- [LLVM 12.0.1](http://llvm.org/docs/index.html): clang, libc++, libc++abi

### Compilation

Create a `build` directory and execute the following commands in it:

```shell
$ CC=clang-12 CXX=clang++-12 cmake -DCMAKE_INSTALL_PREFIX=/path/to/install -DCMAKE_BUILD_TYPE=Release /path/to/symsan/source
$ make
$ make install
```

### Build in Docker

From `symsan/`, build the standalone image with `docker build -t symsan .`.
The old `check.sh` expects a historical test-directory layout; use the lit
suite below to validate the current checkout.

To produce a reusable `install/` tree (binaries, libs, headers) for downstream
projects:

```shell
./scripts/export_install_from_docker.sh
```

Set `SYMSAN_DOCKER_IMAGE` to override the default image tag (`symsan-build:local`).

### LIBCXX

Instrumented libc++, libc++abi, and libunwind archives are optional generated
artifacts; they are not shipped in this checkout or built by the root
`build.sh`. To build them, follow `libcxx/rebuild.sh` from `symsan/libcxx/`,
passing the installed `ko-clang` path. CMake installs archives already present
in `libcxx/build_taint/lib/` when the Symsan install step is run again.

**NOTE**: because the in-process solving module (`solvers/z3.cpp`) uses Z3's C++ API
and STL containers, so itself depends on the C++ libs. Due to such dependencies,
you'll see linking errors when building C++ targets when using this module.
Though it's possible to resolve these errors by not instrumenting the dependencies
(adding them to the [ABIList](https://clang.llvm.org/docs/DataFlowSanitizer.html#abi-list),
 then rebuild the C++ libs), we don't recommend using it for C++ targets.
Instead, it's much cleaner to use an out-of-process solving module like Fastgen.

When using an extracted LLVM toolchain, put its `bin/` on `PATH` and ensure
its shared libraries are discoverable by the dynamic loader (for example via
`LD_LIBRARY_PATH`). The compiler and LLVM headers must both come from LLVM 12.

## Test

To verify the code works, try some simple tests
(forked from [Angora](https://github.com/AngoraFuzzer/Angora),
adapted by [@insuyun](https://github.com/insuyun) to lit):

```
$ pip install lit
$ cd your_build_dir
$ lit tests
```

C++ tests require the optional instrumented libc++ archives described above;
without them, lit reports those tests as unsupported.

### Environment Options

* `KO_CC` specifies the clang to invoke, if the default version isn't clang-12,
  set this variable to allow the compiler wrapper to find the correct clang.

* `KO_CXX` specifies the clang++ to invoke, if the default version isn't clang++-12,
  set this variable to allow the compiler wrapper to find the correct clang++.

* `KO_USE_Z3=1` links the in-process Z3-based solver into a compiler-instrumented
  target. It is not selected by default by `ko-clang`. With Z3 linked, branch
  recording and explicit queries are available; automatic file generation is
  controlled separately by `solve_on_branch`.
  SymSan also supports out-of-process solving, which provides better compatibility.
  Check [FastGen](https://github.com/R-Fuzz/fastgen).

* `TAINT_OPTIONS="... solve_on_branch=1"` enables automatic input generation
  with the in-process Z3 solver. The default keeps branch recording available
  for explicit value and path queries without generating files.

* `KO_USE_FASTGEN` links the out-of-process client. Run such a binary through
  the installed `fgtest` driver. Set `SYMCC_INPUT_FILE` and `SYMCC_OUTPUT_DIR`,
  or supply `taint_file` and `output_dir` through `TAINT_OPTIONS`. The driver
  preserves those paths/options, adds its IPC settings, and propagates the
  child's exit status.

* `KO_USE_NATIVE_LIBCXX` enables using the native uninstrumented libc++ and libc++abi.

* `KO_DONT_OPTIMIZE` don't override the optimization level to `O3`.

### Hybrid Fuzzing

SymSan needs a driver to perform hybrid fuzzing, like [FastGen](https://github.com/R-Fuzz/fastgen).
It could also be used as a custom mutator for [AFL++](https://github.com/AFLplusplus/AFLplusplus).

## Runtime Memory Models

Compiler-instrumented programs declare `__dfsan_native_shadow` and use the
linear shadow layout emitted by the LLVM pass. SymFit's emulator uses sparse
shadow pages instead. Native loads keep their source bit width; emulator
loads retain the register-width extension expected by translated helpers.
CPU objects can use distinct heap allocations, so vCPUs do not alias a single
fixed mapping. Native programs do not require SymFit's telemetry transport;
the runtime supplies disabled weak defaults.

The regression entry points and IA/RPC semantics are documented in the
[root README](../README.md#symfit-regression-tests) and
[interactive contract](../docs/interactive_scripting_contract.md).

## Reference

To cite SymSan in scientific work, please use the following BibTeX:

``` bibtex
@inproceedings {chen2022symsan,
  author =       {Ju Chen and Wookhyun Han and Mingjun Yin and Haochen Zeng and
                  Chengyu Song and Byoungyong Lee and Heng Yin and Insik Shin},
  title =        {SymSan: Time and Space Efficient Concolic Execution via Dynamic Data-Flow Analysis},
  booktitle =    {{USENIX} Security Symposium (Security)},
  year =         2022,
  url =          {https://www.usenix.org/conference/usenixsecurity22/presentation/chen-ju},
  publisher =    {{USENIX} Association},
  month =        aug,
}
```
