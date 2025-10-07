#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Defaults & paths (override via env)
# -----------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Submodule sources (added via: external/symcc, external/symsan)
SYMCC_SRC="${SYMCC_SRC:-"$ROOT/external/symcc"}"
SYMSAN_SRC="${SYMSAN_SRC:-"$ROOT/external/symsan"}"
SYMFIT_SRC="${SYMFIT_SRC:-"$ROOT"}"   # symfit = this repo

# Build roots
BUILD_DIR="${BUILD_DIR:-"$ROOT/build"}"
SYMCC_BUILD="${SYMCC_BUILD:-"$BUILD_DIR/symcc"}"
SYMSAN_BUILD="${SYMSAN_BUILD:-"$BUILD_DIR/symsan"}"
#SYMFIT_SYMCC_BUILD="${SYMFIT_SYMCC_BUILD:-"$BUILD_DIR/symfit-symcc"}"
SYMFIT_SYMSAN_BUILD="${SYMFIT_SYMSAN_BUILD:-"$BUILD_DIR/symfit-symsan"}"

# Toolchain / perf
CLANG_VER="${CLANG_VER:-12}"          # override if different
CORES_DEFAULT="$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu || echo 8)"
JOBS="${JOBS:-$CORES_DEFAULT}"

# Build type & switches
DEBUG=0
CMAKE_BUILD_TYPE="RelWithDebInfo"     # for symcc; symsan uses Release (like your original)
SYMSAN_DEBUG="OFF"

# -----------------------------
# Helpers
# -----------------------------
log() { printf "\033[1;34m[build]\033[0m %s\n" "$*"; }
die() { printf "\033[1;31m[error]\033[0m %s\n" "$*" >&2; exit 1; }
mkcd() { mkdir -p "$1" && cd "$1"; }

need_dir() {
  local d="$1"
  [[ -d "$d" ]] || die "Expected directory not found: $d"
}

# -----------------------------
# Target builders
# -----------------------------
build_symcc() {
  need_dir "$SYMCC_SRC"
  mkcd "$SYMCC_BUILD"
  log "Configuring SymCC in $SYMCC_BUILD (src=$SYMCC_SRC)"
  cmake -G Ninja \
    -DQSYM_BACKEND=ON \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DZ3_TRUST_SYSTEM_VERSION=ON \
    "${SYMCC_SRC}"
  log "Building SymCC"
  ninja -j"${JOBS}" all
}

build_symsan() {
  need_dir "$SYMSAN_SRC"
  mkcd "$SYMSAN_BUILD"
  log "Configuring Symsan (clang-${CLANG_VER}), debug=${SYMSAN_DEBUG}"
  CC="clang-${CLANG_VER}" CXX="clang++-${CLANG_VER}" \
  cmake -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${SYMSAN_BUILD}" \
        -DSYMSAN_DEBUG="${SYMSAN_DEBUG}" \
        "${SYMSAN_SRC}"
  log "Building & installing Symsan"
  make -j"${JOBS}"
  make install
}

configure_symfit_common() {
  local backend="$1"           # symcc | symsan
  local bdir="$2"              # build dir

  LLVM_CONFIG_BIN="${LLVM_CONFIG_BIN:-llvm-config-12}"
  if command -v "$LLVM_CONFIG_BIN" >/dev/null 2>&1; then
    LLVM_INCLUDEDIR="$($LLVM_CONFIG_BIN --includedir)"
  else
    # Fallback to common Ubuntu path
    LLVM_INCLUDEDIR="/usr/lib/llvm-12/include"
  fi

  need_dir "$SYMFIT_SRC"
  mkcd "$bdir"

  local debug_flag=""
  [[ $DEBUG -eq 1 ]] && debug_flag="--enable-debug"

  EXTRA_CFLAGS="-I${LLVM_INCLUDEDIR}"
  # Common configure flags (from your script)
  "${SYMFIT_SRC}/configure"       \
    --extra-cflags="${EXTRA_CFLAGS}" \
    --audio-drv-list=             \
    --disable-bluez               \
    --disable-sdl                 \
    --disable-gtk                 \
    --enable-2nd-ccache           \
    ${debug_flag}                 \
    --disable-vte                 \
    --disable-opengl              \
    --disable-virglrenderer       \
    --target-list=x86_64-linux-user \
    --enable-capstone=git         \
    --disable-werror              \
    --symcc-source="${SYMCC_SRC}" \
    --symcc-build="${SYMCC_BUILD}" \
    --symsan-source="${SYMSAN_SRC}" \
    --symsan-build="${SYMSAN_BUILD}"

  log "Building symfit (${backend}) in ${bdir}"
  make -j"${JOBS}"
}

#build_symfit_symcc()   { configure_symfit_common "symcc"  "$SYMFIT_SYMCC_BUILD"; }
build_symfit_symsan()  { configure_symfit_common "symsan" "$SYMFIT_SYMSAN_BUILD"; }

# -----------------------------
# CLI parsing
# -----------------------------
usage() {
cat <<'EOF'
Usage: ./build.sh [targets] [options]

Targets (default: all)
  symcc            Build SymCC
  symsan           Build Symsan
  symfit-symsan    Build symfit (Symsan backend)
  all              Build everything above in order

Options
  --debug          Enable debug for symfit (and Symsan's SYMSAN_DEBUG=ON)
  --release        (default) Release/RelWithDebInfo as in original script
  -jN              Set parallel jobs (default: auto-detected)
  --print-paths    Print effective paths and exit

Environment overrides
  SYMCC_SRC, SYMSAN_SRC, SYMFIT_SRC
  BUILD_DIR, SYMCC_BUILD, SYMSAN_BUILD, SYMFIT_SYMSAN_BUILD
  CLANG_VER, JOBS

Examples:
  ./build.sh all
  JOBS=32 ./build.sh symcc symsan
  ./build.sh --debug all
EOF
}

TARGETS=()
PRINT_PATHS=0

while (( "$#" )); do
  case "$1" in
    symcc|symsan|symfit-symsan|all)
      TARGETS+=("$1"); shift;;
    --debug)
      DEBUG=1; SYMSAN_DEBUG="ON"; shift;;
    --release)
      DEBUG=0; SYMSAN_DEBUG="OFF"; shift;;
    -j*)
      JOBS="${1#-j}"; shift;;
    --print-paths)
      PRINT_PATHS=1; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      die "Unknown arg: $1 (see --help)"
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(all)
fi

if [[ $PRINT_PATHS -eq 1 ]]; then
  cat <<EOF
ROOT                 = ${ROOT}
SYMCC_SRC            = ${SYMCC_SRC}
SYMSAN_SRC           = ${SYMSAN_SRC}
SYMFIT_SRC           = ${SYMFIT_SRC}
BUILD_DIR            = ${BUILD_DIR}
SYMCC_BUILD          = ${SYMCC_BUILD}
SYMSAN_BUILD         = ${SYMSAN_BUILD}
SYMFIT_SYMSAN_BUILD  = ${SYMFIT_SYMSAN_BUILD}
CLANG_VER            = ${CLANG_VER}
JOBS                 = ${JOBS}
DEBUG                = ${DEBUG} (symsan_debug=${SYMSAN_DEBUG})
EOF
  exit 0
fi

# Ensure build dirs exist
mkdir -p "${SYMCC_BUILD}" "${SYMSAN_BUILD}" "${SYMFIT_SYMSAN_BUILD}"

# -----------------------------
# Execution
# -----------------------------
for t in "${TARGETS[@]}"; do
  case "$t" in
    symcc)           build_symcc;;
    symsan)          build_symsan;;
    symfit-symsan)   build_symfit_symsan;;
    all)
      build_symcc
      build_symsan
      build_symfit_symsan
      ;;
  esac
done

log "Done."

