#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Defaults & paths (override via env)
# -----------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source repos
SYMSAN_SRC="${SYMSAN_SRC:-}"
SYMFIT_SRC="${SYMFIT_SRC:-"$ROOT"}"   # symfit = this repo

# Build roots
BUILD_DIR="${BUILD_DIR:-"$ROOT/build"}"
SYMSAN_INSTALL="${SYMSAN_INSTALL:-${SYMSAN_BUILD:-"$BUILD_DIR/symsan"}}"
SYMSAN_BUILD_DIR="${SYMSAN_BUILD_DIR:-"$BUILD_DIR/symsan-build"}"
SYMFIT_SYMSAN_BUILD="${SYMFIT_SYMSAN_BUILD:-"$BUILD_DIR/symfit-symsan"}"
SYMFIT_TARGET_LIST="${SYMFIT_TARGET_LIST:-x86_64-linux-user,i386-linux-user,x86_64-softmmu,aarch64-softmmu,aarch64-linux-user}"

# Toolchain / perf
CLANG_VER="${CLANG_VER:-12}"          # override if different
CORES_DEFAULT="$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu || echo 8)"
JOBS="${JOBS:-$CORES_DEFAULT}"

# Build type & switches
DEBUG=0
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

need_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Expected file not found: $f"
}

is_url() {
  [[ "$1" =~ ^https?:// ]]
}

resolve_github_release_tarball_url() {
  local repo="$1"
  local tag="$2"
  local pattern="$3"
  local api_url=""
  local api_json=""
  local download_url=""

  if [[ "$tag" == "latest" ]]; then
    api_url="https://api.github.com/repos/${repo}/releases/latest"
  else
    api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  fi

  printf "\033[1;34m[build]\033[0m Querying GitHub release metadata: %s (%s)\n" "$repo" "$tag" >&2
  if command -v curl >/dev/null 2>&1; then
    api_json="$(curl -LfsS "$api_url")"
  elif command -v wget >/dev/null 2>&1; then
    api_json="$(wget -qO- "$api_url")"
  else
    die "Neither curl nor wget found; cannot query GitHub releases"
  fi

  if command -v python3 >/dev/null 2>&1; then
    download_url="$(python3 -c 'import json, re, sys
d = json.load(sys.stdin)
p = re.compile(sys.argv[1])
for a in d.get("assets", []):
    n = a.get("name", "")
    u = a.get("browser_download_url", "")
    if p.search(n) and u:
        print(u)
        sys.exit(0)
sys.exit(1)
' "$pattern" <<<"$api_json" || true)"
  else
    download_url="$(printf "%s\n" "$api_json" | grep -oE 'https://[^"]+\.tar\.gz' | head -n1 || true)"
  fi

  [[ -n "$download_url" ]] || die "No release asset matched pattern '${pattern}' in ${repo} (${tag})"
  printf "%s\n" "$download_url"
}

find_symsan_prefix() {
  local root="$1"
  if [[ -x "$root/bin/fgtest" ]]; then
    printf '%s\n' "$root"
    return 0
  fi

  local candidate
  candidate="$(find "$root" -type f -name fgtest -path "*/bin/fgtest" -print -quit || true)"
  if [[ -n "$candidate" ]]; then
    dirname "$(dirname "$candidate")"
    return 0
  fi
  return 1
}

install_symsan_from_tarball() {
  local src="$1"
  local tarball_path="$src"
  local tmp=""
  local extract_dir=""
  local symsan_prefix=""

  if is_url "$src"; then
    need_dir "$BUILD_DIR"
    tarball_path="$BUILD_DIR/$(basename "${src%%\?*}")"
    if [[ -z "$(basename "$tarball_path")" || "$(basename "$tarball_path")" == "/" ]]; then
      tarball_path="$BUILD_DIR/symsan-release.tar.gz"
    fi
    log "Downloading Symsan tarball: $src"
    if command -v curl >/dev/null 2>&1; then
      curl -LfsS "$src" -o "$tarball_path"
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$tarball_path" "$src"
    else
      die "Neither curl nor wget found; cannot download $src"
    fi
  fi

  need_file "$tarball_path"
  tmp="$(mktemp -d)"

  log "Extracting Symsan tarball into temporary directory"
  tar -xf "$tarball_path" -C "$tmp"
  extract_dir="$tmp"

  if symsan_prefix="$(find_symsan_prefix "$extract_dir")"; then
    rm -rf "$SYMSAN_INSTALL"
    mkdir -p "$SYMSAN_INSTALL"
    cp -a "$symsan_prefix"/. "$SYMSAN_INSTALL"/
  else
    die "Could not find bin/fgtest in extracted tarball: $tarball_path"
  fi

  [[ -x "$SYMSAN_INSTALL/bin/fgtest" ]] || die "Invalid Symsan install, missing executable: $SYMSAN_INSTALL/bin/fgtest"
  rm -rf "$tmp"
  log "Installed Symsan artifacts to $SYMSAN_INSTALL"
}

ensure_symsan_ready() {
  if [[ "${AUTO_DOWNLOAD_SYMSAN:-0}" == "1" && -z "$SYMSAN_TARBALL" ]]; then
    SYMSAN_TARBALL="$(resolve_github_release_tarball_url "$SYMSAN_RELEASE_REPO" "$SYMSAN_RELEASE_TAG" "$SYMSAN_RELEASE_ASSET_PATTERN")"
  fi

  if [[ -n "$SYMSAN_TARBALL" ]]; then
    install_symsan_from_tarball "$SYMSAN_TARBALL"
    return 0
  fi

  if [[ "$USE_PREBUILT_SYMSAN" == "1" ]]; then
    [[ -x "$SYMSAN_INSTALL/bin/fgtest" ]] || die "USE_PREBUILT_SYMSAN=1 but missing $SYMSAN_INSTALL/bin/fgtest"
    log "Using prebuilt Symsan at $SYMSAN_INSTALL"
    return 0
  fi

  if [[ -x "$SYMSAN_INSTALL/bin/fgtest" ]]; then
    log "Found existing Symsan artifacts at $SYMSAN_INSTALL (skipping source build)"
    return 0
  fi

  build_symsan
}

# -----------------------------
# Target builders
# -----------------------------
build_symsan() {
  [[ -n "$SYMSAN_SRC" ]] || die "SYMSAN_SRC must point to a standalone Symsan checkout"
  need_dir "$SYMSAN_SRC"
  mkdir -p "$SYMSAN_BUILD_DIR" "$SYMSAN_INSTALL"
  log "Configuring Symsan (clang-${CLANG_VER}), debug=${SYMSAN_DEBUG}"
  CC="clang-${CLANG_VER}" CXX="clang++-${CLANG_VER}" cmake \
        -S "${SYMSAN_SRC}" \
        -B "${SYMSAN_BUILD_DIR}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${SYMSAN_INSTALL}" \
        -DSYMSAN_DEBUG="${SYMSAN_DEBUG}"
  log "Building & installing Symsan"
  cmake --build "${SYMSAN_BUILD_DIR}" -j"${JOBS}"
  mkdir -p "${SYMSAN_BUILD_DIR}/instrumentation/CMakeFiles/CMakeRelink.dir"
  cp "${SYMSAN_BUILD_DIR}/instrumentation/libTaintPass.so" \
     "${SYMSAN_BUILD_DIR}/instrumentation/CMakeFiles/CMakeRelink.dir/"
  cmake --install "${SYMSAN_BUILD_DIR}"
}

configure_symfit_common() {
  local backend="$1"
  local bdir="$2"              # build dir

  LLVM_CONFIG_BIN="${LLVM_CONFIG_BIN:-}"
  LLVM_INCLUDEDIR="${LLVM_INCLUDEDIR:-}"

  if [[ -z "${LLVM_INCLUDEDIR}" ]]; then
    if [[ -n "${LLVM_CONFIG_BIN}" ]] && command -v "$LLVM_CONFIG_BIN" >/dev/null 2>&1; then
      LLVM_INCLUDEDIR="$($LLVM_CONFIG_BIN --includedir)"
    else
      local llvm_cfg
      for llvm_cfg in llvm-config llvm-config-18 llvm-config-17 llvm-config-16 llvm-config-15 llvm-config-14 llvm-config-13 llvm-config-12; do
        if command -v "$llvm_cfg" >/dev/null 2>&1; then
          LLVM_CONFIG_BIN="$llvm_cfg"
          LLVM_INCLUDEDIR="$($llvm_cfg --includedir)"
          break
        fi
      done
    fi
  fi

  if [[ -z "${LLVM_INCLUDEDIR}" || ! -f "${LLVM_INCLUDEDIR}/llvm/IR/Instruction.def" ]]; then
    local llvm_root
    for llvm_root in /usr/lib/llvm-18 /usr/lib/llvm-17 /usr/lib/llvm-16 /usr/lib/llvm-15 /usr/lib/llvm-14 /usr/lib/llvm-13 /usr/lib/llvm-12; do
      if [[ -f "${llvm_root}/include/llvm/IR/Instruction.def" ]]; then
        LLVM_INCLUDEDIR="${llvm_root}/include"
        break
      fi
    done
  fi

  [[ -n "${LLVM_INCLUDEDIR}" && -f "${LLVM_INCLUDEDIR}/llvm/IR/Instruction.def" ]] \
    || die "Could not find LLVM include dir containing llvm/IR/Instruction.def. Set LLVM_INCLUDEDIR or LLVM_CONFIG_BIN."

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
    --target-list="${SYMFIT_TARGET_LIST}" \
    --enable-capstone=git         \
    --disable-werror              \
    --symsan-build="${SYMSAN_INSTALL}"

  log "Building symfit (${backend}) in ${bdir}"
  make -j"${JOBS}"
}

build_symfit_symsan()  { configure_symfit_common "symsan" "$SYMFIT_SYMSAN_BUILD"; }

relink_symfit_symsan() {
  need_dir "$SYMFIT_SYMSAN_BUILD"

  log "Refreshing shared support objects in ${SYMFIT_SYMSAN_BUILD}"
  make -C "$SYMFIT_SYMSAN_BUILD" \
    libqemuutil.a \
    symfit-telemetry/symfit_telemetry.o

  local target_dir=""
  local prog_name=""
  IFS=',' read -r -a target_dirs <<< "$SYMFIT_TARGET_LIST"
  for target_dir in "${target_dirs[@]}"; do
    [[ -n "$target_dir" ]] || continue
    if [[ ! -d "$SYMFIT_SYMSAN_BUILD/$target_dir" ]]; then
      die "Configured target build directory does not exist: $SYMFIT_SYMSAN_BUILD/$target_dir"
    fi

    case "$target_dir" in
      *-linux-user)
        prog_name="symfit-${target_dir%-linux-user}"
        ;;
      *-softmmu)
        prog_name="qemu-system-${target_dir%-softmmu}"
        ;;
      *)
        die "Unsupported relink target directory: $target_dir"
        ;;
    esac

    log "Relinking ${prog_name}"
    make -C "$SYMFIT_SYMSAN_BUILD/$target_dir" "$prog_name"
  done
}

# -----------------------------
# CLI parsing
# -----------------------------
usage() {
cat <<'EOF'
Usage: ./build.sh [targets] [options]

Targets (default: all)
  symsan           Build Symsan
  symfit-symsan    Build symfit (Symsan backend)
  relink-symfit-symsan
                   Refresh shared support objects and relink configured user/system targets
  all              Build everything above in order

Options
  --debug          Enable debug for symfit (and Symsan's SYMSAN_DEBUG=ON)
  --release        (default) Release/RelWithDebInfo as in original script
  -jN              Set parallel jobs (default: auto-detected)
  --print-paths    Print effective paths and exit

Environment overrides
  SYMSAN_SRC, SYMFIT_SRC
  BUILD_DIR, SYMSAN_INSTALL, SYMSAN_BUILD_DIR, SYMFIT_SYMSAN_BUILD
  SYMSAN_TARBALL         Path or URL to a prebuilt Symsan tarball
  AUTO_DOWNLOAD_SYMSAN=1 Resolve and download a release tarball automatically
  SYMSAN_RELEASE_REPO    GitHub repo for releases (default: bitsecurerlab/symsan)
  SYMSAN_RELEASE_TAG     Release tag or 'latest' (default: latest)
  SYMSAN_RELEASE_ASSET_PATTERN
                         Regex for release asset name (default: \.tar\.gz$)
  USE_PREBUILT_SYMSAN=1  Skip source build and use existing SYMSAN_INSTALL
  SYMSAN_SRC             Path to a standalone Symsan checkout for source builds
  SYMSAN_BUILD           Backward-compatible alias for SYMSAN_INSTALL
  CLANG_VER, JOBS
  SYMFIT_TARGET_LIST     QEMU target list (default: x86_64-linux-user,i386-linux-user,x86_64-softmmu,aarch64-softmmu,aarch64-linux-user)

Examples:
  ./build.sh all
  JOBS=32 ./build.sh symsan symfit-symsan
  ./build.sh --debug all
  SYMSAN_ROOT=/mnt/d/git/symsan ./build.sh all
EOF
}

TARGETS=()
PRINT_PATHS=0

while (( "$#" )); do
  case "$1" in
    symsan|symfit-symsan|relink-symfit-symsan|all)
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
SYMSAN_SRC           = ${SYMSAN_SRC:-<unset>}
SYMFIT_SRC           = ${SYMFIT_SRC}
BUILD_DIR            = ${BUILD_DIR}
SYMSAN_INSTALL       = ${SYMSAN_INSTALL}
SYMSAN_BUILD_DIR     = ${SYMSAN_BUILD_DIR}
SYMSAN_BUILD         = ${SYMSAN_BUILD:-<alias of SYMSAN_INSTALL>}
SYMFIT_SYMSAN_BUILD  = ${SYMFIT_SYMSAN_BUILD}
SYMFIT_TARGET_LIST   = ${SYMFIT_TARGET_LIST}
CLANG_VER            = ${CLANG_VER}
JOBS                 = ${JOBS}
DEBUG                = ${DEBUG} (symsan_debug=${SYMSAN_DEBUG})
EOF
  exit 0
fi

# Ensure build dirs exist
mkdir -p "${SYMSAN_INSTALL}" "${SYMSAN_BUILD_DIR}" "${SYMFIT_SYMSAN_BUILD}"

# -----------------------------
# Execution
# -----------------------------
for t in "${TARGETS[@]}"; do
  case "$t" in
    symsan)          build_symsan;;
    symfit-symsan)   build_symfit_symsan;;
    relink-symfit-symsan) relink_symfit_symsan;;
    all)
      ensure_symsan_ready
      build_symfit_symsan
      ;;
  esac
done

log "Done."
