#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SOURCE_KIND="symfit"
QEMU_SRC="${HOME}/git/qemu"
SYMFIT_SRC="${HOME}/git/symfit"
BUILD_DIR="/tmp/qemu-build-ia"
OUT_DIR="${REPO_ROOT}/tools/qemu"
TARGET_LIST="i386-linux-user,x86_64-linux-user"
SYMSAN_BUILD_OVERRIDE=""
JOBS="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"
CLEAN=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Build instrumented qemu-user binaries for dynamiq.

Usage:
  scripts/build_qemu_toolchain.sh [options]

Options:
  --source-kind <kind>   Source type: symfit or qemu (default: symfit)
  --symfit-src <path>    SymFit source tree (default: ~/git/symfit)
  --symsan-build <path>  Existing SymSan build/prefix to reuse for SymFit builds
  --qemu-src <path>      QEMU source tree (default: ~/git/qemu)
  --build-dir <path>     Build directory (default: /tmp/qemu-build-ia)
  --out-dir <path>       Output directory (default: ./tools/qemu)
  --target-list <list>   QEMU target list (default: i386-linux-user,x86_64-linux-user)
  --jobs <n>             Parallel build jobs (default: nproc or 4)
  --clean                Remove build directory before configure/build
  --dry-run              Print actions without executing
  -h, --help             Show this help

Outputs:
  <out-dir>/qemu-i386-instrumented
  <out-dir>/qemu-x86_64-instrumented
EOF
}

run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] %q' "$1"
    shift
    for arg in "$@"; do
      printf ' %q' "${arg}"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-kind)
      SOURCE_KIND="$2"
      shift 2
      ;;
    --symfit-src)
      SYMFIT_SRC="$2"
      shift 2
      ;;
    --symsan-build)
      SYMSAN_BUILD_OVERRIDE="$2"
      shift 2
      ;;
    --qemu-src)
      QEMU_SRC="$2"
      shift 2
      ;;
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --target-list)
      TARGET_LIST="$2"
      shift 2
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "${SOURCE_KIND}" != "symfit" && "${SOURCE_KIND}" != "qemu" ]]; then
  echo "Unsupported --source-kind: ${SOURCE_KIND}" >&2
  exit 1
fi

run mkdir -p "${OUT_DIR}"

copy_outputs() {
  local i386_src="$1"
  local x86_64_src="$2"

  if [[ ! -x "${i386_src}" ]]; then
    echo "Missing i386 binary: ${i386_src}" >&2
    exit 1
  fi
  if [[ ! -x "${x86_64_src}" ]]; then
    echo "Missing x86_64 binary: ${x86_64_src}" >&2
    exit 1
  fi

  run cp -f "${i386_src}" "${OUT_DIR}/qemu-i386-instrumented"
  run cp -f "${x86_64_src}" "${OUT_DIR}/qemu-x86_64-instrumented"
  run chmod 755 "${OUT_DIR}/qemu-i386-instrumented" "${OUT_DIR}/qemu-x86_64-instrumented"
}

resolve_existing_symfit_binary_dir() {
  local candidate
  for candidate in \
    "${BUILD_DIR}/symfit-symsan" \
    "${SYMFIT_SRC}/build/symfit-symsan" \
    "${SYMFIT_SRC}/build/release/symfit-symsan"
  do
    if [[ -x "${candidate}/i386-linux-user/symfit-i386" && -x "${candidate}/x86_64-linux-user/symfit-x86_64" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

resolve_symsan_build_for_symfit() {
  if [[ -n "${SYMSAN_BUILD_OVERRIDE}" ]]; then
    printf '%s\n' "${SYMSAN_BUILD_OVERRIDE}"
    return 0
  fi

  if [[ -d "${SYMFIT_SRC}/build/symsan" ]]; then
    printf '%s\n' "${SYMFIT_SRC}/build/symsan"
    return 0
  fi

  if [[ -d "${SYMFIT_SRC}/build/release/symsan" ]]; then
    printf '%s\n' "${SYMFIT_SRC}/build/release/symsan"
    return 0
  fi

  printf '%s\n' "${BUILD_DIR}/symsan"
}

if [[ "${SOURCE_KIND}" == "qemu" ]]; then
  if [[ ! -d "${QEMU_SRC}" ]]; then
    echo "QEMU source directory not found: ${QEMU_SRC}" >&2
    exit 1
  fi
  if [[ ! -x "${QEMU_SRC}/configure" ]]; then
    echo "QEMU configure script missing or not executable: ${QEMU_SRC}/configure" >&2
    exit 1
  fi

  if [[ "${CLEAN}" -eq 1 ]]; then
    run rm -rf "${BUILD_DIR}"
  fi

  run mkdir -p "${BUILD_DIR}"

  # Always re-run configure so existing build dirs get updated target lists.
  run bash -lc "cd \"${BUILD_DIR}\" && \"${QEMU_SRC}/configure\" --target-list=\"${TARGET_LIST}\" --disable-werror"
  run make -C "${BUILD_DIR}" -j"${JOBS}" qemu-i386 qemu-x86_64
  copy_outputs "${BUILD_DIR}/qemu-i386" "${BUILD_DIR}/qemu-x86_64"
else
  local_symfit_build_dir="${BUILD_DIR}"
  symsan_build_dir="$(resolve_symsan_build_for_symfit)"
  existing_symfit_binary_dir=""

  if [[ ! -d "${SYMFIT_SRC}" ]]; then
    echo "SymFit source directory not found: ${SYMFIT_SRC}" >&2
    exit 1
  fi
  if [[ ! -x "${SYMFIT_SRC}/build.sh" ]]; then
    echo "SymFit build script missing or not executable: ${SYMFIT_SRC}/build.sh" >&2
    exit 1
  fi

  if [[ "${CLEAN}" -eq 1 ]]; then
    run rm -rf "${local_symfit_build_dir}"
  fi

  if existing_symfit_binary_dir="$(resolve_existing_symfit_binary_dir)"; then
    echo "Reusing existing SymFit binaries from:"
    echo "  ${existing_symfit_binary_dir}"
  else
    run mkdir -p "${local_symfit_build_dir}"
    run bash -lc "cd \"${SYMFIT_SRC}\" && BUILD_DIR=\"${local_symfit_build_dir}\" SYMSAN_BUILD=\"${symsan_build_dir}\" SYMFIT_TARGET_LIST=\"${TARGET_LIST}\" JOBS=\"${JOBS}\" ./build.sh symfit-symsan"
    existing_symfit_binary_dir="${local_symfit_build_dir}/symfit-symsan"
  fi
  copy_outputs \
    "${existing_symfit_binary_dir}/i386-linux-user/symfit-i386" \
    "${existing_symfit_binary_dir}/x86_64-linux-user/symfit-x86_64"
fi

echo "Built binaries:"
echo "  ${OUT_DIR}/qemu-i386-instrumented"
echo "  ${OUT_DIR}/qemu-x86_64-instrumented"
