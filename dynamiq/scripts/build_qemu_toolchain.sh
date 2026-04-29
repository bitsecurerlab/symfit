#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DYNAMIQ_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
MONOREPO_ROOT="$(cd -- "${DYNAMIQ_ROOT}/.." && pwd)"

SYMFIT_SRC="${SYMFIT_SRC:-${MONOREPO_ROOT}}"
BUILD_DIR="${BUILD_DIR:-${MONOREPO_ROOT}/build}"
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
  --symfit-src <path>    SymFit source tree (default: merged monorepo root)
  --symsan-build <path>  Existing SymSan build/prefix to reuse for SymFit builds
  --build-dir <path>     Build directory (default: ../build)
  --target-list <list>   QEMU target list (default: i386-linux-user,x86_64-linux-user)
  --jobs <n>             Parallel build jobs (default: nproc or 4)
  --clean                Remove build directory before configure/build
  --dry-run              Print actions without executing
  -h, --help             Show this help

Outputs:
  <build-dir>/symfit/i386-linux-user/symfit-i386
  <build-dir>/symfit/x86_64-linux-user/symfit-x86_64
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
    --symfit-src)
      SYMFIT_SRC="$2"
      shift 2
      ;;
    --symsan-build)
      SYMSAN_BUILD_OVERRIDE="$2"
      shift 2
      ;;
    --build-dir)
      BUILD_DIR="$2"
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

if [[ ! -x "${SYMFIT_SRC}/build.sh" && -x "${DYNAMIQ_ROOT}/build.sh" ]]; then
  SYMFIT_SRC="${DYNAMIQ_ROOT}"
fi

resolve_existing_symfit_binary_dir() {
  local candidate
  for candidate in \
    "${BUILD_DIR}/symfit" \
    "${SYMFIT_SRC}/build/symfit" \
    "${SYMFIT_SRC}/build/release/symfit"
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
  run bash -lc "cd \"${SYMFIT_SRC}\" && BUILD_DIR=\"${local_symfit_build_dir}\" SYMSAN_BUILD=\"${symsan_build_dir}\" SYMFIT_TARGET_LIST=\"${TARGET_LIST}\" JOBS=\"${JOBS}\" ./build.sh"
  existing_symfit_binary_dir="${local_symfit_build_dir}/symfit"
fi

echo "Built binaries:"
echo "  ${existing_symfit_binary_dir}/i386-linux-user/symfit-i386"
echo "  ${existing_symfit_binary_dir}/x86_64-linux-user/symfit-x86_64"
