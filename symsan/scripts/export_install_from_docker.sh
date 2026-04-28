#!/usr/bin/env bash
set -euo pipefail

# Build SymSan in Docker and export runtime artifacts into ./install.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${SYMSAN_DOCKER_IMAGE:-symsan-build:local}"
BUILD_STAGE_DIR="${ROOT_DIR}/build"
INSTALL_DIR="${ROOT_DIR}/install"
TEMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TEMP_DIR}"
  if [[ -n "${CID:-}" ]]; then
    docker rm -f "${CID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[1/4] Building Docker image: ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" "${ROOT_DIR}"

echo "[2/4] Extracting build tree from image"
CID="$(docker create "${IMAGE_TAG}")"
docker cp "${CID}:/workdir/symsan/build/." "${TEMP_DIR}/build"

echo "[3/4] Preparing install layout"
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/lib/symsan" "${INSTALL_DIR}/include/symsan"

cp -f \
  "${TEMP_DIR}/build/bin/ko-clang" \
  "${TEMP_DIR}/build/bin/ko-clang++" \
  "${TEMP_DIR}/build/bin/fgtest" \
  "${INSTALL_DIR}/bin/"

cp -f \
  "${TEMP_DIR}/build/lib/symsan/libTaintPass.so" \
  "${TEMP_DIR}/build/lib/symsan/libdfsan_rt-x86_64.a" \
  "${TEMP_DIR}/build/lib/symsan/libdfsan_rt-x86_64.a.syms" \
  "${TEMP_DIR}/build/lib/symsan/dfsan_abilist.txt" \
  "${TEMP_DIR}/build/lib/symsan/libc++_abilist.txt" \
  "${TEMP_DIR}/build/lib/symsan/taint.ld" \
  "${TEMP_DIR}/build/lib/symsan/zlib_abilist.txt" \
  "${TEMP_DIR}/build/lib/symsan/libZ3Solver.a" \
  "${TEMP_DIR}/build/lib/symsan/libFastgen.a" \
  "${TEMP_DIR}/build/lib/symsan/libc++.a" \
  "${TEMP_DIR}/build/lib/symsan/libc++abi.a" \
  "${TEMP_DIR}/build/lib/symsan/libunwind.a" \
  "${INSTALL_DIR}/lib/symsan/"

cp -f "${ROOT_DIR}/include/"*.h "${INSTALL_DIR}/include/symsan/"
cp -f \
  "${ROOT_DIR}/runtime/dfsan_interface.h" \
  "${ROOT_DIR}/runtime/common_interface_defs.h" \
  "${INSTALL_DIR}/include/symsan/"

echo "[4/4] Export complete"
echo "Install tree updated at: ${INSTALL_DIR}"
