//===-- dfsan_interceptors.cc ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Interceptors for standard library functions.
//===----------------------------------------------------------------------===//

#include <sys/syscall.h>
#include <unistd.h>

#include "dfsan.h"
#include "interception/interception.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;

namespace {

static bool interceptors_initialized;

void ReleaseShadowMemoryPagesToOS(void *addr, SIZE_T length) {
  uptr beg_shadow_addr = (uptr)__dfsan::shadow_for(addr);
  void *end_addr =
      (void *)((uptr)addr + RoundUpTo(length, GetPageSizeCached()));
  uptr end_shadow_addr = (uptr)__dfsan::shadow_for(end_addr);
  ReleaseMemoryPagesToOS(beg_shadow_addr, end_shadow_addr);
}

}

INTERCEPTOR(void *, mmap, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF_T offset) {
  return (void *)internal_mmap(addr, length, prot, flags, fd, offset);
}

INTERCEPTOR(void *, mmap64, void *addr, SIZE_T length, int prot, int flags,
            int fd, OFF64_T offset) {
  return (void *)internal_mmap(addr, length, prot, flags, fd, offset);
}

INTERCEPTOR(int, munmap, void *addr, SIZE_T length) {
  return (int)internal_munmap(addr, length);
}

namespace __dfsan {
void InitializeInterceptors() {
  CHECK(!interceptors_initialized);

  INTERCEPT_FUNCTION(mmap);
  INTERCEPT_FUNCTION(mmap64);
  INTERCEPT_FUNCTION(munmap);

  interceptors_initialized = true;
}
}  // namespace __dfsan
