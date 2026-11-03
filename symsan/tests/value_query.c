// RUN: rm -rf %t.out && mkdir -p %t.out
// RUN: printf '\005' > %t.bin
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin | FileCheck %s

#include <stdint.h>
#include <stdio.h>
#include "lib.h"
#include "symsan/dfsan_interface.h"

int main(int argc, char **argv) {
  uint8_t input = 0;
  uint8_t value;
  uint64_t seed = 0, minimum = 0, maximum = 0;
  size_t assumptions = 0, count = 0;
  dfsan_solve_assignment assignments[8] = {{0}};
  char error[256] = {0};
  int rc;

  if (argc != 2)
    return 2;
  dfsan_begin_value_query_capture();
  FILE *source = chk_fopen(argv[1], "rb");
  chk_fread(&input, 1, 1, source);
  fclose(source);
  if (input >= 10)
    return 3;
  value = (uint8_t)(input + 1);

  dfsan_label label = dfsan_read_label(&value, sizeof(value));
  dfsan_set_value_query_relaxation_profile(0);
  rc = dfsan_query_value_range(label, 0, 0, 0, &seed, &minimum, &maximum,
                               &assumptions, error, sizeof(error));
  // CHECK: range=1 seed=6 min=1 max=10
  printf("range=%d seed=%llu min=%llu max=%llu\n", rc,
         (unsigned long long)seed, (unsigned long long)minimum,
         (unsigned long long)maximum);

  rc = dfsan_query_value_eq(label, 8, assignments, 8, &count, &assumptions,
                            error, sizeof(error));
  // CHECK: eq=1 count=1 symbol=symfit_input_0 value=7
  printf("eq=%d count=%zu symbol=symfit_input_%llu value=%u\n", rc, count,
         (unsigned long long)assignments[0].offset, assignments[0].value);

  rc = dfsan_query_value_range(label, 20, 10, 0, &seed, &minimum, &maximum,
                               &assumptions, error, sizeof(error));
  // CHECK: invalid=-1
  printf("invalid=%d\n", rc);
  return 0;
}
