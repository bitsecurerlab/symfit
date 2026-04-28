#include <stdint.h>
#include <stdio.h>

__attribute__((noinline))
static uint64_t sample_marker(uint64_t acc) {
    return acc + 7;
}

int main(int argc, char **argv) {
    uint64_t acc = 0;
    for (int i = 0; i < 4; ++i) {
        acc += (uint64_t)i * 3;
    }
    acc = sample_marker(acc);
    if (argc > 1) {
        printf("%s %llu\n", argv[1], (unsigned long long)acc);
    } else {
        printf("acc=%llu\n", (unsigned long long)acc);
    }
    return (int)acc;
}
