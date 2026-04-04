#include <stdint.h>
#include <string.h>
#include <unistd.h>

volatile uint8_t exit_marker = 0x42;
volatile uint8_t crash_marker = 0x43;

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "crash") == 0) {
        volatile uint8_t *ptr = (volatile uint8_t *)0;
        *ptr = crash_marker;
        return 99;
    }

    return (int)exit_marker;
}
