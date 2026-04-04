#include <stdint.h>
#include <unistd.h>

char stdin_buffer[16];
volatile unsigned int stdin_sink;

int main(void)
{
    ssize_t n = read(STDIN_FILENO, stdin_buffer, 8);

    asm volatile(
        ".global after_read_label\n"
        "after_read_label:\n"
    );

    if (n <= 0) {
        return 1;
    }

    stdin_sink =
        (unsigned char)stdin_buffer[0] +
        (unsigned char)stdin_buffer[1] +
        (unsigned char)stdin_buffer[2] +
        (unsigned char)stdin_buffer[3] +
        (unsigned char)stdin_buffer[4];
    return stdin_sink == 0xffffffffu ? 2 : 0;
}
