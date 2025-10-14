/*
 * SymFit Test Program
 * Simple test to exercise symbolic execution with multiple branches
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char buf[8] = {0};
    FILE *f = fopen("testfile", "r");

    if (!f) {
        fprintf(stderr, "Failed to open testfile\n");
        return 1;
    }

    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[7] = 0;

    if (n < 1) {
        fprintf(stderr, "Empty file\n");
        return 1;
    }

    // Branch 1: Check first character
    if (buf[0] == 'A') {
        puts("B1:A");
    } else {
        puts("B1:!A");
    }

    // Branch 2: Check length
    if (n > 5) {
        puts("B2:len>5");
    } else {
        puts("B2:len<=5");
    }

    // Branch 3: Check for substring
    if (strcmp(buf, "PASS")) {
        puts("B3:PASS");
    } else {
        puts("B3:!PASS");
    }

    // Branch 4: Check sequence
    if (n >= 3 && buf[1] == 'B' && buf[2] == 'C') {
        puts("B4:ABC");
    }

    // Branch 5: Check line ending
    if (buf[n-1] == '\n') {
        puts("B5:LF");
    } else {
        puts("B5:!LF");
    }

    return 0;
}
