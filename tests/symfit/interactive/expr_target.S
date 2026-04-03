.section .text
.global _start

_start:
    mov $0x11, %rbx
    jmp do_add

do_add:
    add %rax, %rbx
    jmp do_xor

do_xor:
    xor $0x22, %rbx
    jmp do_exit

do_exit:
    mov %rbx, %rdi
    mov $60, %rax
    syscall
