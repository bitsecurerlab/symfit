.section .text
.global _start

_start:
    lea data(%rip), %rbx
    xor %rax, %rax
    jmp constrain_index

constrain_index:
    and $0x7, %rax
    add %rax, %rbx
    jmp do_load

do_load:
    mov (%rbx), %rcx
    jmp do_exit

do_exit:
    xor %rdi, %rdi
    mov $60, %rax
    syscall

.section .data
data:
    .quad 0x1122334455667788
