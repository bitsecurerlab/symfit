.section .text
.global _start
.global data_byte
.global branch2_taken

_start:
    jmp branch1_check

branch1_check:
    movzbl data_byte(%rip), %eax
    cmp $0x41, %al
    sete %bl
    movzbq %bl, %rbx
    je branch1_taken
    jmp do_exit_fail_1

branch1_taken:
    jmp branch2_check

branch2_check:
    movzbl data_byte(%rip), %eax
    add $1, %al
    cmp $0x42, %al
    sete %cl
    movzbq %cl, %rcx
    je branch2_taken
    jmp do_exit_fail_2

branch2_taken:
    mov $0, %edi
    jmp do_exit

do_exit_fail_1:
    mov $1, %edi
    jmp do_exit

do_exit_fail_2:
    mov $2, %edi

do_exit:
    mov $60, %eax
    syscall

.section .data
data_byte:
    .byte 0x41
