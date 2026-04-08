.section .text
.global _start
.global data_byte
.global branch2_taken

_start:
    lea data_byte(%rip), %rbx
    xor %rax, %rax
    jmp branch1_check

branch1_check:
    lea (%rbx,%rax,1), %rdx
    movzbl (%rdx), %ecx
    cmp $0x41, %cl
    je branch1_taken
    jmp do_exit_fail_1

branch1_taken:
    lea (%rbx,%rax,1), %rdx
    movzbl (%rdx), %ecx
    add $1, %cl
    cmp $0x42, %cl
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
