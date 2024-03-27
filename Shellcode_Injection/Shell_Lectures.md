# Shellcode Injection
## Resources
- [Syscall Table, with multiple architectures](https://syscall.sh/)
- [x86_64 Syscall Table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [x86_64 assembly listing](http://ref.x86asm.net/coder64.html)
## Introduction
- Von Neumann Architecture vs Harvard Architecture
    - A Von Neumann architecture sees and stores code as data
        - Almost all general-purpose architectures (x86, ARM, MIPS, PPC, SPARC, etc) are Von Neumann Architecture
    - A Harvard architecture stores data and code separately
        - Pop up in embedded use-cases (AVR, PIC)
## Common Challenges
- Memory Access Width
- Forbidden Bytes (some examples)
    ```
    +-------------------------------------------------------------------+
    |          Byte           |  Problematic Methods                    |
    |-------------------------+-----------------------------------------|
    |     Null byte   \0 0x00 |  strcpy                                 |
    |      Newline    \n 0x0a |  scanf, gets, getline, fgets            |
    | Carriage return \r 0x0d |  scanf                                  |
    |       Space        0x20 |  scanf                                  |
    |        Tab      \t 0x09 |  scanf                                  |
    |        DEL         0x7f |  protocol-specific (telnet, VT100, etc) |
    +-------------------------------------------------------------------+
    ```
    - When the constraints on the shellcode are too hard to get around, but the page where the shellcode is mapped is writable: remember `code == data`
        - By passing a restriction on `int3` (opcode: `0x3cc`):
            ```
            inc BYTE PTR [rip]
            .byte 0xcb
            ```
        - When testing this, we need to make sure `.text` is writable
            - `gcc -Wl,-N --static -nostdlib -o test test.s`
    - Multi-stage shellcode
        - *Stage 1*: `read(0, rip, 1000)`
        - *Stage 2*: input anything we want
- Communicate the flag when there is no way to output data (e.g., `close(1); close(2)`)
    - ?
- The `No-Execute` bit
    - Modern architectures support memory permissions
        - `PROT_READ`
        - `PROT_WRITE`
        - `PROT_EXEC`
        - By default, the stack and the heap are not executable
    - Memory can be made executable using the `mprotect()` system call
        1. Trick the program into `mprotect()`ing (`PROT_EXEC`) our shellcode
            - Most common way is ROP
            - Other cases are situational
        2. Jump to the shellcode
    - Another injection point is JIT, Just In Time Compilation: JIT compilers need to generate and frequently re-generate code that is executed
        - JIT spraying
        - Mitigation: Sandboxing
## Data Execution Prevention

## Writing Shellcode

## Debugging Shellcode

## Forbidden Bytes

## Common Gotchas

## Cross-Architecture Shellcode
