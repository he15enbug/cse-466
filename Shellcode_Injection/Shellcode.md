# Shellcode Injection
- level 1 to 3 have been inished in course [CSE 365](https://github.com/he15enbug/cse-365)
- *babyshell_lv4*: requires no `H` byte (`0x48`), `0x48` is the REX prefix for the 64-bit operand size and resigter extension, i.e., to eliminate `0x48`, we can not use instructions with 64-bit operands. Remember that although `push 0x61` doesn't contain byte `0x48`, it will pad `0x00` to `0x61` to make it 8 bytes, `/flag` is 5 bytes, we can push at most 4 bytes at once, but if it is padded, the `/flag` will become `/fla\0\0\0\0g` on the stack. We can use `pushw` to solve this problem. But another problem is that there are 48 non-zero bits in `rsp`, and we cannot load them to the parameter of open (`rdi`). So, the ultimate solution is to move the data at the end of our code, and use `eip` to locate them. Specifically, in my code, when executing `lea edi, [?]`, the location of the string `/flag` is at `eip+28`
- *babyshell_lv5*: the inputted data cannot contain any form of system call bytes (`syscall`, `sysenter`, `int`). We can bypass this using:
    ```
    inc BYTE PTR [rip]
    .byte 0x0e, 0x05
    ```
- *babyshell_lv6*: this time, our shellcode cannot contain any form of system call bytes, and the first 4096 bytes of the shellcode is no longer writable, that means we cannot modify the code at runtime
    - One solution is to find an *ROP gadget* in the binary of the challenge program, or the libraries it loads. What we want to find is `syscall; ret;` (`0f05c3`), before we jump to the `syscall`, we can push current `rip` on to the stack, such that after the system call, `ret` will jump back. But since the address of the program in `gdb` is slightly different from running the program directly, this solution is not easy
    - Another solution is straightforward, we pad 4096 NOPs (`0x90`) at the beginning of our shellcode, so that the bytes `0e05` is at a writable memory address, we can make them `0f05` at runtime
- *babyshell_lv7*: all file descriptors are closed, so we cannot directly open and send `/flag` to the standard output. But what we can do is change the permission of `/flag`: `execve("/bin/chmod", {"/bin/chmod", "777", "/flag", NULL}, NULL)`. We can store the data on the stack or at the end of our shellcode
- *babyshell_lv8*: this time, the challenge program only accept the first 18 bytes of our shellcode. Use `chmod(const char* pathname, mode_t mode)` system call, to save space, we should choose a short file name (and create a symbolic link to `/flag`)
    1. `ln -sf /flag Z` (choose `Z` because it is `90` (`0x5a`), the same as the number of `chmod` system call, we can reuse it)
    2. the shellcode generated from:
        ```
        mov al, 90
        push rax
        mov rdi, rsp
        mov rsi, 7
        syscall
        ```
    3. input the shellcode to the challenge program, it will modify the permission of `/flag` (for all other users) to `7` (`rwx`), then we can read the flag
- *babyshell_lv9*