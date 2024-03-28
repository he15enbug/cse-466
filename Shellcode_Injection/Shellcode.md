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
- *babyshell_lv9*: after every 10 bytes, the program will overwrite the next 10 bytes of our shellcode with 10 `0xcc`. To bypass this, we just need to pad NOPs (`0x90`) in our code to ensure that the `0xcc`s only overwrite these NOPs, and we also need some jump instructions to jump over these `0xcc`s
    ```
    mov al, 90
    push rax
    jmp . + 17 # jump to 17 bytes ahead of the current instruction
    .fill 15, 1, 0x90
    
    mov rdi, rsp
    mov sil, 7
    syscall
    ```
- *babyshell_lv10*: input will be sorted
- *babyshell_lv11*: input will be sorted, and stdin is closed. It seems like that there is a bug in level 10 and 11, the input actually won't get sorted
- *babyshell_lv12*: every byte in our shellcode should be unique
    ```
    | Bytes     | Instructions |
    ----------------------------
    | b0 5a     | mov al, 0x5a |
    | 50        | push rax     |
    | 48 89 e7  | mov rdi, rsp |
    | 40 b6 07  | mov sil, 7   |
    | 0f 05     | syscall      |
    ```
- *babyshell_lv13*: only 12 bytes for the shellcode. Luckily, the shellcode for the previous task (level 12) is already 11 bytes
- *babyshell_lv14*: only 6 bytes for the shellcode. The basic idea is to use 2-stage shellcode, the stage-1 shellcode will run `read(0, rip, size)` to read in the stage-2 shellcode that read the flag or make it readable to all users. If we directly `mov rsi, <address>` or `lea rsi, [rip+offset]`, we cannot make our stage-1 shellcode less or equal to 6 bytes, we need to reuse the values that are already stored in some registers at the time the challenge program execute our stage-1 shellcode. By debugging the program, we can know that the program put the address of the stage-1 shellcode `0x2f5ad000` into `rdx`, and then `call rdx`. At this point, `rax` is zero, `rdi` is non-zero. What we need: `rax` should be 0, `rdi` should be 0, `rsi` should be the address right after the stage-1 shellcode, `rdx` can be any value that are large enough to ensure the stage-2 shellcode can be read in
    - stage-1 shellcode
        ```
        # rax is already 0
        mov edi, eax # the first parameter of read is 32-bit, we only need to clear edi
        mov esi, edx
        # rdx is already large enough
        syscall
        ```
    - stage-2 shellcode: just reuse any shellcode from previous tasks
