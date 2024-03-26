# Shellcode Injection
- level 1 to 3 have been inished in course [CSE 365](https://github.com/he15enbug/cse-365)
- *babyshell_lv4*: requires no `H` byte (`0x48`), `0x48` is the REX prefix for the 64-bit operand size and resigter extension, i.e., to eliminate `0x48`, we can not use instructions with 64-bit operands. Remember that although `push 0x61` doesn't contain byte `0x48`, it will pad `0x00` to `0x61` to make it 8 bytes, `/flag` is 5 bytes, we can push at most 4 bytes at once, but if it is padded, the `/flag` will become `/fla\0\0\0\0g` on the stack. We can use `pushw` to solve this problem. But another problem is that there are 48 non-zero bits in `rsp`, and we cannot load them to the parameter of open (`rdi`). So, the ultimate solution is to move the data at the end of our code, and use `eip` to locate them. Specifically, in my code, when executing `lea edi, [?]`, the location of the string `/flag` is at `eip+28`
- *babyshell_lv5*: the inputted data cannot contain any form of system call bytes (`syscall`, `sysenter`, `int`). We can bypass this using:
    ```
    inc BYTE PTR [rip]
    .byte 0x0e, 0x05
    ```