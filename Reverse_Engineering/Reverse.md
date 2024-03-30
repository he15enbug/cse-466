# Reverse Engineering
- *babyrev_level12.0*: this challenge is an custom emulator that emulates a completely custom architecture called "Yan85". This challenge is straightforward, debug the program and find the parameters of `memcmp()`, my input is `"123\n"`
    ```
    1: x/1i $rip
    => 0x55c4e42b101b <execute_program+208>:        call   0x55c4e42b0130 <memcmp@plt>
    2: x/8xb $rdi
    0x7ffd4730a64f: 0x70    0x28    0xd7    0x94    0xd6    0x02    0x97    0x71
    3: x/8xb $rsi
    0x7ffd4730a62f: 0x31    0x32    0x33    0x0a    0x00    0x00    0x00    0x00
    ```
    - So, the correct key should be `"\x70\x28\xd7\x94\xd6\x02\x97\x71"`
- *babyrev_level12.1*: still straightforward, this time we only need 4 bytes input
    ```
    (gdb) x/8bx $rsi
    0x7fff1034afba: 0x31    0x32    0x33    0x34    0x00    0x00    0x00    0x00
    (gdb) x/8bx $rdi
    0x7fff1034afda: 0xf6    0xc9    0x11    0xf5    0x00    0x00    0x00    0x00
    ```
- *babyrev_level13.0*: VM-based obfuscation. There are some VM code, but we don't need to reverse those code because we are clever, just go to the `memcmp()` and check its parameters. My input is `12345667`, the challenge compares my input directly with the key, without any process
    ```
    (gdb) x/8bx $rsi
    0x7ffecd1a3004: 0x31    0x32    0x33    0x34    0x35    0x36    0x36    0x37
    (gdb) x/8bx $rdi
    0x7ffecd1a3024: 0x10    0x56    0xf9    0x84    0x5e    0xd5    0xd8    0x10
    ```
- *babyrev_level13.1*: same as the 13.0, debug it and get the key
    ```
    (gdb) x/8bx $rdi
    0x7ffc819908a1: 0xb9    0xf8    0x6c    0x1b    0xe5    0x5a    0xa6    0x95
    ```
- *babyrev_level14.0*: same as 13.0
- *babyrev_level14.1*: same as 13.1
- *babyrev_level15.0*: same as 14.0
- *babyrev_level15.1*: same as 14.1
- *babyrev_level16.0*: from now on, we have to reverse the VM code even if we are clever. In this challenge, there is no `memcmp()`, but there are a few functions: `interpret_sys()`, `interpret_imm()`, `interpret_cmp()`, `interpret_add()`, `interpret_ldm()`, ...
    - Before each time a function with the prefix `interpret_` was called, the value passed to `rdi` is always `QWORD PTR [rbp-0x18]` (the `rbp` is the base pointer of the stack frame for `execute_program()`)
    - `interpret_sys()`: in this function, there are s