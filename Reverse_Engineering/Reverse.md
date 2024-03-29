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
