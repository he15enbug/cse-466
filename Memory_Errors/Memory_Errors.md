# Memory Errors
- *babymem_level4.0*: There is a check on the payload size to ensure our input won't overflow the buffer. We can bypass it by given a payload size `-1`, the challenge uses a signed integer to hold this, which will treat this value as `-1`, so we can pass the check. But for the `read` function, it will treat `-1` as an unsigned integer `0xff...fff`, which is enough for us to reach the return address
    - `rbp = 0x7ffcb4903d50`
    - `&buffer = 0x7ffcb4903d00 (rbp-0x50)`
    - `&win = 0x4024bc`
- *babymem_level4.1*: use the same method as the previous challenge to bypass the payload size check. This time, no address information is provided, we need to `gdb` the challenge to figure out those information
    - `rbp = 0x7fffca526940`
    - `&buffer = 0x7fffca526900 (rbp-0x40)`
    - `&win = 0x401b01`
- *babymem_level5.0*: we are allowed to input multiple payload records, and they will be concatenated together. There is a size check to ensure the total size of the payload fits in the buffer. By debugging the challenge program, we can know that it only checks whether `record_size * record_num < 8`, if we input `-1` and `-1`, we can bypass this check. But another problem is that, the input is 32-bit, the `read()` will take a 64-bit value as its third parameter, `0xffffffff` in 64-bit registers will be a positive number, and the result is very large. When `rdx` is large, `read()` will not read anything, and return a negative result. I am not sure the reason for this yet, but we need to find another way. Take advantage of integer overflow. For example, `record_size = INT32_MIN`, `record_num = 2`, `record_size * record_num` will get `0`
    - `rbp = 0x00007ffc1284b0d0`
    - `&buffer = 0x7ffc1284b080 (rbp-0x50)`
    - `&win = 0x401b01`   
- *babymem_level5.1*: use the same method
    - `rbp = 0x00007ffcca645050`
    - `&buffer = 0x7ffcca644fd0 (rbp-0x50)`
    - `&win = 0x401453`

- *babymem_level9.0*: this time the stack canary is enabled. The core logic of the challenge is `while(n < size) n += read(0, input + n, 1);`, we can use this to overwrite local variable `n` to jump over the canary and overwrite the return address directly. The program is position indepentdent, that means each time we run it, the address of `win_authed` function varies. But due to memory alignment, the first 48 bits of `&win_authed` and the original return address are always the same, and the last 2 bytes of `&win_authed` are `0x?5f5`, so we only need to brute-force this `?` (there are 16 cases), specifically, we fix `?` to a number, and keep running the challenge again and again, until we hit the correct `win_authed` address
    - `&buffer = rbp - 0x70`
    - `&n = &buffer + 100`
    - `&ret_addr = &buffer + 120`
    - `&win_authed = (<OriginalReturnAddress> & 0xffffffff0000) + 0x?5f5`
    - We need to jump over the canary, and modify the 2 bytes from `&buffer + 120` to `0xf5` and `0x?5`, respectively
    - The initial value of `n` is zero, we need to overwrite the buffer, such that after one `n += read(0, input + 0, 1)` instruction, `n` becomes 120 (`0x78`). Then we can input the 2 bytes. `read(0, input + 0, 1)` allows us to input at most 1 byte. First, we need to write 100 bytes to reach the position of `n`, then we need to write a specific value `0x77` to the location, and `n = 0x77+0x01 = 0x78`, we can then write the 2 bytes `0xf5` and `0xa5`
    - An important thing is that there is a check on `edi` in `win_authed`, it only opens and prints out the flag when `edi` is `0x1337`, so we need to figure out how to set `edi` before the `challenge` returns. Unfortunately, we cannot modify `edi` to what we want. Fortunately, we can just jump to a position after that check in `win_authed`, e.g., jump to `win_authed+28` (`0x...?611`)
- *babymem_level9.1*: 
    - `win_authed+28` at `0x...?98c`
    - `&n - &buffer = 0x7ffd906b02bc - 0x7ffd906b02a0 = 28 = 0x1c`
    - `&ret_addr - &buffer = 0x7ffd906b02d0 - 0x7ffd906b02a0 + 8 = 0x38`
- *babymem_level11.0*: the flag will be loaded into memory, but at no point it will be printed out. The input buffer will be stored in an mapped page of memory. The flag is `0x8000` bytes after the address of the buffer, but I could only input `0x1000` bytes of data. I finally figured out that this limit `0x1000` is not set by the challenge, but `printf` (I used `printf "..." | /challenge/...` to run the challenge). Use `(echo "32768"; python3 -c "print('a' * 0x8000)") | /challenge/babymem_level11.0`
- *babymem_level11.1*: debug the program to get the address information
- *babymem_level12.0*: we need to bypass the canary by utilizing a backdoor in the binary to overwrite the return address and get `win_authed` to be executed
    - `&buffer = rbp-0x60`
    - `&ret_addr = rbp+0x08`
    - `&canary = rbp-0x08`
    - `&win_authed+28 = 0x...?1fc`
    - Here is what the backdoor does: It calls `strstr@plt` function, which searches string `"REPEAT"` in our input, if `"REPEAT"` doesn't occur, the `challenge` function checks the canary and returns. Otherwise, it will call `challenge` again, with parameters: `edi = DWORD PTR [rbp-0x84]`, `rsi = QWORD PTR [rbp-0x90]`, `rdx = QWORD PTR [rbp-0x98]` (actually, these are the parameters saved at the beginning of the `challenge`)
    - Note that the `rbp (1st challenge) = rbp (2nd challenge) + 0xb0`
        ```
        +0x08 (ret_addr1)
        0x00 (rbp1)
        -0x08 (canary)
        ...
        -0x60 (buffer1)
        ...
        -0xa8 (ret_addr2)
        -0xb0 (rbp2)
        -0xb8 (canary)
        ...
        -0x110 (buffer2)
        ```
    - As far as I know, there is no way we can jump over the canary and write the return address in this situation. Instead, I noticed that in each run of `challenge`, the value of canary is the same, if we can cause the program to leak the canary (this may somehow modify part of the canary, but the next `challenge` is called before it checks the canary, so we can still get the flag before the program crashes), and in the next `challenge`, we can construct a payload to write this canary and then the target return address
- *babymem_level12.1*: debug the program to find the key offset information, use the same method as level 12.0
- *babymem_level13.0*: In `challenge`, e can find that some data is left in the stack frame, that means those data are not initialized after last use. By observing `main` function, we can see that there is a function `verify_flag`, which opens and read the content of `/flag` to memory, the address is `0x7ffd8421d97a`, then we can get `&buffer` in `challenge`, it is `0x7ffd8421d950` (i.e., `&flag=&buffer+0x2a`), we can pad non-zero bytes to the buffer until we reach the flag
- *babymem_level13.1*: debug the program, find the offsets, leak the flag!
- *babymem_level14.0*: this challenge is like a combination of level 13 and 12. This time, we cannot directly pad non-zero bytes to the canary to leak it, because to do that we need to pad 377 bytes, but the program prints out our input using format string `"%.371s"`, which will print out at most 371 bytes. We can also find the value of the canary at `&buffer+216` and `&buffer+104`
- *babymem_level14.1*: debug the program, find the offsets, leak the flag!
- *babymem_level15.0*: This challenge is listening for connections on TCP port 1337. We can use `nc` command to send data to it. 15.0 is easy as it prints out the value of the canary, and in the same run of the challenge, each connection we created uses the same value for the canary, and the address of `win_authed` is fixed
    - `&canary=&buffer+56`
    - `&win_authed+28=0x71e4`
    - `canary=0x1040006c898c7200` (little endian: `00 72 8c 89 6c 00 40 10`)
    - Initial exploit: `(echo "74"; python -c "print('a' * 56 + '\x00\x72\x8c\x89\x6c\x00\x40\x10' + 'a'*8 + '\xe4\x71')") | nc localhost 1337`. A problem here is that sending the of output `print` of python to `nc` only works for bytes less than `0x80`, e.g., if we use `python -c "print('\x81')" | nc host port`, it will actually send `0xc2 0x81`. A solution is to use `echo -e '\x81'`. So, the payload that works is: `(echo "74"; echo -e 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x72\x8c\x89\x6c\x00\x40\x10aaaaaaaa\xe4\x71') | nc localhost 1337`
- *babymem_level15.1*: we need to brute force 2 values, the address of `win_authed`, and the stack canary. Luckily, we can brute force them separately. First, the canary, to find out the canary, we can try payload with different length, until there is a `SIGABRT` (or we can do it manually with `(echo "100"; python -c "print('a'*100)" | nc localhost 1337)`, and see if there is a `*** stack smashing detected ***: terminated`). We can know that `&canary=&buffer+104`
    - Then, we can start to brute force the canary, actually we can do this one byte a time, and the first byte is always `0x00`. We start from the second byte, i.e., use a payload of 106 bytes: `'a'*104 + '\x00\x??'`. The canary is (little endian) `\x00\na\xda\x02\x9d\xd4\x00`
    - The address of `win_authed` is fixed in each run of the challenge, `gdb` it and we can know that `&win_authed=0x...?f4e`, we only need to try 16 cases to get the correct address
