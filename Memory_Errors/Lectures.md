# Memory Errors Lectures
## High-level problems
1. Trusting the developer
2. Mixing control information and data
3. Mixing data and metadata
4. Initialization and cleanup
## Smashing the stack
- Two causes for stack overflow
    1. Lazy/insecure programming practices: `gets`, `strcpy`, `scanf`, `printf`, etc
    2. Passing pointers around without their size. Even if we wanted to use a safe function (such as `snprintf`), there was not enough information
- What can we corrupt
    1. Memory that is used in a **value** to influence mathematical operations, conditional jumps, etc
    2. Memory that is used as a **read pointer** (or offset), allowing us to force the program to access arbitrary memory
    3. Memory that is used as a **write pointer** (or offset), allowing us to force the program to overwrite arbitrary memory
    4. Memory that is used as a **code pointer**, allowing us to redirect program execution (e.g., the return address of the current function on stack)
## Causes of memory corruption
- Classic buffer overflow
- Signedness mixups
    - `jae` is unsigned comparison, and `jge` is signed comparison
    - The standard C library uses *unsigned integers* for sizes, but the default integer types (`short`, `int`, `long`) are *signed*
    - In the following code, `size` is a signed integer, the underlying instruction for `>` will be `jge`. If we input `-1`, `size > 16` will be false, but in `read(0, buf, size)`, the size will be interpreted as an unsigned integer `0xffffffff`
        ```
        int size;
        scanf("%i", &size);
        if(size > 16) exit(1);
        read(0, buf, size);
        ```
- Integer overflows: what if `size` is the maximum value of `unsigned int`?
    ```
    unsigned int size;
    scanf("%i", &size);
    char *buf = alloca(size + 1);
    int n = read(0, buf, size);
    buf[n] = '\0';
    ```
- Off-by-one errors
    ```
    int a[3] = {1, 2, 3}
    for(int i = 0; i <= 3; i++) a[i] = 0; // i <= 3 can cause overflow
    ```
## Stack canaries
- In function prologue, write random value at the end of the stack frame (right before the return address)
- In function epilogue, make sure this value is still intact
- Situational bypass methods
    1. Leak the canary (using another vulnerability)
    2. Brute-force the canary (for forking processes)
        ```
        char buf[16];
        while(1) {
            if(fork()) wait(0);
            else {
                read(0, buf, 128);
                return;
            }
        }
        ```
    3. Jumping the canary (if the situation allows)
        ```
        char buf[16];
        int i;
        for(i = 0; i < 128; i++) read(0, buf + i, 1); // depending on the stack layout, we can overwrite i and redirect the read to point to after the canary
        ```

## ASLR, Address Space Layout Randomization
- First appeared in 2001 as part of a Linux kernel patch set called PaX
- Written by a team led by an anonymous coder
- **Workarounds**: how do we redirect execution if we don't know where any code is
    1. Leak
        - The addressed still (mostly) have to be in memory so that the program can find its own assets
    2. YOLO
        - Program assets are page-aligned
        - Overwrite just the page offset
            - Pages are always aligned to a `0x1000` alignment
            - Possible page addresses: `0x...000`, the last three nibbles of an address are always `000`
            - If we overwrite the 2 least significant bytes of a pointer, we only have to brute-force one nibble (16 possible values) to successfully redirect the pointer to another location on the same page
        - Requires some brute-forcing
    3. Brute-force (situational)
        ```
        char buf[16];
        while(1) {
            if(fork()) wait(0);
            else {
                read(0, buf, 128);
                return;
            }
        }
        ```
- Disabling ASLR for local testing
    - In pwntools: `pwn.process('./vul_prog', aslr = False)`
    - `gdb` will disable ASLR by default if it has permissions to do so. NOTE: for Set-UID binaries, remove the SUID bit before using `gdb` (`chmod` or `cp`)
    - Spin up a shell whose (non-setuid) children will all have ASLR disabled
        - `# setarch x86_64 -R /bin/bash`
## Causes of disclosure
- Buffer overread
- Termination problems
    ```
    char name[10] = {0};
    char flag[64];
    read(open("/flag", 0), flag, 64);
    printf("Name: ");
    read(0, name, 10);
    printf("Hello %s!\n", name); // If the input is 10 bytes, name will not contain a 0x00 byte at the end, and the flag will also be printed out
    ```
- Uninitialized data
    - See this with compiler optimizations
    ```
    int main() { foo(); bar();}
    void foo() {
        char foo_buffer[64];
        read(open("/flag", 0), foo_buffer, 64);
        memset(foo_buffer, 0, 64);    
    }
    void bar() { char bar_buffer[64]; write(1, bar_buffer, 64); }
    ```
