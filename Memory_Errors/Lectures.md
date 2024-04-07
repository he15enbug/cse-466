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
