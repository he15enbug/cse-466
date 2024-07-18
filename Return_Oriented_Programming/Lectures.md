# Return Oriented Programming Lectures

[TOC]

## Introduction

### Recap: The "No-eXecute" bit

- Modern architectures support memory permissions:
    - **PROT_READ** allows the process to read memory
    - **PROT_WRITE** allows the process to write memory
    - **PROT_EXEC** allows the process to execute memory
- Intuition: *normally*, all code is located in `.text` segments of the loaded ELF files. There is no need to execute code located on the stack or in the heap
- By default in modern systems, the stack and heap are NOT executable
- In the absence of Code **Injection**, we turn to Code **Reuse**

### Blast from the past: Return-to-libc

- In the old times (x86_32), arguments were passed on the stack. During a stack-based buffer overflow, we could overwrite the return address *and* the arguments

    ```
    +-------------+
    |     ...     |
    +-------------+
    |  vuln arg3  | <-- overwrite with argument of the libc function
    +-------------+
    |  vuln arg2  | <-- overwrite with argument of the libc function
    +-------------+
    |  vuln arg1  | <-- overwrite with a fake address
    +-------------+
    |   ret_addr  | <-- overwrite with libc function
    +-------------+
    | previous ebp| <-- padding
    +-------------+
    | vuln buffer | <-- padding
    +-------------+
    ```

- Why is this a blast from the past? Modern architectures don't take arguments on the stack. Game over? No. 
- **Solution**: Find ROP gadgets to load values into registers

## Binary Lego

### ROP by induction

- **Step 0**: overflow the stack
- **Step n**: by controlling the return address, we trigger an ROP gadget: `0x004005f3: pop rdi; ret`
- **Step n+1**: when the gadget returns, it returns to an address we control (i.e., the next gadget)

### Take-away: ROP is *basically* shellcode

- A ROP gadget is equivalent to shellcode, but the instructions available to us are WEIRD
- Hacker term: Programming the [Weird Machine](https://en.wikipedia.org/wiki/Weird_machine), coined in 2009 by Sergey Bratus
- Related concept: [accidental turing completeness](https://beza1e1.tuxen.de/articles/accidentally_turing_complete.html)
- Fundamentally:
    - We get to choose from a set of bizarre meta-instructions already in memory
    - We can chain instructions using `ret` (and addresses on the stack)
    - Same lego pieces, new result

## Techniques

## Complications
