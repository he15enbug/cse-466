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

## Techniques

## Complications
