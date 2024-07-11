# Kernel Security Lectures

[TOC]

## Kernel Part

### Introduction

- *What is an OS kernel?* The kernel is responsible for handling the processes' interactions with each other and with external resources
- *What are external resources?*
    - Examples of kernel-only resources
        - `hlt` instruction: shuts CPU computation
        - `in` and `out` instructions for interacting with hardware peripherals
        - Special registers
            - Control Register 3 `cr3`, which controls the *page table* used to translate virtual addresses to physical addresses. Accessed using `mov`. [Control Register](https://en.wikipedia.org/wiki/Control_register)
            - `MSR_LSTAR` (Model-Specific Register, Long Syscall Target Address Register), which defines where the `syscall` instruction jumps to. Accessed using `wrmsr` and `rdmsr`. [Materials](https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-1.html)
- *How does the computer know whether our code can access these resources?*
    - The CPU tracks a *privilege level* that controls access to resources. This is generally split into "rings" of access
        - *Ring 3*: Userspace, where we have been operating until now. Very restricted
        - *Ring 2*: Generally unused
        - *Ring 1*: Generally unused
        - *Ring 0*: The kernel. Unrestricted, supervisor mode
    - Similar to an OS tracking our user ID, the CPU tracks the current privilege level

#### Rings all the way down

- Supervisor Mode's privileges started causing issues with the rise of *Virtual Machines*. A VM's guest kernel shouldn't be able to have unlimited access to the host's physical hardware
- *Early 2000s solution*: force the VM kernel into Ring 1
- *Drawback*: have to use costly and complex emulation methods to simulate some Ring 0 actons of the guest OS
- *Modern solution*: Ring -1, *Hypervisor* Mode. Able to intercept sensitive Ring 0 actions done by guests and handle them in the host OS

#### Different types of OS models

### Environment Setup

### Kernel Modules

### Privilege Escalation

### Escaping Seccomp

## Kernel Security Part

### Memory Management

### Mitigations

### Writing Kernel Shellcode
