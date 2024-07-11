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
- **Early 2000s solution**: force the VM kernel into Ring 1
- **Drawback**: have to use costly and complex emulation methods to simulate some Ring 0 actons of the guest OS
- **Modern solution**: Ring -1, *Hypervisor* Mode. Able to intercept sensitive Ring 0 actions done by guests and handle them in the host OS

#### Different types of OS models

- In a **monolithic kernel** there is a single, unified kernel binary that handles all OS-level tasks. *Drivers* are libraries loaded into this binary. Examples: Linux, FreeBSD
- In a **microkernel**, there is a tiny "core" binary that provides inter-processs communication and barebone interactions with the hardware. Drivers are normal-ish userspace programs with slightly special privileges. Examples: Minux, seL4
- In a **hybrid kernel**, microkernel features are combined with a monolithic component. Example: Windows (NT), MacOS

#### Switching between rings

- High-level overview:
    1. At bootup, in Ring 0, the kernel sets `MSR_LSTAR` to point to the syscall handler routine
    2. When a userspace (Ring 3) process wants to interact with the kernel, it can call `syscall`
        1. Privilege level switches to Ring 0
        2. Control flow jumps to value of `MSR_LSTAR`
        3. Return address saved to `rcx`
        4. [That's basically it!](https://www.felixcloutier.com/x86/syscall)
    3. When the kernel is ready to return to userspace, it calls the appropriate return instruction (i.e., `sysret` for `syscall`)
        1. Privilege level switches to Ring 3
        2. Control flow jumps to `rcx`
        3. That's basically it!

#### Kernel-Userspace Relationship

- Userspace processes have their **virtual memory** at **low** addresses
- The kernel has its own **virtual memory space**, but in **high** addresses
- System calls do **NOT** switch the virtual memory mapping, but kernel memory is only accessible from Ring 0

#### Kernel Vulnerabilities

- Code in the kernel is just code. Most of the same vulnerability concepts apply

#### Attack Lifecycle

- Kernel exploits can come from a few directions
    1. From the network: remotely-triggered exploits (packets of death, etc). Rare!
    2. From userspace: vulnerabilities in syscall and **ioctl handlers** (i.e., launched from inside a sandbox) (?)
    3. From devices: launch kernel exploits from attached devices such as USB hardware ([**Teensy USB Development Board**](https://www.pjrc.com/teensy/))
- And can achieve a number of things
    1. Act on userspace: privilege escalation, rootkits
    2. Get more access to attack other parts of the system (i.e., trusted execution environments)

#### Example: Geekpwn 2016: Root to TrustZone

- Chain of exploits of Huawei P9 leading to a complete compromise
    1. Android root
    2. Android kernel
    3. TrustZone application
    4. TrustZone kernel
- End result: modify another TrustZone module to allow phone unlock through a Noseprint!

### Environment Setup

#### Emulation

- Kernel development and exploitation can be fraught with errors. To avoid having to reboot constantly, work on a VM. We will need
    1. Compiler
    2. Kernel
    3. Userspace filesystem
    4. Emulator
- [Convenient setup](https://github.com/pwncollege/pwnkernel)

#### Debugging

- If we have a new enough version of `gdb`, and the kernel is configured with debug symbols, and kernel ASLR (Address Space Layout Randomization) is off... (Note: `ni` seems to be broken, use `si` or `finish`, instead)
    ```
    # gdb vmlinux
    (gdb) b *0x400800
    (gdb) c
    ```

#### Where is everything

- If we have root access, `/proc/kallsyms` is a list of locations of symbols (including those of loaded modules)
- If we don't have root access, we'll need to find a leak

#### Further reading

- Advanced environment setup (seems that the site is down)
- [Debugging](https://www.kernel.org/doc/Documentation/dev-tools/gdb-kernel-debugging.rst)
- [Feature-rich kernel experimentation environment](https://github.com/cirosantilli/linux-kernel-module-cheat)

### Kernel Modules

#### What is a kernel module?

- A *kernel module* is a library that loads into the kernel
- Similar to a userspace library (e.g., `/lib/x86_64-linux-gnu/libc.so.6`)
    - The module is an ELF file (`.ko` extension instead of `.so`)
    - The module is loaded into the address space of the kernel
    - Code in the module runs with the same privileges as the kernel
- Kernel modules are used to implement
    - Device drivers (graphics cards, etc)
    - Filesystems
    - Networking functionality
    - Various other stuff

#### Module Interaction

- System Calls
    - Historically, kernel modules could add system call entries through a bit of effort by modifying the kernel's system call table
    - This is explicitly unsupported in modern kernels
- Interrupts
    - Theoretically, a module could register an interrupt handler by using the `LIDT` (Load Interrupt Descriptor Table Register) and `LGDT` (Load Global Descriptor Table Register) instructions and be triggered by, say, an `int 42` instruction
    - Useful one-byte interrupt instructions to hook
        - `int3 (0xcc)` normally causes a `SIGTRAP`, but can be hooked
        - `int1 (0xf1)` normally used for hardware debugging, but can be hooked
    - A module can also hook the *Invalid Opcode Exception interrupt*
        - Can be used to implement custom instructions in software
        - Example for security retrofitting: [Youtube Video](https://www.youtube.com/watch?v=OhQacawMxoY)
    - Usually a bespoke interaction method
- Files
    - The most common way of interacting with modules is via file
        1. `/dev`: mostly traditional devices (e.g., `/dev/dsp` for audio)
        2. `/proc`: started out in System V Unix as information about running processes. Linux expanded it into a disastrous mess of kernel interfaces. The solution...
        3. `/sys`: non-process information interface with the kernel
    - A module can register a file in one of the above locations
    - Userspace code can `open()` that file to interact with the module

#### File `read()` and `write()`

- One interaction mode is to handler `read()` and `write()` for our module's exposed file
- From kernel space
    ```c
    static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
    static ssize_t device_write(struct file *filp, const char *buffer, size_t len, loff_t *off)
    ```
- From user space
    ```c
    int fd = open("/dev/pwn-college", 0);
    read(fd, buffer, 128);
    ```
- Useful for modules that deal with streams (e.g., a stream of audio or video data)

#### File `ioctl()`

- Input/Output Control provides a much more flexible interface
- From kernel space
    ```c
    static long device_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param)
    ```
- From user space
    ```c
    int fd = open("/dev/pwn-college", 0);
    ioctl(fd, COMMAND_CODE, &custom_data_structure);
    ```
- Useful for setting and querying non-stream data (e.g., webcam resolution settings as opposed to webcam video stream)

#### Driver Interaction: Inside the Kernel

- The kernel can do *anything*, and kernel modules in a monolithic kernel **are** the kernel. Anything is possible...
- But typically, the kernel:
    1. reads data from userspace (using `copy_from_user`)
    2. "does stuff" (open files, read files, interact with hardware, etc)
    3. writes data to userspace (using `copy_to_user`)
    4. returns to userspace

#### Module Compilation

- `pwnkernel` does the tedious stuff for us
    1. Write our kernel module in `src/mymodule.c`
    2. Add an entry for it on the top of `src/Makefile`
    3. `./build.sh`

#### Module Loading

- Kernel modules are loaded using the `init_module` syscall, usually done through the `insmod` utility: `# insmod mymodule.ko`

#### Listing Modules

- Loaded kernel modules can be listed using `# lsmod`

#### Module Removal

- Loaded kernel modules can be removed using the `delete_module` system call, usually done through the `rmmod` utility: `# rmmod mymodule`

#### Fantastic Kernel Modules and Where to Find Them

- `hello_log`: demonstrates the simplest possible kernel module
- `hello_dev_char`: demonstrates a module exposing a `/dev` character device
- `hello_ioctl`: exposes a `/dev` device with ioctl interface
- `hello_proc_char`: exposes a `/proc` device
- `make_root`: exposes a `/proc` device with ioctl interface and an evil backdoor

### Privilege Escalation

### Escaping Seccomp

## Kernel Security Part

### Memory Management

### Mitigations

### Writing Kernel Shellcode