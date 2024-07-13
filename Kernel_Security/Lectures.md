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

#### Kernel Memory Corruption

- Recall
    
    ```c
    copy_to_user(userspace_address, kernel_address, length);
    copy_from_user(kernel_address, userspace_address, length);
    ```

- Kernel memory must be kept uncorrupted. Corruption can
    - Crash the system
    - Brick the system
    - Escalate process privileges
    - Interfere with other processes
- All user data should be carefully handled and **only** accessed with `copy_to_user` and `copy_from_user`

#### Kernel Vulnerabilities Happen

- Kernel code is just code
- Memory corruptions, allocator misuse, etc, all happen in the kernel
- What can we do with this? Privilege Escalation

#### The Classic: Privilege Escalation

- The kernel tracks user the privileges (and other data) of every running process
    
    ```c
    struct task_struct {
        struct thread_info thread_info;

        ...

        /* Process credentials */

        /* Objective and real subjective task credentials (COW, Copy-On-Write) */
        const struct cred __rcu *real_cred;
        /* Effective (overridable) subjective credentials (COW) */
        const struct cred __rcu *cred;
    
    };

    struct cred {
        ...
        kuid_t euid; /* effective UID of the task */
        ...
    }
    ```

- How do we set these?
    - The credentials are supposed to be immutable (i.e., they can be cached elsewhere, and shouldn't be updated in place). Instead, they can be replaced: `commit_creds(struct cred *)`
    - The cred struct seems a bit complex, but the kernel can make us a fresh one
        
        ```c
        struct cred * prepare_kernel_cred(struct task_struct *reference_task_struct)
        ```

    - Luckily, if we pass NULL to the reference struct, it will give us a cred struct with root access and full privileges (?)
    - We have to run: `commit_creds(prepare_kernel_cred(0))`
- Complications
    - How do we know where `commit_creds` and `prepare_kernel_cred` are in memory?
        - Older kernels (or newer kernels when kASLR is disabled) are mapped at predictable locations
        - `/proc/kallsyms` is an interface for the kernel to give root these addresses
        - If enabled, `gdb` support is our friend
        - Otherwise, it's the exact same problem as userspace ASLR

### Escaping Seccomp

- If the `seccomp` sandbox is correctly configured, the attacker can't do anything useful... But they can still interact with the system calls that are allowed to try to trigger vulnerabilities in the kernel
- [Over 30 Chrome sandbox escapes in 2019 alone](https://github.com/allpaca/chrome-sbx-db)
- Stay tuned for Advanced Exploitation module

#### Let's dig in

- The `cred` struct is a member of `task_struct`, which also has

    ```c
    struct task_struct {
        // LOTS of stuff, including
        const struct cred __rcu *cred;
        struct thread_info thread_info;
    }

    struct thread_info {
        unsigned long flags;    /* low level flags */
        u32 status;             /* thread synchronous flags */
    }
    ```

- `flags` is a bit field that, among many other things, holds a bit named `TIF_SECCOMP`. Useful references: [the task struct](https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L632), [the flags](https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/thread_info.h#L85)
#### In Linux's syscall entry
- [Reference](https://elixir.bootlin.com/linux/latest/source/arch/x86/entry/vsyscall/vsyscall_64.c#L217)

    ```c
    /*
	 * Handle seccomp.  regs->ip must be the original value.
	 * See seccomp_send_sigsys and Documentation/userspace-api/seccomp_filter.rst.
	 *
	 * We could optimize the seccomp disabled case, but performance
	 * here doesn't matter.
	 */
	regs->orig_ax = syscall_nr;
	regs->ax = -ENOSYS;
	tmp = secure_computing();
	if ((!tmp && regs->orig_ax != syscall_nr) || regs->ip != address) {
		warn_bad_vsyscall(KERN_DEBUG, regs,
				  "seccomp tried to change syscall nr or ip");
		force_exit_sig(SIGSYS);
		return true;
	}
    ```

#### Digging into seccomp...

- [Reference](https://elixir.bootlin.com/linux/latest/source/include/linux/seccomp.h#L43)

    ```c
    static inline int secure_computing(void)
    {
        if (unlikely(test_syscall_work(SECCOMP)))
            return  __secure_computing(NULL);
        return 0;
    }
    int __secure_computing(const struct seccomp_data *sd)
    {
        // LOST of stuff, then...
        
        this_syscall = sd ? sd->nr : syscall_get_nr(current, task_pt_regs(current));

        switch(mode) {
            case SECCOMP_MODE_STRICT:
                __seccopm_computing_strict(this_syscall); /* may call do_exit */
                return 0;
            case SECCOMP_MODE_FILTER:
                return __seccomp_filter(this_syscall, sd, false);
            default:
                BUG();
        }
    }
    ```

#### Takeaway

- To escape seccomp, we just need to do (in KERNEL space):
    
    ```c
    current_task_struct->thread_info.flags &= ~(1 << TIF_SECCOMP)
    ```

- How do we get the `current_task_struct`?
    - We are in luck! The kernel points the segment register `gs` to the current task struct. In kernel development, there is a shorthand macro for this: `current`
- The plan:
    - Access `current->thread_info.flags` via the `gs` register
    - Clear the `TIF_SECCOMP` flag
    - Get the flag!
- Caveat: our children will still be `seccomp`ed (that's stored elsewhere)

## Kernel Security Part

### Memory Management

- Recall: Computer Architecture
- Recall: Process Memory
    - Each Linux process has a virtual memory space. It contains:
        - The binary
        - The libraries
        - The heap
        - The stack
        - Any memory specifically mapped by the program
        - Some helper regions
        - **Kernel code** in the "upper half" of the memory (above `0x8000000000000000` on 64-bit architectures), inaccessible to the process
    - **Virtual memory** is dedicated to our process
    - **Physical memory** is shared among the whole system
    - We can see this whole space by looking at `/proc/self/maps`

#### Physical Memory

- Physical memory is the RAM inside our computer. But there can be only one physical address `0x400100...`. To load multiple programs into memory, one solution is position independent code (like libraries). But what about isolation?

#### Virtual Memory

- Virtual memory provides different views into physical memory
- The OS kernel (in collaboration with the CPU architecture) maintains mappings between a process' virtual memory addresses and the actual addresses they correspond to in physical memory

#### How to Map Virtual and Physical Memory

- **Strawman solution**: Each process gets ... 4 KB of memory. Each process' entire virtual memory gets mapped at some place in physical memory
    - Pro: easy to track the mappings
    - Con: what if P2 needs to allocate more memory

    ```
    +-----------------------------------------+
    | P1 Memory   | P2 Memory   | P3 Memory   | <- Physical Memory
    +-----------------------------------------+
    +-----------------------------------------+
    | P1 V-Memory | P2 V-Memory | P3 V-Memory | <- Virtual Memory
    +-----------------------------------------+
    ```

- **Solution**: non-contiguous physical memory
    - Track the physical base address of pages of virtual addresses
    - The physical position of contiguous virual pages can be non-contiguous

    ```
    +-------------------------------------------------------+
    |  P1 page 1  |  P2 page 1  |  P3 page 1  |  P2 page 2  | <- Physical Memory
    +-------------------------------------------------------+
    +-------------------------------------------------------+
    | P1 V-Page 1 | P2 V-Page 1 | P2 V-Page 2 | P3 V-Page 1 | <- Virtual Memory
    +-------------------------------------------------------+
    ```

#### The Page Table

- Diving back into history, we start with the **Page Table** full of **Page Table Entries**
- Each page table holds 512 entries, mapping up to 2 MB of memory
    
    ```
    ----------------
      Page Table
    ----+-----------
    000 | 0xaa201000
    001 | 0x421e0000
    002 | 0x5c644000
    ... | ...
    511 | 0xfa115000
    ----+-----------
    ```

- What about non-contiguous virtual memory? What if we need more than 2 MB of memory?

#### Supporting Non-Contiguous Virtual Memory

- Introducing the multi-level paging structure
- A **Page Directory** contains 512 **Page Directory Entries**, each mapping a page table, each holding 512 entries, each referring a page of 0x1000 bytes, for a total of 1 GB of addressable virtual memory (`512 * 512 * 0x1000` bytes)
- **Overhead**
    - `0x1000` bytes for the PD
    - `0x1000` bytes (per PT) for each 2 MB of memory
- **Overhead Reduction**
    - By setting a special flag, a **PDE** can refer to a 2 MB region of physical memory (instead of a **PT**) (?)

#### What if we need more than 1 GB of RAM?

- A **Page Directory Page Table** contains 512 **Page Directory Pointers** addressing a total of 512 GB of RAM
- **Overhead**
    - `0x1000` for the PDPT
    - `0x1000 * 512` bytes for the PDs
- **Overhead Reduction**
    - By setting a special flag, a PDP can refer to a 1 GB region of physical memory (instead of a PD)

- 512 GB is getting small... Modern systems have **4 levels of paging**. A **Page Map Level 4** maps 512 PDPT addressing a theoretical total of 256 TB of RAM

#### A Virtual Address

- Consider `0x7fff47d4c123`. In binary:

    ```
    011111111 111111101 000111110 101001100 000100100011
        A         B         C         D         E
    
    A index into PML4 (to select PDPT)
    B index into PDPT (to select PD)
    C index into PD (to select PT)
    D index into PT (to select physical page)
    E index into page (to select physical bytes)
    ```

#### Process Isolation

- Each process has its **own** PML4. How to find it?
- The **CR3** register holds the physical location of the PML4
- **ONLY** accessible in ring0
- **Side note**: Other control registers exist, setting processor options (including whether we are in 32-bit or 64-bit mode) and lots of other craziness. [References](https://wiki.osdev.org/CPU_Registers_x86)

#### VM Isolation

- How do we isolate multiple virtual machines, the kernels of whom expect to have full access to physical memory?
- **The Extended Page Table**
- ANOTHER FREAKING ADDRESS TRANSLATION TABLE???
- Every VM thinks it has access to physical memory. In reality, each "physical" memory access is translated through the EPT analogous to a virtual memory translation
    
    ```
    EPT PML4 -> EPT PDPT -> EPT PD -> EPT PT
    ```

#### Hardware support for lookups

- It would be too slow for the kernel to do all of these lookups in software...
- Introducing the **Memory Management Unit**
- The MMU does the lookups in haardware. Blazing fast!
- Resolved addresses are cached in the **Translaton Lookaside Buffer**

#### Other Architectures

- So far, we focused on `x86`, but other architectures are analogous!
- **ARM** ([full details](https://developer.arm.com/documentation/100940/0101/)): 
    - `CR3` equivalent: `TTBR0` (for userspace) and `TTBR1` (for kernel addresses)
    - Translation tables are referred to as Level 0, 1, 2, and 3
- **Linux**: generic terminology
    
    ```
    PML4 = PGD (Page Global Directory)
    PDPT = PUD (Page Upper Directory)
     PD  = PMD (Page Mid-Level Directory)
     PT  = PT  (Page Table)
    ```

- Linux *requires* a hardware MMU (although certain forks do not)

#### The Kernel Sees All

- Processes cannot see each other's memory... But the kernel can
- **The Old Way**: old linuxes could access physical memory via `/dev/mem` as root
- **The New Way**
    - If we want to get at physical memory now, we must do it from the kernel
    - Physical memory is mapped **contiguously** in the kernel's virtual memory space for convenient access. Two kernel macros:
        - `phys_to_virt()` converts a physical address into a (kernel) virtual address
        - `virt_to_phys()` converts a (kernel) virtual address into a physical address
    - These macros are simple address additions and subtractions. **Easy to compile and reverse-engineer**

### Mitigations

- The kernel will get hacked. The Linux Kernel had 149 vulnerabilities (as tracked by CVEs) in 2021 alone. What now?

#### Many Mitigations Available

- Some are familiar:
    - **Stack canaries** protect the stack
    - **kASLR** bases the kernel at a random location *at boot*
    - **Heap/stack regions** are not executable by default
    - [The kernel's philosophy](https://www.kernel.org/doc/Documentation/security/self-protection.txt)
- With the expected bypasses:
    - **Stack canaries**: leak the canary
    - **kASLR**: leak the kernel base address
    - **Heap/stack regions**: Return Oriented Programming, ROP
- Solutions? One crazy idea in kASLR: shuffle functions around
    - **Function Granular ASLR**: upcoming mitigation to prevent kASLR bypass via trivial address disclosure. [More information](https://lwn.net/Articles/824307/)

#### Kernel-Specific Mitigation: Supervisor Memory Protection

- Many exploits trick the kernel from accessing or executing user-space memory
- **SMEP.**: prevents kernel-space code from **E**xecuting userspace memory *at all ever*
- **SMAP.**: prevents kernel-space from even **A**ccessing userspace memory unless the *AC flag* in the `RFLAGS` register is set. Two ring0 instructions, `stac` and `clac`, manage this bit
- Why separate these? There **are** cases where the kernel needs access to userspace memory (e.g., to access the `path` argument to `open()`). `copy_from_user` sets the AC flag to access userspace
- [More details](https://wiki.osdev.org/Supervisor_Memory_Protection)

#### Possible Workarounds

- Kernel exploitation is an material art, with new offensive and defensive techniques constantly being developed
- One technique to keep in mind: 
    - `run_cmd(char *cmd)`: just yolo-run a command in userspace, as root! Like `system()`, but in the kernel. [Implementation](https://elixir.bootlin.com/linux/latest/ident/run_cmd)

### Writing Kernel Shellcode
