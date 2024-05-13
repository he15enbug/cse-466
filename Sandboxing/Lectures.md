# Sandboxing Lectures
## Background
- (1950s) First, everything ran on bare metal
    - Problem: every process was omnipotent
- (1960s) Hardware measures were developed to separate "system" and `process` code
    - Problem: processes could still clobber each other
- (1980s) Hardware measures separated the memory space of different processes
- (1990s) The rise of *in-process* separation. Separation between the interpreter and the interpreted code
- (2000s) Browser hacking
    - Process
        1. Link victim to malicious web page
        2. Trigger vulnerability
        3. Wreak havoc all over the victim machine
    - Known as a "Drive By Download". Popular "traditional" targets: Adobe Flash, ActiveX, Java Applets
- (2010s) Browser hacking mitigations
    - Original solution: eliminate traditional targets
    - Turns out that this does not solve the problem. Hackers moved on to:
        - JavaScript engine vulnerabilities
        - Media codec vulnerabilities
        - Imaging library vulnerabilities
- (2010s) The rise of sandboxing: untrusted code/data (i.e., downloaded JS, PNGs, PDFs, etc) should live in a process with *almost zero* permissions
    1. Spawn *privileged* parent process
    2. Spawn *sandboxed* child processes
    3. When a child needs to perform a privileged action, it asks the parent
- Sandboxing is extremely effective and strong
    - need one set of vulnerabilities to exploit sandboxed process
    - need another set of vulnerabilities to "break out" of the sandbox

## `chroot`
- Traditional sandbox: `chroot` jail. It used to be the de-facto sandboxing utility
- It changes the meaning of `/` for a process and its children
- `chroot("/tmp/jail")` will disallow processes from getting out of the jail
- No *syscall filtering* or other isolation
- Pitfalls
    - `chroot()` won't do anything to **previously-open** resources
        - How is this useful? Similar to `open` and `execve`, Linux has `openat` and `execveat` (and many other system calls also have "at" variants)
            - `int openat(int dirfd, char *pathname, int flags)`
            - `int execveat(int dirfd, char *pathname, char **argv, char **envp, int flags)`
            - `dirfd` can be a file descriptor representing any `open()`ed directory, or the special value `AT_FDCWD` (it is used to indicate that the current working directory should be used as the directory file descriptor). **Note** that `chroot` does not change the current working directory
    - Forgetfulness: the kernel has no memory of previous `chroot`s for a process (you can `chroot` again to escape, e.g., `chroot("../../../../")`, if the current working directory is not moved into the jail)
- Safety
    - A user with an effective ID of 0 can always break out of a `chroot`, unless the `chroot` syscall is blocked
    - Missing other forms of isolation: PID, network, IPC (*Inter-Process Communication*)
    - Replacements
        - `cgroups`
        - `namespaces`
        - `seccomp`
- Useful Reference
    - `chroot("/new/root/directory")`: set the kernel's concept of the root dirctory of a process
    - `chdir("/new/root/directory")`: set the kernel's concept of the current working directory of a process
    - `open("../../file", O_RDONLY)`, `openat(AT_FDCWD, "../../file", O_RDONLY)`: open a file relative to the current working directory

## `seccomp`
- *Syscall Filtering*: modern sandboxes *heavily* restrict permitted system calls through the use of a kernel-level sandboxing mechanism: `seccomp`
- `seccomp` allows developers to write [complex rules](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html) (also inherited by children) to:
    - Allow certain syscalls
    - Disallow certain syscalls
    - Filter allowed and disallowed system calls based on argument variables
- How does `seccomp` work
    - `seccomp` uses the kernel functionality *eBPF, extended Berkeley Packet Filters*, which are programs that run in an *in-kernel*, "provably-safe" virtual machine
    - Can instrument kernel functionality in very general ways
        - Originally used to filter network traffic (`iptables`)
        - Used to implement system-wide syscall tracing: [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)
    - Used with `seccomp()` to apply syscall filtering to processes
### Escaping `seccomp()`
- Generally, to do anything useful, a sandboxed process needs to be able to communicate with the privileged process. Normally, this means allowing the sandboxed process to use **some** syscalls. This opens up some attack vectors:
    - Permissive policies
    - Syscall confusion
    - Kernel vulnerabilities in the syscall handlers
- *Permissive Policies*
    - Combination of:
        1. System calls are complex, and there are a lot of them
        2. Developers might avoid breaking functionality by erring on the side of permissiveness
    - Well-known example: depending on system configuration, allowing the `ptrace()` system call could let a sandboxed process to "puppet" a non-sandboxed process
    - Less-known effects:
        1. `sendmsg()` can transfer file descriptors between processes
        2. `prctl()` has bizarre possible effects
        3. `process_vm_writev()` allows direct access to other process' memory
- *Syscall Confusion*
    - Many 64-bit architectures are backwards compatible with their 32-bit ancestors
        ```
        amd64 / x86_64 -- x86
               aarch64 -- arm
                mips64 -- mips
             powerpc64 -- ppc
               sparc64 -- sparc
        ```
    - On some systems, we can switch between 32-bit mode and 64-bit mode *in the same process*, so the kernel must be ready for either. Interestingly, system call numbers differ between architectures, including 32-bit and 64-bit variants of the same architecture. Policies that allow both 32-bit and 64-bit system calls can fail to properly sandbox one or the other mode
    - Example: the number for `exit()` is 60 on `amd64` (`mov rax, 60; syscall`), while 1 on `x86` (`mov eax, 1; int 0x80`)
- *Kernel Vulnerabilities*
    - If the `seccomp` sandbox is correctly configured, the attacker can still interact with the syscalls that are allowed, and try to trigger vulnerabilities in the kernel
    - [Over 30 Chrome sandbox escapes in 2019 alone](https://github.com/allpaca/chrome-sbx-db)

- Data exfiltration (e.g., the flag) even if we can't directly communicate with the outside world
    - Send "smoke signals":
        - Runtime of a process (`sleep(x)` syscall) can convey data
        - Clean termination or a crash (can convey 1 bit)
        - Return value of a program (`exit(x)`) can convey 1 byte
    - Real-world example: attackers use DNS queries to bypass network egress filters
