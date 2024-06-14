# Race Condition Lectures

[TOC]

## Background

- Olden days: single core CPUs
- Modern times:
    - Multi-core, but still fewer cores than processes: the kernel decides what processes to "schedule" when
    - Limited-channel memory controllers (i.e., quad-channel memory)
    - Limited-channel storage media
    - Single-channel network communication
- Bottom line: Bottlenecks in computing architecture cause concurrent events to be at least partially serialized
- Without implicit dependencies or explicit effort by the program, the execution order is only guaranteed within a process (really, within a thread)

### TOCTOU: Time of Check / Time of Use

- Some execution orderings can be **buggy**: `P1`'s `do_action()` might be taking actions in a changed world from the one examined by `check_input()`
    ```c
    P1 check_input()
    P2 check_input()
    P2 do_action() <-- might have changed the world
    P1 do_action()
    ```
- Abusing concurrency errors requires *racing* to carefully impact the state of an application during a weak point. Hence: **Race Condition**
    ```c
    P1 check_input()
    WEAK POINT
    P1 do_action()
    ```

### History

- Race condition were originally discussed in a *hardware* context: in 1954, David Huffman, of Huffman Encoding fame, wrote about them in his PhD dissertation, "The Synthesis of Sequential Switching Circuits"

## Races in the Filesystem

### Exploiting Race Conditions

- By changing the state that a program is running while the program assumes that this state has not changed. Attackers must be able to impact said environment, one common case are **Races in the Filesystem**

### The Filesystem

- Huge window of opportunity: any point between `open()` and full startup of `/bin/sh` is an attack window
    ```c
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(fd, "#!/bin/sh\necho SAFE\n", 20);
    close(fd);
    execl("/bin/sh", "bin/sh", argv[1], NULL); // what if the file is replaced before being executed
    ```
- Much smaller window. General exploitation: slow down the victim as much as possible
    ```c
    int echo_fd = open("/bin/echo", O_RDONLY);
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0755);
    sendfile(fd, echo_fd, 0, 1024*1024);
    close(fd);
    execl(argv[1], argv[1], "SAFE", NULL); 
    ```

#### Playing Nice

- One method: `nice`: The Linux kernel's scheduler supports different priorities for different programs. The `nice` command (and `nice()` syscall) expose this functionality
- Usage: `$ nice /usr/bin/intensive_command`
- `nice` is for CPU, while `ionice` is for I/O. Using them in combination can slow down programs enough to win races

#### Path Complexity

- Not all filesystem access is equal, e.g., `cat my_file` and `cat a/b/c/d/e/f/g/h/i/j/my_file`. The kernel takes time to go into all these directories
- We can pass in SUPER long paths to slow the program down (mind that Linux has a path size limit of 4096 bytes)

##### Filesystem Mazes

- We can do better than 4096 bytes by using symbolic links: we can use paths like `/my/maze/a_end/root/b_end/root/c_end/root/my_file` to reference `/my/maze/my_file` through a huge number of directory traversals
    ```
    /my/maze/a/1/2/3/4/5/6/7/root -> /my/maze
    
    /my/maze/a_end -> /my/maze/a/1/2/3/4/5/6/7/
    
    /my/maze/b/1/2/3/4/5/6/7/root -> /my/maze
    
    /my/maze/b_end -> /my/maze/b/1/2/3/4/5/6/7/
    
    /my/maze/c/1/2/3/4/5/6/7/root -> /my/maze

    /my/maze/c_end -> /my/maze/c/1/2/3/4/5/6/7/
    ```
- Mind that Linux has a limit of 40 symbolic links per path resolution

#### Example

- CVE-2019-7307

#### Mitigations

- Safe programming practices (`O_NOFOLLOW`, `mkstemp()`, etc.)
- Symlink protections in `/tmp`
    1. `root` cannot follow symlinks in `/tmp` that are owned by other users
    2. specifically made to prevent these sorts of issues

## Processes and Threads

## Races in Memory

## Signals and Reentrancy
