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

### Processes

- Processes have their own:
    - Virtual Memory
        - Stack
        - Heap
        - etc.
    - Registers
    - File descriptors
    - Process ID
    - Security properties
        - `uid`
        - `gid`
        - `seccomp` rules

### Threads

- A process can have multiple threads (and has at least its main thread)
- Threads share:
    - Virtual memory (exclude stack)
    - File descriptors
- But have their own
    - Registers
    - Stack
    - Thread ID
    - Security properties: `uid`, `gid`, `seccomp` rules

#### Creating Threads

- **High level**
    - Threads can be created and managed using many different high-level libs, e.g., `pthread`
        ```c
        void *thread_main(int arg) {
            printf("Thread %d, PID %d, TID %d, UID %d\n", arg, getpid(), gettid(), getuid());
        }
        main() {
            pthread_t thread1, thread2;
            pthread_create(&thread_1, NULL, thread_main, 1);
            pthread_create(&thread_2, NULL, thread_main, 2);
            printf("Main thread: PID %d, TID %d, UID %d\n", getpid(), gettid(), getuid());
            pthread_join(thread1, NULL);
            pthread_join(thread2, NULL);
        }
        ```
    - Execution order between threads is not deterministic
- **Low level**
    - At low level, threads are created using the `clone()` system call
    - `clone()` is the successor of `fork()`, allowing for more control over what is shared between the parent and child
    - The `pthread_create()` library function uses `clone()` syscall to create a child process that shares memory and other resources with the parent
    - `clone()` can do other things, e.g., starting containers with `CLONE_NEWNS`

#### Discrepancies (between `libc` and the Linux system call interface)

- Examples:
    - `setuid`: the `libc` syscall wrapper will set the UID of all the threads of the process, but the Linux syscall only set the UID of the caller thread
    - `exit`: the `libc` syscall wrapper will actually call the `exit_group()` syscall to terminate all the threads, while the Linux syscall only terminates the caller thread

#### Terminating Threads

- A common practice is to communicate with threads using global variables. It might be unsafe to access global memory from multiple threads. It might cause *Races in Memory*

## Races in Memory

### Motivating Example

- Consider the following: what if check 1 and check 2 are passed, we provide a value larger than or equal to 16 for `read(0, &size, 1)` before executing `read(0, buffer, size)`
    ```c
    unsigned int size =42;
    void read_data() {
        char buffer[16];
        if(size < 16) { <------- Check 1
            printf("Valid size! Enter payload up to %d bytes.\n", size);
            printf("Read %d bytes!\n", read(0, buffer, size));
        }
        else printf("Invalid size %d!\n", size);
    }

    void *thread_allocator(int arg) {
        while(1) read_data();
    }

    main() {
        pthread_t allocator;
        pthread_create(&allocator, NULL, thread_allocator, 0);
        while(size != 0) read(0, &size, 1); <------- Check 2
        exit(0);
    }
    ```

### Special Case: Double Fetch

- `copy_from_user()` in kernel space: sometimes, kernel developers make mistakes
    ```c
    int check_safety(char *user_buffer, int maximum_size) {
        int size;
        copy_from_user(&size, user_buffer, sizeof(size));
        return size <= maximum_size;
    }
    static long device_ioctl(struct file *file, unsigned int cmd, unsigned long user_buffer) {
        int size;
        char buffer[16];
        if(!check_safety(user_buffer, 16)) return;
        copy_from_user(&size, user_buffer, sizeof(size));
        copy_from_user(buffer, user_buffer+sizeof(size), size);
    }
    ```
- This is a TOCTOU, with the race between the kernel and a sibling thread of the caller

### Othre Data Races

- General data races can have weird effects
    ```c
    unsigned int num = 0;
    void *thread_main(int arg) {
        while(1) {
            num++;
            num--;
            if(num != 0) printf("NUM: %d\n", num);
        }
    }
    main() {
        // create and run 2 threads
    }
    ```
### Preventing Data Races

- Utilizing *mutexes* (inter-thread locks): a block of code protected by mutexes is called *critical section*

### Detecting Data Races

- **valgrind** has two tools: `helgrind` and `drd`, both detect data races if the relevant code is triggered by test cases
- In general, this problem remains unsolved. A recent example: `CVE-2020-12652`, a double-fetch bug in an `ioctl` handler in the Linux kernel

## Signals and Reentrancy
