# Sandboxing

## babyjail-level1

- The program takes the file path as parameter, and display its content. The program will use `chroot` to sandbox the process. Use `../../../../../../flag` as parameter (use enough `../` to ensure that we reach the root path)

## babyjail-level2

- The program takes our shellcode as input, and run it. We only need to construct the shellcode that opens and prints out `../../../../flag` to stdout, and input it to the challenge program

## babyjail-level3

- The challenge moves the current directory into the jail, so we cannot use `../../../../` to get to the root path of the system. `chroot('/')` to escape. But a vulnerability is that before it changes the root and current directory, it will open a file or directory specified by us in the argument. We can open `/` (the root path of the system), then, we can use `openat(root_fd, 'flag', O_RDONLY)` to open `/flag` (the real flag) even inside this `chroot` jail

## babyjail-level4

- Same setting as in level 3, but allows only the following syscalls: ["openat", "read", "write", "sendfile"]. Luckily, we only used `openat` and `sendfile` in level 3, so we can directly use the code in level 3 to solve level 4

## babyjail-level5

- Use `dir_fd = open('/', 0, 0)` (inside the `chroot` sandbox), `linkat(3, 'flag', dir_fd, 'xxx')`, `flag_fd =  open('/xxx', 0, 0)`, then `sendfile(1, flag_fd, 0, 1000)`

## babyjail-level6

- Use `fchdir(dir_fd)` to switch to the real root (that we previously opened)

## babyjail-level7

- We can only use these system calls: ["chdir", "chroot", "mkdir", "open", "read", "write", "sendfile"]. None of `chroot`, `chdir`, and `mkdir` takes file descriptor as input, how can we take the advantage of the previously opened directory (`/`, or something else that we can specify)? We cannot. But one thing important is that when current working directory is not inside the chroot jail, we can use `../../../../` to get the root path of the OS, we can `mkdir` a new directory inside the jail, and `chroot` to the new directory, this will not change the current working directory, i.e., our current working directory is now outside the jail!

## babyjail-level8

- We can only use these system calls: ["openat", "read", "write", "sendfile"]. But unlike level 4, in this challenge, it will no longer open a directory before changing the root and current working directory, so we cannot use `openat(3, 'flag', 0)` to escape the jail. We can open `/` (with FD `3`) when running the challenge using `exec`: `exec 3</ /challenge/babyjail_level8 < shellcode-raw`. The assembly code for level 4 can be reused. Note that when the command finishes, the terminal will be closed. To be able to copy the flag, we can save the output into a file: `(exec 3</ /challenge/babyjail_level8 < shellcode-raw) > flag.txt`

## babyjail-level9

- Allowed system calls: [`close`, `stat`, `fstat`, `lstat`], the challenge will not open a file for us before it creates a `chroot` jail. The tricky part is that this challenge allows only syscall number `3`, `4`, `5`, and `6`, and it uses`seccomp` to apply the filter for `x86_32` architecture. In `x86_32`, these numbers are actually the following system calls: `read`, `write`, `open`, and `close`, so we can directly open, read, and write the flag. Mind that the calling convention for `x86_32` is to pass the arguments using `ebx`, `ecx`, `edx`... And we can use `int 0x80` to make a system call

## babyjail-level10

- This challenge only allows `read` and `exit` system call, and it will open a file for us before `chroot`ing. There is a side channel to leak the flag from memory, that is, we `read` the opened flag file, and using 1 byte of the flag as the parameter of `exit`, so we are able to learn 1 byte of the flag each time

## babyjail-level11

- We can only use `read` and `nanosleep`. Similarly, we can use each byte of the flag as the parameter for `nanosleep`, and measure the time the shellcode runs to probe the value of that byte. It might be difficult to get the precise time in nanoseconds, we can multiply the byte by a large number, e.g., `10000000`, and we just need to count the number of `0.01 second`s it tooks to run the shellcode. If the result is still not so precise, we can multiply a larger number. The idea is straightforward, to save time, I didn't implement this, instead, I directly used the solution for level 12, which can extract the flag using only `read` syscall

## babyjail-level12

- This time we can only use `read` system call. We can enumerate the value of each byte of the flag, and compare it with the content in memory. The point is how to know the comparing result. This challenge only allows us to use `read` system call, after our shellcode finished, there will be a segment fault (exit number `-11`). If we run a system call that is not allowed, the exit number will be `-31`, this is a side channel that we can take advantage of. To improve the effeciency, we can use `multiprocessing`

## babyjail-level13

- The point is to figure out the commands that the parent process can parse. If we send `pring_msg:content` to the parent, it will print out the content. If we send `read_file:/flag` to the parent will read the file `/flag`, and send its content back to the socket pair (i.e., we can then read the content to memory using `read` syscall with FD `4`). With this information, it would be not difficult to escape this sandbox. We can let the parent process to load the flag into memory using `read_file:/flag\0`, then we append the string `print_msg:` to the flag in memory, and send the appended content to the parent process, which will then print out the content of the flag

## babyjail-level14

- Now we start to try to escape sandboxes implemented using modern namespacing techniques. Before starting level 14 to 18, watch the *Namespacing Live Session 1 & 2*

## babyjail-level15

## babyjail-level16

## babyjail-level17

## babyjail-level18
