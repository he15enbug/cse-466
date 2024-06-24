#!/bin/bash

# Usage: ./repeat_challenge.sh 2.1
for i in {0..100000}
do
    /challenge/babyrace_level$1 my_file | grep 'pwn'
done
