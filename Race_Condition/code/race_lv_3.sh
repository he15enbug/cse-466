#!/bin/bash

for i in {0..100000}
do
    printf 'a%.0s' {1..900} > my_file
    printf '' > my_file
done
