# Sandboxing
- *babyjail-level1*: the program takes the file path as parameter, and display its content. The program will use `chroot` to sandbox the process. Use `../../../../../../flag` as parameter (use enough `../` to ensure that we reach the root path)
- *babyjail-level2*: the program takes our shellcode as input, and run it. We only need to construct the shellcode that opens and prints out `../../../../flag` to stdout, and input it to the challenge program
- *babyjail-level3*
- *babyjail-level4*