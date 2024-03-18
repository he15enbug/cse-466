#include <stdio.h>
#include <stdlib.h>

/*
Usage:
gcc -shared -o lib_rd_flag.so -fPIC lib_rd_flag.c
ssh-keygen -D ./lib_rd_flag.so
*/

void C_GetFunctionList() {
    FILE *file = fopen("/flag", "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    printf("Successfully opened file: /flag\n");

    char line[256];
    if(fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }

    fclose(file);
}
