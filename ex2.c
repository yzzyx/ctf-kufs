#include <stdio.h>
#include <string.h>


void copystr(char *str) {
    int x;
    char buf1[64];
    char buf2[64];
    strcpy(buf2, str);

    printf("x: %p\n", &x);
    printf("buf1: %p\n", buf1);
    printf("buf2: %p\n", buf2);
}

int main(int argc, char *argv[], char *envp) {

    if (argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        return -1;
    }

    printf("envp: %p\n", envp);
    copystr(argv[1]);

    return 0;
}

