#include <stdio.h>

int main() {
    int x;
    char buf1[64];
    char buf2[64];

    printf("x: %p\n", &x);
    printf("buf1: %p\n", buf1);
    printf("buf2: %p\n", buf2);
    return 0;
}
