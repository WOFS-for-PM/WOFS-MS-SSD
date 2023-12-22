#include <fcntl.h>
#include <stdio.h>

int main() {
    printf("Hello, World!\n");

    int fd = open("test.txt", O_RDWR);
    if (fd == -1) {
        printf("Error opening file\n");
        return 1;
    }

    return 0;
}