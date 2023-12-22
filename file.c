#define _GNU_SOURCE
#include <fcntl.h>

#include "killer.h"

int hk_open(const char *pathname, int flags, ...) {
    int fd = open("/dev/nvme0n1p1", O_RDWR | O_DIRECT);
    if (fd == -1) {
        return 1;
    }
    return 0;
}

int hk_close(int fd) {
    return 0;
}

ssize_t hk_read(int fd, void *buf, size_t count) {
    return 0;
}

ssize_t hk_write(int fd, const void *buf, size_t count) {
    return 0;
}

int hk_lseek(int fd, int offset, int whence) {
    return 0;
}
