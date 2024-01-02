#define _GNU_SOURCE
#include <fcntl.h>

#include "killer.h"

extern struct super_block sb;

int hk_open(const char *pathname, int flags, ...) {
    return 0;
}

int hk_close(int fd) {
    return 0;
}

ssize_t hk_read(int fd, void *buf, size_t count) {
    return 0;
}

static off_t offset = 0;
ssize_t hk_write(int fd, const void *buf, size_t count) {
    struct hk_sb_info *sbi = HK_SB(&sb);

    assert(sbi->magic == KILLER_SUPER_MAGIC);
    assert(DEV_HANDLER_PTR(sbi)->iodepth == IO_DEPTH);
    io_write(DEV_HANDLER_PTR(sbi), offset, (char *)buf, 4096, O_IO_DROP);
    offset += 4096;

    return count;
}

int hk_lseek(int fd, int offset, int whence) {
    return 0;
}
