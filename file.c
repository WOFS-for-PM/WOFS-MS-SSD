#define _GNU_SOURCE
#include <fcntl.h>

#include "killer.h"

extern struct super_block sb;

int hk_open(struct inode *inode, struct file *filp) {
    return generic_file_open(inode, filp);
}

ssize_t hk_file_read(struct file *filp, char __user *buf, size_t len,
                     loff_t *ppos) {
    return 0;
}

ssize_t hk_file_write(struct file *filp, const char __user *buf, size_t len,
                      loff_t *ppos) {
    struct hk_sb_info *sbi = HK_SB(&sb);
    unsigned long i;

    assert(sbi->magic == KILLER_SUPER_MAGIC);
    assert(DEV_HANDLER_PTR(sbi, 0)->iodepth == IO_DEPTH);

    for (i = 0; i < len / 4096; i += 4096) {
        io_write(DEV_HANDLER_PTR(sbi, 0), *ppos, (char *)buf, 4096, O_IO_DROP);
    }
    *ppos += i;

    return len;
}

static loff_t hk_llseek(struct file *filp, loff_t offset, int whence) {
    if (whence != SEEK_DATA && whence != SEEK_HOLE)
        return generic_file_llseek(filp, offset, whence);

    return -EINVAL;
}

const struct inode_operations hk_file_inode_operations;

const struct file_operations hk_file_operations = {
    .llseek = hk_llseek,
    .read = hk_file_read,
    .write = hk_file_write,
    // .read_iter = hk_rw_iter,
    // .write_iter = hk_rw_iter,
    // .mmap = NULL, /* TODO: Not support mmap yet */
    // .mmap_supported_flags = MAP_SYNC,
    .open = hk_open,
    // .fsync = hk_fsync,
    // .flush = hk_flush,
    // .unlocked_ioctl = hk_ioctl,
    .fallocate = NULL, /* TODO: Not support yet */
#ifdef CONFIG_COMPAT
    .compat_ioctl = hk_compat_ioctl,
#endif
};