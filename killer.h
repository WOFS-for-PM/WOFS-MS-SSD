#ifndef _KILLER_H
#define _KILLER_H

#include "killer_config.h"

#ifndef __KERNEL__
#include "./backend/common.h"
#include "./linux/linux_port.h"
#endif

/*
 * Debug code
 */
#ifdef KBUILD_MODNAME
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#endif
#endif

/* #define hk_dbg(s, args...)		pr_debug(s, ## args) */
#define hk_dbg(s, args...) pr_info("cpu-%d: "s, smp_processor_id(), ##args)
#define hk_dbg1(s, args...)
#define hk_warn(s, args...) pr_warn(s, ##args)
#define hk_info(s, args...) pr_info("cpu-%d: "s, smp_processor_id(), ##args)
#define hk_err(s, args...)                                 \
    do {                                                   \
        pr_error("cpu-%d: "s, smp_processor_id(), ##args); \
        BUG_ON(1);                                         \
    } while (0);

#define clear_opt(o, opt) (o &= ~KILLER_MOUNT_##opt)
#define set_opt(o, opt) (o |= KILLER_MOUNT_##opt)
#define test_opt(sb, opt) (HK_SB(sb)->s_mount_opt & KILLER_MOUNT_##opt)

/* ======================= ANCHOR: Global values ========================= */
extern int measure_timing;
extern int wprotect;

#include "rng_lock.h"
#include "stats.h"
#include "super.h"
#include "linix.h"
#include "inode.h"
#include "objm.h"

#define KILLER_O_ATOMIC 010

void print_debug(int fd);

int *hk_errno();

int hk_mkfs(int flag);

int hk_init(int flag);

int hk_mkdir(const char *pathname, uint16_t mode);

int hk_stat(const char *pathname, struct stat *buf);  // TODO

int hk_fstat(int fd, struct stat *buf);  // TODO

// int  hk_fstat64 (int fd, struct stat64 *buf);

int hk_lstat(const char *pathname, struct stat *buf);  // TODO

int hk_statvfs(const char *path, struct statvfs *buf);  // TODO

int hk_fstatvfs(int fd, struct statvfs *buf);  // TODO

int hk_fstatfs(int fd, struct statfs *buf);  // ******

int hk_truncate(const char *path, off_t length);

int hk_ftruncate(int fd, off_t len);

int hk_open(const char *pathname, int flags, ...);

int hk_openat(int dirfd, const char *pathname, int flags, ...);

int hk_creat(const char *pathname, uint16_t mode);

int hk_close(int fd);

ssize_t hk_write(int fd, const void *buf, size_t count);

ssize_t hk_pwrite(int fd, const void *buf, size_t count, off_t offset);

ssize_t hk_read(int fd, void *buf, size_t count);

ssize_t hk_pread(int fd, void *buf, size_t count, off_t offset);

int hk_link(const char *oldpath, const char *newpath);  // TODO

int hk_unlink(const char *pathname);  // TODO

int hk_rmdir(const char *pathname);  // TODO

int hk_rename(const char *oldpath, const char *newpath);  // ******

DIR *hk_opendir(const char *_pathname);  // ******

struct dirent *hk_readdir(DIR *dirp);  // ******

int hk_closedir(DIR *dirp);  // ******

int hk_chdir(const char *path);  // TODO

char *hk_getcwd(char *buf, int size);  // TODO

int hk_lseek(int fd, int offset, int whence);  // ******

int hk_access(const char *pathname, int mode);  // ******

int hk_fcntl(int fd, int cmd, ...);  // ******

/* ======================= ANCHOR: Static Utils ========================= */
static inline int hk_get_cpuid(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);

    return smp_processor_id() % sbi->cpus;
}

#endif