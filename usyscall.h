#ifndef _USYSCALL_H
#define _USYSCALL_H

#include "./backend/common.h"
#include "./linux/linux_port.h"

#define USYS_MAX_FD 4096

void print_debug(int fd);

int *usys_errno();

int usys_init(void);

int usys_mkfs(int flag);

int usys_mkdir(const char *pathname, uint16_t mode);

int usys_stat(const char *pathname, struct stat *buf);  // TODO

int usys_fstat(int fd, struct stat *buf);  // TODO

// int  usys_fstat64 (int fd, struct stat64 *buf);

int usys_lstat(const char *pathname, struct stat *buf);  // TODO

int usys_statvfs(const char *path, struct statvfs *buf);  // TODO

int usys_fstatvfs(int fd, struct statvfs *buf);  // TODO

int usys_fstatfs(int fd, struct statfs *buf);  // ******

int usys_fsync(int fd);

int usys_truncate(const char *path, off_t length);

int usys_ftruncate(int fd, off_t len);

int usys_open(const char *pathname, int flags, int mode);

int usys_openat(int dirfd, const char *pathname, int flags, ...);

int usys_creat(const char *pathname, uint16_t mode);

int usys_close(int fd);

ssize_t usys_write(int fd, const void *buf, size_t count);

ssize_t usys_pwrite(int fd, const void *buf, size_t count, off_t offset);

ssize_t usys_read(int fd, void *buf, size_t count);

ssize_t usys_pread(int fd, void *buf, size_t count, off_t offset);

int usys_link(const char *oldpath, const char *newpath);  // TODO

int usys_unlink(const char *pathname);  // TODO

int usys_rmdir(const char *pathname);  // TODO

int usys_rename(const char *oldpath, const char *newpath);  // ******

DIR *usys_opendir(const char *_pathname);  // ******

struct dirent *usys_readdir(DIR *dirp);  // ******

int usys_closedir(DIR *dirp);  // ******

int usys_chdir(const char *path);  // TODO

char *usys_getcwd(char *buf, int size);  // TODO

int usys_lseek(int fd, long offset, int whence);  // ******

int usys_access(const char *pathname, int mode);  // ******

int usys_fcntl(int fd, int cmd, ...);  // ******

#endif