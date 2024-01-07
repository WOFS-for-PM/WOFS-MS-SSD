#define _GNU_SOURCE
#include <dlfcn.h>

#include <boost/preprocessor/seq/for_each.hpp>

#include "glibc/ffile.h"
#include "killer.h"

static struct kmem_cache *hk_inode_cachep;

static void init_once(void *foo) {
    struct hk_inode_info *vi = foo;

    inode_init_once(&vi->vfs_inode);
}

static int __init init_inodecache(void) {
    hk_inode_cachep =
        kmem_cache_create("hk_inode_cache", sizeof(struct hk_inode_info), 0,
                          (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), init_once);
    if (hk_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void) {
    /*
     * Make sure all delayed rcu free inodes are flushed before
     * we destroy cache.
     */
    if (hk_inode_cachep) {
        kmem_cache_destroy(hk_inode_cachep);
        hk_inode_cachep = NULL;
    }
}

static struct inode *hk_alloc_inode(struct super_block *sb) {
    struct hk_inode_info *vi;

    vi = kmem_cache_alloc(hk_inode_cachep, GFP_NOFS);
    if (!vi)
        return NULL;

    vi->header = NULL;

    return &vi->vfs_inode;
}

static void hk_destroy_inode(struct inode *inode) {
    struct hk_inode_info *vi = HK_I(inode);

    kmem_cache_free(hk_inode_cachep, vi);
}

struct super_operations hk_sops = {
    .alloc_inode = hk_alloc_inode,
    .destroy_inode = hk_destroy_inode,
    .evict_inode = NULL,
};

// #define WRAPPER_DEBUG

#ifdef WRAPPER_DEBUG
#define PRINT_FUNC pr_info("\tcalled KILLER func: %s\n", __func__)
#else
#define PRINT_FUNC ;
#endif

#define HK_FD_OFFSET 1024

#define EMPTY(...)
#define DEFER(...) __VA_ARGS__ EMPTY()
#define OBSTRUCT(...) __VA_ARGS__ DEFER(EMPTY)()
#define EXPAND(...) __VA_ARGS_

#define MK_STR(arg) #arg
#define MK_STR2(x) MK_STR(x)
#define MK_STR3(x) MK_STR2(x)
// Information about the functions which are wrapped by EVERY module
// Alias: the standard function which most users will call
#define ALIAS_OPEN open
#define ALIAS_CREAT creat
#define ALIAS_EXECVE execve
#define ALIAS_EXECVP execvp
#define ALIAS_EXECV execv
#define ALIAS_MKNOD __xmknod
#define ALIAS_MKNODAT __xmknodat

#define ALIAS_FOPEN fopen
#define ALIAS_FOPEN64 fopen64
#define ALIAS_FREAD fread
#define ALIAS_FEOF feof
#define ALIAS_FERROR ferror
#define ALIAS_CLEARERR clearerr
#define ALIAS_FWRITE fwrite
#define ALIAS_FSEEK fseek
#define ALIAS_FTELL ftell
#define ALIAS_FTELLO ftello
#define ALIAS_FCLOSE fclose
#define ALIAS_FPUTS fputs
#define ALIAS_FGETS fgets
#define ALIAS_FFLUSH fflush

#define ALIAS_FSTATFS fstatfs
#define ALIAS_FDATASYNC fdatasync
#define ALIAS_FCNTL fcntl
#define ALIAS_FCNTL2 __fcntl64_nocancel_adjusted
#define ALIAS_FADVISE posix_fadvise64
#define ALIAS_OPENDIR opendir
#define ALIAS_READDIR readdir
#define ALIAS_READDIR64 readdir64
#define ALIAS_CLOSEDIR closedir
#define ALIAS_ERROR __errno_location
#define ALIAS_SYNC_FILE_RANGE sync_file_range

#define ALIAS_ACCESS access
#define ALIAS_READ read
#define ALIAS_READ2 __libc_read
#define ALIAS_WRITE write
#define ALIAS_SEEK lseek
#define ALIAS_CLOSE close
#define ALIAS_FTRUNC ftruncate
#define ALIAS_TRUNC truncate
#define ALIAS_DUP dup
#define ALIAS_DUP2 dup2
#define ALIAS_FORK fork
#define ALIAS_VFORK vfork
#define ALIAS_MMAP mmap
#define ALIAS_READV readv
#define ALIAS_WRITEV writev
#define ALIAS_PIPE pipe
#define ALIAS_SOCKETPAIR socketpair
#define ALIAS_IOCTL ioctl
#define ALIAS_MUNMAP munmap
#define ALIAS_MSYNC msync
#define ALIAS_CLONE __clone
#define ALIAS_PREAD pread
#define ALIAS_PREAD64 pread64
#define ALIAS_PWRITE64 pwrite64
#define ALIAS_PWRITE pwrite
//#define ALIAS_PWRITESYNC pwrite64_sync
#define ALIAS_FSYNC fsync
#define ALIAS_FDSYNC fdatasync
#define ALIAS_FTRUNC64 ftruncate64
#define ALIAS_OPEN64 open64
#define ALIAS_LIBC_OPEN64 __libc_open64
#define ALIAS_SEEK64 lseek64
#define ALIAS_MMAP64 mmap64
#define ALIAS_MKSTEMP mkstemp
#define ALIAS_MKSTEMP64 mkstemp64
#define ALIAS_ACCEPT accept
#define ALIAS_SOCKET socket
#define ALIAS_UNLINK unlink
#define ALIAS_POSIX_FALLOCATE posix_fallocate
#define ALIAS_POSIX_FALLOCATE64 posix_fallocate64
#define ALIAS_FALLOCATE fallocate
#define ALIAS_STAT stat
#define ALIAS_STAT64 stat64
#define ALIAS_FSTAT fstat
#define ALIAS_FSTAT64 fstat64
#define ALIAS_LSTAT lstat
#define ALIAS_LSTAT64 lstat64
#define ALIAS_XSTAT __xstat
#define ALIAS_XSTAT64 __xstat64

/* Now all the metadata operations */
#define ALIAS_MKDIR mkdir
#define ALIAS_RENAME rename
#define ALIAS_LINK link
#define ALIAS_SYMLINK symlink
#define ALIAS_RMDIR rmdir
/* All the *at operations */
#define ALIAS_OPENAT openat
#define ALIAS_SYMLINKAT symlinkat
#define ALIAS_MKDIRAT mkdirat
#define ALIAS_UNLINKAT unlinkat

// The function return type
#define RETT_OPEN int
#define RETT_LIBC_OPEN64 int
#define RETT_CREAT int
#define RETT_EXECVE int
#define RETT_EXECVP int
#define RETT_EXECV int
#define RETT_SHM_COPY void
#define RETT_MKNOD int
#define RETT_MKNODAT int

// #ifdef TRACE_FP_CALLS
#define RETT_FOPEN FILE *
#define RETT_FOPEN64 FILE *
#define RETT_FWRITE size_t
#define RETT_FSEEK int
#define RETT_FTELL long int
#define RETT_FTELLO off_t
#define RETT_FCLOSE int
#define RETT_FPUTS int
#define RETT_FGETS char *
#define RETT_FFLUSH int
// #endif

#define RETT_FSTATFS int
#define RETT_FDATASYNC int
#define RETT_FCNTL int
#define RETT_FCNTL2 int
#define RETT_FADVISE int
#define RETT_OPENDIR DIR *
#define RETT_READDIR struct dirent *
#define RETT_READDIR64 struct dirent64 *
#define RETT_CLOSEDIR int
#define RETT_ERROR int *
#define RETT_SYNC_FILE_RANGE int

#define RETT_ACCESS int
#define RETT_READ ssize_t
#define RETT_READ2 ssize_t
#define RETT_FREAD size_t
#define RETT_FEOF int
#define RETT_FERROR int
#define RETT_CLEARERR void
#define RETT_WRITE ssize_t
#define RETT_SEEK off_t
#define RETT_CLOSE int
#define RETT_FTRUNC int
#define RETT_TRUNC int
#define RETT_DUP int
#define RETT_DUP2 int
#define RETT_FORK pid_t
#define RETT_VFORK pid_t
#define RETT_MMAP void *
#define RETT_READV ssize_t
#define RETT_WRITEV ssize_t
#define RETT_PIPE int
#define RETT_SOCKETPAIR int
#define RETT_IOCTL int
#define RETT_MUNMAP int
#define RETT_MSYNC int
#define RETT_CLONE int
#define RETT_PREAD ssize_t
#define RETT_PREAD64 ssize_t
#define RETT_PWRITE ssize_t
#define RETT_PWRITE64 ssize_t
//#define RETT_PWRITESYNC ssize_t
#define RETT_FSYNC int
#define RETT_FDSYNC int
#define RETT_FTRUNC64 int
#define RETT_OPEN64 int
#define RETT_SEEK64 off64_t
#define RETT_MMAP64 void *
#define RETT_MKSTEMP int
#define RETT_MKSTEMP64 int
#define RETT_ACCEPT int
#define RETT_SOCKET int
#define RETT_UNLINK int
#define RETT_POSIX_FALLOCATE int
#define RETT_POSIX_FALLOCATE64 int
#define RETT_FALLOCATE int
#define RETT_STAT int
#define RETT_STAT64 int
#define RETT_FSTAT int
#define RETT_FSTAT64 int
#define RETT_LSTAT int
#define RETT_LSTAT64 int
#define RETT_XSTAT int
#define RETT_XSTAT64 int
/* Now all the metadata operations */
#define RETT_MKDIR int
#define RETT_RENAME int
#define RETT_LINK int
#define RETT_SYMLINK int
#define RETT_RMDIR int
/* All the *at operations */
#define RETT_OPENAT int
#define RETT_SYMLINKAT int
#define RETT_MKDIRAT int
#define RETT_UNLINKAT int

// The function interface
#define INTF_OPEN const char *path, int oflag, ...
#define INTF_LIBC_OPEN64 const char *path, int oflag, ...

#define INTF_CREAT const char *path, mode_t mode
#define INTF_EXECVE const char *filename, char *const argv[], char *const envp[]
#define INTF_EXECVP const char *file, char *const argv[]
#define INTF_EXECV const char *path, char *const argv[]
#define INTF_SHM_COPY void
#define INTF_MKNOD int ver, const char *path, mode_t mode, dev_t *dev
#define INTF_MKNODAT \
    int ver, int dirfd, const char *path, mode_t mode, dev_t *dev

// #ifdef TRACE_FP_CALLS
#define INTF_FOPEN const char *__restrict path, const char *__restrict mode
#define INTF_FOPEN64 const char *__restrict path, const char *__restrict mode
#define INTF_FREAD \
    void *__restrict buf, size_t length, size_t nmemb, FILE *__restrict fp
#define INTF_CLEARERR FILE *fp
#define INTF_FEOF FILE *fp
#define INTF_FERROR FILE *fp
#define INTF_FWRITE \
    const void *__restrict buf, size_t length, size_t nmemb, FILE *__restrict fp
#define INTF_FSEEK FILE *fp, long int offset, int whence
#define INTF_FTELL FILE *fp
#define INTF_FTELLO FILE *fp
#define INTF_FCLOSE FILE *fp
#define INTF_FPUTS const char *str, FILE *stream
#define INTF_FGETS char *str, int n, FILE *stream
#define INTF_FFLUSH FILE *fp
// #endif

#define INTF_FSTATFS int fd, struct statfs *buf
#define INTF_FDATASYNC int fd
#define INTF_FCNTL int fd, int cmd, ...
#define INTF_FCNTL2 int fd, int cmd, void *arg
#define INTF_FADVISE int fd, off_t offset, off_t len, int advice
#define INTF_OPENDIR const char *path
#define INTF_READDIR DIR *dirp
#define INTF_READDIR64 DIR *dirp
#define INTF_CLOSEDIR DIR *dirp
#define INTF_ERROR void
#define INTF_SYNC_FILE_RANGE \
    int fd, off64_t offset, off64_t nbytes, unsigned int flags

#define INTF_ACCESS const char *pathname, int mode
#define INTF_READ int file, void *buf, size_t length
#define INTF_READ2 int file, void *buf, size_t length
#define INTF_WRITE int file, const void *buf, size_t length
#define INTF_SEEK int file, off_t offset, int whence
#define INTF_CLOSE int file
#define INTF_FTRUNC int file, off_t length
#define INTF_TRUNC const char *path, off_t length
#define INTF_DUP int file
#define INTF_DUP2 int file, int fd2
#define INTF_FORK void
#define INTF_VFORK void
#define INTF_MMAP \
    void *addr, size_t len, int prot, int flags, int file, off_t off
#define INTF_READV int file, const struct iovec *iov, int iovcnt
#define INTF_WRITEV int file, const struct iovec *iov, int iovcnt
#define INTF_PIPE int file[2]
#define INTF_SOCKETPAIR int domain, int type, int protocol, int sv[2]
#define INTF_IOCTL int file, unsigned long int request, ...
#define INTF_MUNMAP void *addr, size_t len
#define INTF_MSYNC void *addr, size_t len, int flags
#define INTF_CLONE int (*fn)(void *a), void *child_stack, int flags, void *arg
#define INTF_PREAD int file, void *buf, size_t count, off_t offset
#define INTF_PREAD64 int file, void *buf, size_t count, off_t offset
#define INTF_PWRITE int file, const void *buf, size_t count, off_t offset
#define INTF_PWRITE64 int file, const void *buf, size_t count, off_t offset
//#define INTF_PWRITESYNC int file, const void *buf, size_t count, off_t offset
#define INTF_FSYNC int file
#define INTF_FDSYNC int file
#define INTF_FTRUNC64 int file, off64_t length
#define INTF_OPEN64 const char *path, int oflag, ...
#define INTF_SEEK64 int file, off64_t offset, int whence
#define INTF_MMAP64 \
    void *addr, size_t len, int prot, int flags, int file, off64_t off
#define INTF_MKSTEMP char *file
#define INTF_MKSTEMP64 char *file
#define INTF_ACCEPT int file, struct sockaddr *addr, socklen_t *addrlen
#define INTF_SOCKET int domain, int type, int protocol
#define INTF_UNLINK const char *path
#define INTF_POSIX_FALLOCATE int file, off_t offset, off_t len
#define INTF_POSIX_FALLOCATE64 int file, off_t offset, off_t len
#define INTF_FALLOCATE int file, int mode, off_t offset, off_t len
#define INTF_STAT const char *path, struct stat *buf
#define INTF_STAT64 const char *path, struct stat64 *buf
#define INTF_FSTAT int file, struct stat *buf
#define INTF_FSTAT64 int file, struct stat64 *buf
#define INTF_LSTAT const char *path, struct stat *buf
#define INTF_LSTAT64 const char *path, struct stat64 *buf
#define INTF_XSTAT int ver, const char *path, struct stat *buf
#define INTF_XSTAT64 int ver, const char *path, struct stat64 *buf
/* Now all the metadata operations */
#define INTF_MKDIR const char *path, uint32_t mode
#define INTF_RENAME const char *old, const char *new
#define INTF_LINK const char *path1, const char *path2
#define INTF_SYMLINK const char *path1, const char *path2
#define INTF_RMDIR const char *path
/* All the *at operations */
#define INTF_OPENAT int dirfd, const char *path, int oflag, ...
#define INTF_UNLINKAT int dirfd, const char *path, int flags
#define INTF_SYMLINKAT const char *old_path, int newdirfd, const char *new_path
#define INTF_MKDIRAT int dirfd, const char *path, mode_t mode

#define KILLER_ALL_OPS                                                         \
    (OPEN)(OPEN64)(OPENAT)(CREAT)(CLOSE)(ACCESS)(SEEK)(TRUNC)(FTRUNC)(LINK)(   \
        UNLINK)(FSYNC)(READ)(WRITE)(PREAD)(PREAD64)(PWRITE)(PWRITE64)(XSTAT)(  \
        XSTAT64)(RENAME)(MKDIR)(RMDIR)(FSTATFS)(FDATASYNC)(FCNTL)(FADVISE)(    \
        OPENDIR)(CLOSEDIR)(READDIR)(READDIR64)(ERROR)(SYNC_FILE_RANGE)(FOPEN)( \
        FPUTS)(FGETS)(FWRITE)(FREAD)(FCLOSE)(FSEEK)(FFLUSH)

#define PREFIX(call) (real_##call)

// Real syscall type
#define TYPE_REL_SYSCALL(op) typedef RETT_##op (*real_##op##_t)(INTF_##op);
#define TYPE_REL_SYSCALL_WRAP(r, data, elem) TYPE_REL_SYSCALL(elem)

BOOST_PP_SEQ_FOR_EACH(TYPE_REL_SYSCALL_WRAP, placeholder, KILLER_ALL_OPS)

static struct real_ops {
#define DEC_REL_SYSCALL(op) real_##op##_t op;
#define DEC_REL_SYSCALL_WRAP(r, data, elem) DEC_REL_SYSCALL(elem)
    BOOST_PP_SEQ_FOR_EACH(DEC_REL_SYSCALL_WRAP, placeholder, KILLER_ALL_OPS)
} real_ops;

void insert_real_op() {
#define FILL_REL_SYSCALL(op) \
    real_ops.op = dlsym(RTLD_NEXT, MK_STR3(ALIAS_##op));
#define FILL_REL_SYSCALL_WRAP(r, data, elem) FILL_REL_SYSCALL(elem)
    BOOST_PP_SEQ_FOR_EACH(FILL_REL_SYSCALL_WRAP, placeholder, KILLER_ALL_OPS)
}

// NOTE: It is hard to determine which program will
//       use what constructor priority (both called
//       before main), it is a must to check the real
//       ops for every function
// NOTE: Good news is that the performance is measured
//       after main(), so insert_real_op will not happen
#define OP_DEFINE_SAFE(op, FUNC)          \
    RETT_##op ALIAS_##op(INTF_##op) {     \
        if (unlikely(real_ops.op == 0)) { \
            insert_real_op();             \
        }                                 \
        FUNC                              \
    }

#define OP_DEFINE(op) RETT_##op ALIAS_##op(INTF_##op)

OP_DEFINE_SAFE(OPEN, {
    PRINT_FUNC;
    if (*path == '\\' || *path != '/' || path[1] == '\\') {
        int ret;
        if (oflag & O_CREAT) {
            va_list ap;
            mode_t mode;
            va_start(ap, oflag);
            mode = va_arg(ap, mode_t);
#ifdef WRAPPER_DEBUG
            pr_info("\t\tpath: %s\n", path);
#endif
            char *p = (char *)path;
            while (*p == '\\') {
                p++;
            }
            if (p[1] == '\\') {
                p++;
                *p = '/';
            }
            ret = hk_open(p, oflag, mode);
            if (ret == -1 && *path != '\\') {
                return real_ops.OPEN(path, oflag, mode);
            }
        } else {
#ifdef WRAPPER_DEBUG
            pr_info("\t\tpath: %s\n", path);
#endif
            ret = hk_open((*path == '\\') ? path + 1 : path, oflag);
            if (ret == -1 && *path != '\\') {
                return real_ops.OPEN(path, oflag);
            }
        }
        if (ret == -1) {
            return ret;
        }
#ifdef WRAPPER_DEBUG
        pr_info("open returned: %d\n", ret + HK_FD_OFFSET);
#endif
        return ret + HK_FD_OFFSET;
    } else {
        if (oflag & O_CREAT) {
            va_list ap;
            mode_t mode;
            va_start(ap, oflag);
            mode = va_arg(ap, mode_t);
            return real_ops.OPEN(path, oflag, mode);
        } else {
            return real_ops.OPEN(path, oflag);
        }
    }
    return 0;
})

// NOTE: this is important for FIO
OP_DEFINE_SAFE(OPEN64, {
    PRINT_FUNC;
    if (oflag & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, oflag);
        mode = va_arg(ap, mode_t);
        return open(path, oflag, mode);
    } else {
        return open(path, oflag);
    }
})

OP_DEFINE_SAFE(OPENAT, {
    PRINT_FUNC;
    if (*path == '\\' || *path != '/') {
        int ret;
        if (oflag & O_CREAT) {
            va_list ap;
            mode_t mode;
            va_start(ap, oflag);
            mode = va_arg(ap, mode_t);
            PRINT_FUNC;
            ret = hk_openat(dirfd - HK_FD_OFFSET,
                            (*path == '\\') ? path + 1 : path, oflag, mode);
            if (ret == -1 && *path != '\\') {
                return real_ops.OPENAT(dirfd, path, oflag, mode);
            }
        } else {
            PRINT_FUNC;
            ret = hk_openat(dirfd - HK_FD_OFFSET,
                            (*path == '\\') ? path + 1 : path, oflag);
            if (ret == -1 && *path != '\\') {
                return real_ops.OPENAT(dirfd, path, oflag);
            }
        }
        if (ret == -1) {
            return ret;
        }
        return ret + HK_FD_OFFSET;
    } else {
        if (oflag & O_CREAT) {
            va_list ap;
            mode_t mode;
            va_start(ap, oflag);
            mode = va_arg(ap, mode_t);
            return real_ops.OPENAT(dirfd, path, oflag, mode);
        } else {
            return real_ops.OPENAT(dirfd, path, oflag);
        }
    }
})

OP_DEFINE_SAFE(WRITE, {
    if (file >= HK_FD_OFFSET) {
        PRINT_FUNC;
        return hk_write(file - HK_FD_OFFSET, buf, length);
    } else {
        return real_ops.WRITE(file, buf, length);
    }
})

OP_DEFINE_SAFE(FADVISE, {
    PRINT_FUNC;
    if (fd >= HK_FD_OFFSET) {
        return 0;
    } else {
        return real_ops.FADVISE(fd, offset, len, advice);
    }
})

OP_DEFINE_SAFE(XSTAT, {
    PRINT_FUNC;
    if (ver >= HK_FD_OFFSET) {
        return 0;
    } else {
        return real_ops.XSTAT(ver, path, buf);
    }
})

OP_DEFINE_SAFE(XSTAT64, {
    PRINT_FUNC;
    if (ver >= HK_FD_OFFSET) {
        return 0;
    } else {
        return real_ops.XSTAT64(ver, path, buf);
    }
})

OP_DEFINE_SAFE(CLOSE, {
    PRINT_FUNC;
    if (file >= HK_FD_OFFSET) {
        return hk_close(file - HK_FD_OFFSET);
    } else {
        pr_info("real_ops.CLOSE(%d)\n", file);
        return real_ops.CLOSE(file);
    }
})

OP_DEFINE_SAFE(FCLOSE, {
    PRINT_FUNC;
    if (fileno(fp) >= HK_FD_OFFSET) {
        return 0;
    } else {
        return real_ops.FCLOSE(fp);
    }
})

struct super_block sb = {.s_fs_info = NULL};

extern int hk_fill_super(struct super_block *sb, void *data, int silent);
extern void hk_put_super(struct super_block *sb);
extern int hk_show_stats(void);

#define MAX_BACKTRACE 16

void err_handler(int signum) {
    void *array[MAX_BACKTRACE];
    size_t size;
    char **strings;
    size_t i;
    char *orig_ld_preload;
    int ret = 0;

    size = backtrace(array, MAX_BACKTRACE);
    strings = backtrace_symbols(array, size);

    printf("\n");
    printf("\n");

    if (signum == SIGSEGV)
        printf("BUG\n");
    else if (signum == SIGINT)
        printf("KILLED by user\n");
    else
        printf("UNKNOWN\n");

    printf("RIP: %p\n", __builtin_return_address(0));

    orig_ld_preload = getenv("LD_PRELOAD");
    assert(orig_ld_preload != NULL);
    putenv("LD_PRELOAD=");

    for (i = 0; i < size; i++) {
        char syscom[512] = {0}, exe[128] = {0}, ofs[128] = {0};
        char *p = strings[i], *q = exe, *r = ofs;
        while (*p != '(')
            *q++ = *p++;
        *q = '\0';
        p++;
        while (*p != '+')
            p++;
        while (*p != ')')
            *r++ = *p++;
        *r = '\0';

        sprintf(syscom, "addr2line -i -a -f -p --exe=%s %s 2>/dev/null", exe,
                ofs);
        ret = system(syscom);
        if (ret != 0) {
            pr_info("Failed to execute addr2line\n");
        }
    }
    putenv(orig_ld_preload);

    exit(1);
}

#define MAX_PROG_NAME 128

static inline int get_prog_name(char *prog) {
    pid_t pid = getpid();
    size_t ret;
    sprintf(prog, "/proc/%d/cmdline", pid);
    FILE *fp = fopen(prog, "r");

    if (fp == NULL) {
        pr_info("Failed to open %s\n", prog);
        return -EINVAL;
    }

    ret = fread(prog, 1, MAX_PROG_NAME, fp);
    if (ret == 0) {
        pr_info("Failed to read %s\n", prog);
        return -EINVAL;
    }
    fclose(fp);
    return 0;
}

static int __init hk_create_slab_caches(void) {
    init_inodecache();
    init_obj_ref_inode_cache();
    init_obj_ref_attr_cache();
    init_obj_ref_dentry_cache();
    init_obj_ref_data_cache();
    init_claim_req_cache();
    init_hk_inode_info_header_cache();
    init_tl_node_cache();
    return 0;
}

void hk_destory_slab_caches(void) {
    destroy_inodecache();
    destroy_obj_ref_inode_cache();
    destroy_obj_ref_attr_cache();
    destroy_obj_ref_dentry_cache();
    destroy_obj_ref_data_cache();
    destroy_claim_req_cache();
    destroy_hk_inode_info_header_cache();
    destroy_tl_node_cache();
}

static int inited = 0;
static __attribute__((constructor(101))) void killer_init(void) {
    char prog[MAX_PROG_NAME] = {0};
    assert(!get_prog_name(prog));

#ifdef DEBUG
    char *target = getenv("TARGET_TEST_PROG");
    assert(target != NULL);
    if (strcmp(prog, target) != 0) {
        pr_info("Not the target program, skip\n");
        return;
    }
#endif

    if (real_ops.ERROR == 0) {
        insert_real_op();
        inited = 1;
    }

    pr_info("Starting to initialize KILLER.\n");
    pr_info("Installing real syscalls...\n");
    pr_info("Real syscall installed. Initializing KILLER...\n");

    signal(SIGSEGV, err_handler);
    signal(SIGINT, err_handler);

    if (real_ops.ERROR != 0) {
        hk_create_slab_caches();
        
        // pr_info("Checking I/O engine...\n");
        // assert(!io_test());
        // pr_info("I/O engine is ready.\n");

        hk_fill_super(&sb, NULL, 0);

        pr_info("Checking KILLER porting...\n");
        assert(!port_test());
        pr_info("KILLER porting is ready.\n");

        pr_info("KILLER initialized in CPU %d.\n", smp_processor_id());
        pr_info("Now the program [%s] begins.\n", prog);
        return;
    }
    pr_info("Failed to init\n");
}

static __attribute__((destructor)) void killer_destroy(void) {
    char prog[MAX_PROG_NAME] = {0};
    assert(!get_prog_name(prog));

#ifdef DEBUG
    char *target = getenv("TARGET_TEST_PROG");
    assert(target != NULL);
    if (strcmp(prog, target) != 0) {
        pr_info("Current: %s, Target: %s. Not the target program, skip\n", prog,
                target);
        return;
    }
#endif

    if (measure_timing)
        hk_show_stats();
    hk_put_super(&sb);
    hk_destory_slab_caches();
    pr_info("KILLER unloaded.\n");
}
