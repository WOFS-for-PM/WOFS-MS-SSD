#ifndef _HK_CONFIG_H
#define _HK_CONFIG_H

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/falloc.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <x86intrin.h>

#define EPERM 1    /* Operation not permitted */
#define ENOENT 2   /* No such file or directory */
#define ESRCH 3    /* No such process */
#define EINTR 4    /* Interrupted system call */
#define EIO 5      /* I/O error */
#define ENXIO 6    /* No such device or address */
#define E2BIG 7    /* Argument list too long */
#define ENOEXEC 8  /* Exec format error */
#define EBADF 9    /* Bad file number */
#define ECHILD 10  /* No child processes */
#define EAGAIN 11  /* Try again */
#define ENOMEM 12  /* Out of memory */
#define EACCES 13  /* Permission denied */
#define EFAULT 14  /* Bad address */
#define ENOTBLK 15 /* Block device required */
#define EBUSY 16   /* Device or resource busy */
#define EEXIST 17  /* File exists */
#define EXDEV 18   /* Cross-device link */
#define ENODEV 19  /* No such device */
#define ENOTDIR 20 /* Not a directory */
#define EISDIR 21  /* Is a directory */
#define EINVAL 22  /* Invalid argument */
#define ENFILE 23  /* File table overflow */
#define EMFILE 24  /* Too many open files */
#define ENOTTY 25  /* Not a typewriter */
#define ETXTBSY 26 /* Text file busy */
#define EFBIG 27   /* File too large */
#define ENOSPC 28  /* No space left on device */
#define ESPIPE 29  /* Illegal seek */
#define EROFS 30   /* Read-only file system */
#define EMLINK 31  /* Too many links */
#define EPIPE 32   /* Broken pipe */
#define EDOM 33    /* Math argument out of domain of func */
#define ERANGE 34  /* Math result not representable */

#ifndef DEV_PATH
#define DEV_PATH "/dev/nvme0n1p1"
#endif  // DEV_PATH

#ifndef IO_DEPTH
#define IO_DEPTH num_online_cpus()
#endif  // IO_DEPTH

#define KILLER_SUPER_BLKS 2

#define KILLER_SUPER_MAGIC 0x4b494c4c  // "KILL" in ascii
#define KILLER_OBJ_MAGIC 0x4b4f424a    // "KOBJ" in ascii

/*
 * Mount flags
 */
#define KILLER_MOUNT_PROTECT 0x000001      /* wprotect CR0.WP */
#define KILLER_MOUNT_XATTR_USER 0x000002   /* Extended user attributes */
#define KILLER_MOUNT_POSIX_ACL 0x000004    /* POSIX Access Control Lists */
#define KILLER_MOUNT_DAX 0x000008          /* Direct Access */
#define KILLER_MOUNT_ERRORS_CONT 0x000010  /* Continue on errors */
#define KILLER_MOUNT_ERRORS_RO 0x000020    /* Remount fs ro on errors */
#define KILLER_MOUNT_ERRORS_PANIC 0x000040 /* Panic on errors */
#define KILLER_MOUNT_HUGEMMAP 0x000080     /* Huge mappings with mmap */
#define KILLER_MOUNT_HUGEIOREMAP 0x000100  /* Huge mappings with ioremap */
#define KILLER_MOUNT_FORMAT 0x000200       /* was FS formatted on mount? */
#define KILLER_MOUNT_DATA_COW 0x000400  /* Copy-on-write for data integrity */
#define KILLER_MOUNT_HISTORY_W 0x008000 /* History window for file open */

#define POSSIBLE_MAX_CPU 1024
/*
 * HUNTER-KILLER CONFIGURATIONS
 */
#define HK_BLK_SZ_BITS 12
#define HK_BLK_SZ (1 << HK_BLK_SZ_BITS)
#define HK_NUM_INO (1024 * 1024)
#define HK_RG_SLOTS (1024 * 1024)
#define HK_RG_ENTY_SLOTS (4)
#define HK_MLIST_INST_MAXRETRIES (5)
#define HK_EXTEND_NUM_BLOCKS (512)  /* for optimizing append/sequntial write */
#define HK_LINIX_SLOTS (1024 * 256) /* related to init size */
#define HK_HISTORY_WINDOWS (1)      /* for dynamic workloads */
#define HK_NAME_LEN (128 - 36)
#define HK_HASH_BITS7 7      /* for those long period hash table */
#define HK_HASH_BITS3 3      /* for those frequent creating hash table */
#define HK_CMT_QUEUE_BITS 10 /* for commit queue */
#define HK_CMT_MAX_PROCESS_BATCH (1024 * 256)
#define HK_CMT_WAKEUP_THRESHOLD (HK_CMT_MAX_PROCESS_BATCH * 2)
#define HK_MAX_GAPS_INRAM (1024 * 256)
#define HK_CMT_WORKER_NUM 4 /* for commit worker */
#define HK_JOURNAL_SIZE (4 * 1024)
#define HK_PERCORE_JSLOTS (1) /* per core journal slots */
#define HK_READAHEAD_WINDOW (16 * 1024)
#define HK_RESCUE_WORKERS 8 /* for failure recovery */
#define HK_ROOT_INO (0)
#define HK_RESV_NUM (1)

#define CACHELINE_SIZE (64)
#define CACHELINE_MASK (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr) + CACHELINE_SIZE - 1) & CACHELINE_MASK)

#define READDIR_END (ULONG_MAX)

#endif