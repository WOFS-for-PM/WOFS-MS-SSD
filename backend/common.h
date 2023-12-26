#ifndef _COMMON_H
#define _COMMON_H

#include "../linux/linux_port.h"
#include <linux/io_uring.h>

#ifndef GET_EVENTS_MAX_TRIES
#define GET_EVENTS_MAX_TRIES(td) ((td)->iodepth * 10)
#endif

#define IO_READ 0
#define IO_WRITE 1
#define IO_SYNC 2

enum q_status {
    Q_COMPLETED = 0, /* completed sync */
    Q_QUEUED = 1,    /* queued, will complete async */
    Q_BUSY = 2,      /* no more room, call ->commit() */
};

struct io_u {
    // Never changed
    void *buf;
    size_t cap;
    int idx;
    // Dynamic
    off_t offset;
    size_t len;
    int opcode;
};

struct thread_data {
    int iodepth;
    int bs;

    char *dev_path;

    void *buf;

    // NOTE: free list for io_u for O(1) allocation
    spinlock_t comp_lock;
    spinlock_t avai_lock;
    unsigned long *comp_bm;
    struct list_head avai_q;
    struct io_u *io_us;

    // NOTE: we need to swipe non-read io_u(s)
    struct task_struct *ack_thread;

    spinlock_t td_lock;

    void *io_ops_data;
    struct ioengine_ops *io_ops;

    void *options;
};

struct ioengine_ops {
    const char *name;
    struct list_head list;

    int (*init)(struct thread_data *);
    int (*prep)(struct thread_data *, struct io_u *);
    enum q_status (*queue)(struct thread_data *, struct io_u *);
    int (*commit)(struct thread_data *);
    int (*getevents)(struct thread_data *, unsigned int, unsigned int);
    struct io_u *(*event)(struct thread_data *, int);
    void (*cleanup)(struct thread_data *);
    bool (*ack)(struct thread_data *, struct io_u *);

    int (*unit_test)(void);
};

// Common
int thread_data_init(struct thread_data *td, int iodepth, int bs,
                     char *dev_path, void *options);
int thread_data_cleanup(struct thread_data *td);

int mark_io_u_complete(struct thread_data *td, struct io_u *io_u);
int mark_io_u_available(struct thread_data *td, struct io_u *io_u);

// IO ops
int io_register(void);
int io_unregister(void);

int io_open(struct thread_data *td, const char *e);
int io_close(struct thread_data *td);
int io_write(struct thread_data *td, off_t offset, char *buf, size_t len);
int io_commit(struct thread_data *td, int io_ud);
int io_read(struct thread_data *td, off_t offset, char *buf, size_t len);
int io_sync(struct thread_data *td);

#endif