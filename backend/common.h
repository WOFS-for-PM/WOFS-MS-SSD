#ifndef _COMMON_H
#define _COMMON_H

#include "../linux/linux_port.h"
#include <linux/io_uring.h>

#ifndef GET_EVENTS_MAX_TRIES  
#define GET_EVENTS_MAX_TRIES(td) ((td)->iodepth * 10)
#endif

struct thread_data {
    int iodepth;
    int bs;

    char *dev_path;

    void *buf;
    void *io_ops_data;
};

enum q_status {
    Q_COMPLETED = 0, /* completed sync */
    Q_QUEUED = 1,    /* queued, will complete async */
    Q_BUSY = 2,      /* no more room, call ->commit() */
};

// Common
int thread_data_init(struct thread_data *td, int iodepth, int bs,
                     char *dev_path);
int thread_data_cleanup(struct thread_data *td);

// IO ring driver
int ioring_init(struct thread_data *td, int sqpoll_cpu);
enum q_status ioring_queue(struct thread_data *td, unsigned long long offset,
                           int sqe_idx, int opcode);
int ioring_commit(struct thread_data *td);
int ioring_getevents(struct thread_data *td, unsigned int min,
                     unsigned int max);
int ioring_event(struct thread_data *td, int event);
void ioring_cleanup(struct thread_data *td);

int ioring_test(void);

#endif