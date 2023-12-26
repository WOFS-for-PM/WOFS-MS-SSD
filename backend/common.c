#include <fcntl.h>
#include <stdlib.h>

#include "common.h"

#define PREDEFINED_PAGE_SIZE 4096
#define PREDEFINED_CACHE_LINE_SIZE 64
#define CACHE_LINE_FILE \
    "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void) {
    char size[32];
    int fd, ret;

    fd = open(CACHE_LINE_FILE, O_RDONLY);
    if (fd < 0)
        return -1;

    ret = read(fd, size, sizeof(size));

    close(fd);

    if (ret <= 0)
        return -1;
    else
        return atoi(size);
}

static inline int os_cache_line_size(void) {
    static int size = 0;

    size = arch_cache_line_size();
    if (size <= 0)
        size = PREDEFINED_CACHE_LINE_SIZE;

    return size;
}

static inline int os_page_size(void) {
    static int size = 0;

    size = getpagesize();
    if (size <= 0)
        size = PREDEFINED_PAGE_SIZE;

    return size;
}

// [io_u_idx_start, io_u_idx_end)
struct io_unode {
    struct list_head list;
    int io_u_idx_start;
    int io_u_idx_end;
};

static int complete_ack_thread(void *arg) {
    struct thread_data *td = arg;
    struct io_u *io_u;
    int ret;

    if (!td->io_ops->ack) {
        return 0;
    }

    while (!kthread_should_stop()) {
        for (int i = 0; i < td->iodepth; i++) {
            io_u = &td->io_us[i];

            if (test_bit(io_u->idx, td->comp_bm)) {
                ret = td->io_ops->ack(td, io_u);
                if (ret) {
                    clear_bit(io_u->idx, td->comp_bm);
                    mark_io_u_available(td, io_u);
                }
            }
        }
        schedule();
    }
    return 0;
}

int thread_data_init(struct thread_data *td, int iodepth, int bs,
                     char *dev_path, void *options) {
    size_t buf_size;
    struct io_unode *unode;
    int ret;

    buf_size = (unsigned long long)iodepth * (unsigned long long)bs;

    ret = posix_memalign(&td->buf, os_page_size(), buf_size);
    if (ret) {
        perror("posix_memalign");
        BUG_ON(1);
        return ret;
    }

    assert(bs % os_cache_line_size() == 0);

    td->iodepth = iodepth;
    td->bs = bs;
    td->dev_path = dev_path;
    td->options = options;
    td->io_ops = NULL;
    spin_lock_init(&td->td_lock);

    spin_lock_init(&td->comp_lock);
    spin_lock_init(&td->avai_lock);
    td->comp_bm =
        kzalloc(BITS_TO_LONGS(iodepth) * sizeof(unsigned long), GFP_KERNEL);
    INIT_LIST_HEAD(&td->avai_q);

    unode = calloc(1, sizeof(struct io_unode));
    if (!unode) {
        perror("calloc");
        BUG_ON(1);
        return -ENOMEM;
    }
    unode->io_u_idx_start = 0;
    unode->io_u_idx_end = iodepth;
    list_add_tail(&unode->list, &td->avai_q);

    td->io_us = calloc(iodepth, sizeof(struct io_u));
    if (!td->io_us) {
        perror("calloc");
        BUG_ON(1);
        return -ENOMEM;
    }

    for (int i = 0; i < iodepth; i++) {
        td->io_us[i].buf = td->buf + i * bs;
        td->io_us[i].cap = bs;
        td->io_us[i].idx = i;
    }

    return 0;
}

int thread_data_cleanup(struct thread_data *td) {
    struct io_unode *unode, *n;

    list_for_each_entry_safe(unode, n, &td->avai_q, list) {
        list_del(&unode->list);
        free(unode);
    }
    free(td->comp_bm);
    free(td->buf);
    free(td->io_us);

    return 0;
}

int __get_io_u(struct thread_data *td, struct io_u **io_u) {
    struct io_unode *unode;
    int idx;

    spin_lock(&td->avai_lock);

    unode = list_first_entry(&td->avai_q, struct io_unode, list);
    if (!unode) {
        spin_unlock(&td->avai_lock);
        return -1;
    }

    idx = unode->io_u_idx_start++;
    if (unode->io_u_idx_start == unode->io_u_idx_end) {
        list_del(&unode->list);
        free(unode);
    }
    spin_unlock(&td->avai_lock);

    *io_u = &td->io_us[idx];

    return 0;
}

int get_io_u(struct thread_data *td, struct io_u **io_u) {
    int ret, min = 1, r;

    ret = __get_io_u(td, io_u);
    if (!io_u) {
        // Digest queued io_u(s)
        assert(td->io_ops->commit);

        spin_lock(&td->td_lock);
        min = td->io_ops->commit(td);
        spin_unlock(&td->td_lock);

        min = min > 0 ? min : 1;

        assert(td->io_ops->getevents);
        spin_lock(&td->td_lock);
        r = td->io_ops->getevents(td, min, td->iodepth);
        spin_unlock(&td->td_lock);
        assert(r > 0);

        // Retry
        ret = get_io_u(td, io_u);
        if (!io_u) {
            return -EBUSY;
        }
    }
    return ret;
}

int __enqueue_io_u(struct list_head *q, struct io_u *io_u) {
    struct io_unode *unode;
    int idx, new_node = 0;

    idx = io_u->idx;
    unode = list_first_entry(q, struct io_unode, list);
    if (unode) {
        if (idx == unode->io_u_idx_start - 1) {
            unode->io_u_idx_start--;
        } else if (idx == unode->io_u_idx_end) {
            unode->io_u_idx_end++;
        } else {
            new_node = 1;
        }
    }

    if (new_node) {
        unode = calloc(1, sizeof(struct io_unode));
        if (!unode) {
            perror("calloc");
            BUG_ON(1);
            return -ENOMEM;
        }
        unode->io_u_idx_start = idx;
        unode->io_u_idx_end = idx + 1;
        list_add_tail(&unode->list, q);
    }

    return 0;
}

int mark_io_u_complete(struct thread_data *td, struct io_u *io_u) {
    spin_lock(&td->comp_lock);
    bitmap_set(td->comp_bm, io_u->idx, 1);
    spin_unlock(&td->comp_lock);
    return 0;
}

int mark_io_u_available(struct thread_data *td, struct io_u *io_u) {
    int ret;
    spin_lock(&td->avai_lock);
    ret = __enqueue_io_u(&td->avai_q, io_u);
    if (ret) {
        spin_unlock(&td->avai_lock);
        return ret;
    }
    spin_unlock(&td->avai_lock);
    return 0;
}

static struct list_head engine_list;

static inline struct ioengine_ops *find_ioengine(const char *name) {
    struct ioengine_ops *io_ops;

    list_for_each_entry(io_ops, &engine_list, list) {
        if (strcmp(io_ops->name, name) == 0) {
            return io_ops;
        }
    }

    return NULL;
}

static inline void register_ioengine(struct ioengine_ops *io_ops) {
    list_add_tail(&io_ops->list, &engine_list);
}

static inline void unregister_ioengine(struct ioengine_ops *io_ops) {
    list_del(&io_ops->list);
}

extern struct ioengine_ops uring_io_ops;

int io_register(void) {
    INIT_LIST_HEAD(&engine_list);
    register_ioengine(&uring_io_ops);
    return 0;
}

int io_unregister(void) {
    unregister_ioengine(&uring_io_ops);
    return 0;
}

int io_open(struct thread_data *td, const char *e) {
    struct ioengine_ops *io_ops;

    io_ops = find_ioengine(e);
    if (!io_ops) {
        printf("io engine %s not found\n", e);
        return -1;
    }

    td->io_ops = io_ops;
    td->ack_thread = kthread_create(complete_ack_thread, td, NULL);

    return 0;
}

int io_close(struct thread_data *td) {
    if (td->ack_thread)
        kthread_stop(td->ack_thread);
    td->io_ops = NULL;
    return 0;
}

// Return partial write io_u idx (it is your choice to queue it or not)
// -1 means no partial write, all io_u(s) are queued
// -EBUSY means no io_u available
// >= 0 means partial write, the idx of the io_u that is not queued
int io_write(struct thread_data *td, off_t offset, char *buf, size_t len) {
    struct io_u *io_u = NULL;
    int ret = -1;
    int i, loop = len / td->bs;
    size_t per_size;

    for (i = 0; i < loop; i++) {
        ret = get_io_u(td, &io_u);
        if (ret) {
            printf("get_io_u failed\n");
            return -EBUSY;
        }

        per_size = len > td->bs ? td->bs : len;

        io_u->opcode = IO_WRITE;
        io_u->offset = offset;
        io_u->len = per_size;
        memcpy(io_u->buf, buf, per_size);

        // When the io_u is full, queue it
        if ((per_size & (td->bs - 1)) == 0) {
            assert(td->io_ops->queue);

            spin_lock(&td->td_lock);
            td->io_ops->queue(td, io_u);
            spin_unlock(&td->td_lock);
        }

        offset += td->bs;
        len -= td->bs;
        buf += td->bs;
    }

    return io_u->idx;
}

int __check_in_range(struct io_u *io_u, off_t offset, size_t len) {
    return io_u->offset >= offset && io_u->offset + io_u->len <= offset + len;
}

// Must wait for all io_u(s) to be completed
int io_read(struct thread_data *td, off_t offset, char *buf, size_t len) {
    struct io_u *io_u = NULL;
    int ret = -1, r, min = 1;
    int i, loop = len / td->bs;
    size_t per_size;

    for (i = 0; i < loop; i++) {
        ret = get_io_u(td, &io_u);
        if (ret) {
            printf("get_io_u failed\n");
            return -EBUSY;
        }

        per_size = len > td->bs ? td->bs : len;

        io_u->opcode = IO_READ;
        io_u->offset = offset;
        io_u->len = per_size;

        assert(td->io_ops->queue);

        spin_lock(&td->td_lock);
        td->io_ops->queue(td, io_u);
        spin_unlock(&td->td_lock);

        offset += td->bs;
        len -= td->bs;
        buf += td->bs;
    }

    // Digest queued io_u(s)
    spin_lock(&td->td_lock);

    assert(td->io_ops->commit);
    min = td->io_ops->commit(td);

    assert(td->io_ops->getevents);
    r = td->io_ops->getevents(td, min, td->iodepth);
    // NOTE: many io_u(s) that belongs to different threads
    //       may be completed
    assert(r >= 0);

    spin_unlock(&td->td_lock);

    while (loop) {
        for (i = 0; i < td->iodepth; i++) {
            if (test_bit(i, td->comp_bm)) {
                io_u = &td->io_us[i];
                // This is the io_u belongs to this thread
                if (io_u->opcode == IO_READ &&
                    __check_in_range(io_u, offset, len)) {
                    memcpy(buf + io_u->offset, io_u->buf, io_u->len);
                    clear_bit(i, td->comp_bm);
                    mark_io_u_available(td, io_u);

                    loop--;
                }
            }
        }
    }

    return 0;
}