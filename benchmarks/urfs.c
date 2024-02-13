#include "../backend/common.h"
#include "common.h"

struct thread_data *td = NULL;

#define DEVSIZE (16 * 1024L * 1024L * 1024L)
#define BLKSIZE 4096
#define INVALID_PBA 0xFFFFFFFFFFFFFFFF
struct urfs_extent {
    uint64_t pba;
    uint64_t nblk;
} __attribute__((packed));

#define HEADERSIZE 512
#define FULLPATH 512
#define METASIZE (3 * 1024)
#define MAX_NEXTENTS (METASIZE / sizeof(struct urfs_extent))

struct urfs_iheader {
    uint64_t ino;
    uint64_t size;
    uint64_t gran;
    char padding[HEADERSIZE - 24];
} __attribute__((packed));

struct urfs_inode {
    struct urfs_iheader header;
    char fullpath[FULLPATH];
    char meta[METASIZE];
} __attribute__((packed));

static_assert(sizeof(struct urfs_inode) == 4096);

#define INODE_TABLE_START (8 * 1024L * 1024L * 1024L)
#define DATA_SIZE INODE_TABLE_START
#define LEVEL_SIZE (2 * 1024 * 1024)
// [start, end)
struct urfs_alloc_node {
    struct list_head list;
    uint64_t start;
    uint64_t end;
};

#define ALLOC_SMALL_ZONE 0x0
#define ALLOC_LARGE_ZONE 0x1

struct urfs_alloc_node urfs_alloc_list;
struct urfs_inode itarget = {.header.gran = 2 * 1024 * 1024};
struct inode inode = {.i_private = &itarget};
struct file filp = {.f_inode = &inode};

void urfs_init_allocator(uint64_t start, uint64_t end) {
    INIT_LIST_HEAD(&urfs_alloc_list.list);
    struct urfs_alloc_node *node = (struct urfs_alloc_node *)kmalloc(
        sizeof(struct urfs_alloc_node), GFP_KERNEL);
    node->start = start;
    node->end = end;
    list_add(&node->list, &urfs_alloc_list.list);
}

void urfs_destroy_allocator() {
    struct urfs_alloc_node *node = NULL;
    struct urfs_alloc_node *tmp = NULL;

    list_for_each_entry_safe(node, tmp, &urfs_alloc_list.list, list) {
        list_del(&node->list);
        kfree(node);
    }
}

void urfs_init_itarget() {
    itarget.header.ino = 0;
    itarget.header.size = 0;
    memset(itarget.fullpath, 0, FULLPATH);
    memset(itarget.meta, 0, METASIZE);
    for (int i = 0; i < MAX_NEXTENTS; i++) {
        ((struct urfs_extent *)itarget.meta)[i].pba = INVALID_PBA;
        ((struct urfs_extent *)itarget.meta)[i].nblk = 0;
    }
}

long urfs_alloc_zone(u8 mode, uint64_t size) {
    uint64_t nblk = round_up(size, BLKSIZE) / BLKSIZE;
    long ret = -ENOSPC;
    struct urfs_alloc_node *node = NULL;
    struct urfs_alloc_node *tmp = NULL;

    if (mode == ALLOC_SMALL_ZONE) {
        assert(nblk == 1);
        // alloc from the head (normal order)
        list_for_each_entry_safe(node, tmp, &urfs_alloc_list.list, list) {
            if (node->end - node->start >= nblk) {
                ret = node->start;
                node->start += nblk;
                if (node->start == node->end) {
                    list_del(&node->list);
                    kfree(node);
                }
                return ret;
            }
        }
    } else if (mode == ALLOC_LARGE_ZONE) {
        assert(nblk >= 512);
        // alloc from the tail (reverse order)
        list_for_each_entry_safe_reverse(node, tmp, &urfs_alloc_list.list,
                                         list) {
            if (node->end - node->start >= nblk) {
                node->end -= nblk;
                ret = node->end;
                if (node->start == node->end) {
                    list_del(&node->list);
                    kfree(node);
                }
                return ret;
            }
        }
    }

    return ret;
}

int __urfs_find_slot_zone(u8 mode, uint64_t start, uint64_t end,
                          struct urfs_alloc_node **prev,
                          struct urfs_alloc_node **next) {
    struct urfs_alloc_node *node = NULL;
    struct urfs_alloc_node *tmp = NULL;
    *prev = NULL;
    *next = NULL;
    int ret = -EINVAL;

    if (mode == ALLOC_SMALL_ZONE) {
        // free to the head (normal order)
        list_for_each_entry_safe(node, tmp, &urfs_alloc_list.list, list) {
            if (node->end == start) {
                *prev = node;
                ret = 0;
            }
            if (node->start == end) {
                *next = node;
                ret = 0;
            }

            if (node->end < start) {
                *prev = *prev ? *prev : node;
                return ret;
            }
        }
    } else if (mode == ALLOC_LARGE_ZONE) {
        // free to the tail (reverse order)
        list_for_each_entry_safe_reverse(node, tmp, &urfs_alloc_list.list,
                                         list) {
            if (node->end == start) {
                *prev = node;
                ret = 0;
            }
            if (node->start == end) {
                *next = node;
                ret = 0;
            }

            if (node->start > end) {
                *prev = *prev ? *prev
                              : list_entry(node->list.prev,
                                           struct urfs_alloc_node, list);
                return ret;
            }
        }
    }

    return ret;
}

void urfs_free_zone(u8 mode, uint64_t start, uint64_t end) {
    uint64_t nblk = end - start;
    struct urfs_alloc_node *prev = NULL;
    struct urfs_alloc_node *next = NULL;
    int ret;

    if (mode == ALLOC_SMALL_ZONE) {
        assert(nblk == 1);
    } else if (mode == ALLOC_LARGE_ZONE) {
        assert(nblk >= 512);
    }

    ret = __urfs_find_slot_zone(mode, start, end, &prev, &next);
    if (!ret) {
        if (prev && next) {
            next->start = prev->start;
            list_del(&prev->list);
            kfree(prev);
        } else if (prev) {
            prev->end = end;
        } else if (next) {
            next->start = start;
        }
    } else {
        struct urfs_alloc_node *new_node = (struct urfs_alloc_node *)kmalloc(
            sizeof(struct urfs_alloc_node), GFP_KERNEL);
        new_node->start = start;
        new_node->end = end;
        if (mode == ALLOC_SMALL_ZONE) {
            list_add(&new_node->list,
                     prev ? &prev->list : &urfs_alloc_list.list);
        } else if (mode == ALLOC_LARGE_ZONE) {
            list_add(&new_node->list,
                     prev ? &prev->list : urfs_alloc_list.list.prev);
        }
    }

    return;
}

void urfs_print_free_zone() {
    struct urfs_alloc_node *node = NULL;
    int cnt = 0;

    list_for_each_entry(node, &urfs_alloc_list.list, list) {
        printf("start: %lu, end: %lu\n", node->start, node->end);
        cnt++;
    }

    printf("cnt: %d\n", cnt);
}

int urfs_alloc_test() {
    long ret;
    struct urfs_alloc_node *node = NULL;
    int loop = 10, cnt = 0;

    urfs_init_allocator(0, DEVSIZE / BLKSIZE / 2);

    urfs_print_free_zone();

    for (int i = 0; i < loop; i++) {
        ret = urfs_alloc_zone(ALLOC_SMALL_ZONE, 1 * BLKSIZE);
        assert(ret == i);
    }

    for (int i = 0; i < loop; i++) {
        ret = urfs_alloc_zone(ALLOC_LARGE_ZONE, 512 * BLKSIZE);
        assert(ret == DEVSIZE / BLKSIZE / 2 - 512 * (i + 1));
    }

    for (int i = 0; i < loop; i++) {
        urfs_free_zone(ALLOC_SMALL_ZONE, i, i + 1);
    }
    urfs_print_free_zone();

    for (int i = 0; i < loop; i++) {
        urfs_free_zone(ALLOC_LARGE_ZONE, DEVSIZE / BLKSIZE / 2 - 512 * (i + 1),
                       DEVSIZE / BLKSIZE / 2 - 512 * i);
        urfs_print_free_zone();
    }

    list_for_each_entry(node, &urfs_alloc_list.list, list) {
        assert(node->start == 0);
        assert(node->end == DEVSIZE / BLKSIZE / 2);
        cnt++;
    }

    assert(cnt == 1);

    return 0;
}

void __io_copy(uint64_t src, uint64_t dst, uint64_t len) {
    char *buf = (char *)kmalloc(len, GFP_KERNEL);
    io_read(td, src, buf, len, O_IO_DROP);
    io_write(td, dst, buf, len, O_IO_DROP);
    kfree(buf);
}

int urfs_merge_extents(struct urfs_extent *old_extent1,  // logical low address
                       struct urfs_extent *old_extent2,  // logical high address
                       struct urfs_extent *new_extent) {
    long blk, i;
    int ret = 0;

    blk = urfs_alloc_zone(ALLOC_LARGE_ZONE, itarget.header.gran);
    if (blk < 0) {
        return -ENOSPC;
    }

    for (i = 0; i < old_extent1->nblk; i++) {
        __io_copy((old_extent1->pba + i) * BLKSIZE, (blk + i) * BLKSIZE,
                  BLKSIZE);
    }

    for (i = 0; i < old_extent2->nblk; i++) {
        __io_copy((old_extent2->pba + i) * BLKSIZE,
                  (blk + old_extent1->nblk + i) * BLKSIZE, BLKSIZE);
    }

    urfs_free_zone(ALLOC_LARGE_ZONE, old_extent1->pba,
                   old_extent1->pba + old_extent1->nblk);

    urfs_free_zone(ALLOC_LARGE_ZONE, old_extent2->pba,
                   old_extent2->pba + old_extent2->nblk);

    new_extent->pba = blk;
    new_extent->nblk = old_extent1->nblk + old_extent2->nblk;

    return ret;
}

long urfs_get_blocks(struct inode *inode, long *blks) {
    uint64_t isize = itarget.header.size;
    uint64_t icap = round_up(isize, itarget.header.gran);
    uint64_t igran = itarget.header.gran;
    uint64_t blk_left = (icap - isize) / BLKSIZE;
    uint64_t iindex = isize / igran, ibuddy_index = 0, i;
    long ret;

    if (blk_left > 0) {
        ret = ((struct urfs_extent *)itarget.meta)[iindex].pba +
              (isize - round_down(isize, igran)) / BLKSIZE;
        *blks = *blks > blk_left ? blk_left : *blks;
    } else {
        if (isize == MAX_NEXTENTS * igran) {
            struct urfs_extent *old_extent, *old_buddy_extent;
            struct urfs_extent *new_extent;
            // upgrade the allocation granularity
            itarget.header.gran *= 2;
            // merge extents using new granularity
            for (i = 0; i < MAX_NEXTENTS / 2; i++) {
                iindex = i * 2;
                ibuddy_index = iindex + 1;
                old_extent = &((struct urfs_extent *)itarget.meta)[iindex];
                old_buddy_extent =
                    &((struct urfs_extent *)itarget.meta)[ibuddy_index];
                new_extent = &((struct urfs_extent *)itarget.meta)[i];
                urfs_merge_extents(old_extent, old_buddy_extent, new_extent);
            }
        }
        ret = urfs_alloc_zone(ALLOC_LARGE_ZONE, itarget.header.gran);
        *blks = *blks > itarget.header.gran / BLKSIZE
                    ? itarget.header.gran / BLKSIZE
                    : *blks;
        if (ret < 0) {
            return -ENOSPC;
        }
    }
    return ret;
}

ssize_t urfs_file_write(struct file *filp, const char __user *buf, size_t len,
                        loff_t *ppos) {
    long blk, blks;
    long written = 0;
    uint64_t iindex;
    struct urfs_extent *extent;

    blks = roundup(len, BLKSIZE) / BLKSIZE;

    itarget.header.size = *ppos;
    while (len > 0) {
        blk = urfs_get_blocks(filp->f_inode, &blks);
        if (blk < 0) {
            return blk;
        }

        written = len > blks * BLKSIZE ? blks * BLKSIZE : len;
        io_write(td, blk * BLKSIZE, buf, written, O_IO_DROP);

        // update inode metadata
        iindex = itarget.header.size / itarget.header.gran;
        extent = &((struct urfs_extent *)itarget.meta)[iindex];
        if (extent->pba == INVALID_PBA) {
            extent->pba = blk;
            extent->nblk = written / BLKSIZE;
        } else {
            extent->nblk += written / BLKSIZE;
        }

        itarget.header.size += written;
        len -= written;
        *ppos += written;

        io_write(
            td,
            INODE_TABLE_START + itarget.header.ino * sizeof(struct urfs_inode),
            (char *)&itarget, sizeof(struct urfs_inode), O_IO_CACHED);
    }

    return len;
}

#define URFS_BENCH_START(name)                       \
    {                                                \
        urfs_init_allocator(0, DATA_SIZE / BLKSIZE); \
        urfs_init_itarget();                         \
        BENCH_START(name)

#define URFS_BENCH_END(loop, size) \
    BENCH_END(loop, size);         \
    urfs_destroy_allocator();      \
    }

int main() {
    td = init_io_engine(-1);
    DECLARE_BENCH_ENV();

    URFS_BENCH_START("urfs seq 256MiB write (no merge)");
    loop = 64 * 1024;
    loff_t pos = 0;
    for (int i = 0; i < loop; i++) {
        urfs_file_write(&filp, buf, 4096, &pos);
    }
    URFS_BENCH_END(loop, loop * 4096);

    URFS_BENCH_START("urfs seq 512MiB write (single merge)");
    loop = 128 * 1024;
    loff_t pos = 0;
    for (int i = 0; i < loop; i++) {
        urfs_file_write(&filp, buf, 4096, &pos);
    }
    URFS_BENCH_END(loop, loop * 4096);

    URFS_BENCH_START("urfs seq 1GiB write (double merge)");
    loop = 256 * 1024;
    loff_t pos = 0;
    for (int i = 0; i < loop; i++) {
        urfs_file_write(&filp, buf, 4096, &pos);
    }
    URFS_BENCH_END(loop, loop * 4096);

    destroy_io_engine(td);
}