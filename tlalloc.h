/**
 * Copyright (C) 2022 Deadpool
 *
 * Two Layer PM Allocator: allocate blocks and meta blocks/entries
 *
 * This file is part of hunter-userspace.
 *
 * hunter-userspace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * hunter-userspace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with hunter-userspace.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _HK_TLALLOC_H
#define _HK_TLALLOC_H

#include "linux/linux_port.h"

#define TL_BLK 0x1
#define TL_MTA 0x2
#define TL_TYPE_MSK 0x000f

#define TL_ALLOC_HINT_NO_LOCK 0x10
#define TL_ALLOC_HINT_MSK 0x00f0

/* typedef enum {
    PKG_ATTR,
    PKG_CREATE,
    PKG_UNLINK,
    PKG_RENAME,
    PKG_DATA,
    PKG_TYPE_NUM
} HUNT_PKG_TYPE; */

// [low, high)
struct range_node {
    struct rb_node node;
    /* Block, inode */
    struct {
        unsigned long low;
        unsigned long high;
    };
};

static inline int default_compare(unsigned long a, unsigned long b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

int range_insert_node(struct rb_root_cached *tree, struct range_node *new_node,
                      int (*comparator)(unsigned long, unsigned long));
int range_find_node(struct rb_root_cached *tree, unsigned long low,
                    struct range_node **ret_node,
                    int (*comparator)(unsigned long, unsigned long));
int range_insert_range(struct rb_root_cached *tree, unsigned long low,
                       unsigned long high,
                       int (*comparator)(unsigned long, unsigned long));
int range_remove_range(struct rb_root_cached *tree, unsigned long low,
                       unsigned long high,
                       int (*comparator)(unsigned long, unsigned long));
unsigned long range_try_pop_N_once(struct rb_root_cached *tree,
                                   unsigned long *N);
/* PKG_UNLINK can be split into CREATE + UNLINK; we use linker to link these two
 * package */
/* corresponding to package in media */
#define TL_MTA_PKG_ATTR 0x1000   /* fop: truncate operations */
#define TL_MTA_PKG_UNLINK 0x2000 /* fop: unlink operations */
#define TL_MTA_PKG_CREATE 0x4000 /* fop: create/mkdir operations */
#define TL_MTA_PKG_DATA 0x8000   /* I/O: write operations */
#define TL_MTA_TYPE_NUM 4
#define TL_MTA_TYPE_MSK 0xff00

static __always_inline int idx_to_meta_type(int idx) {
    switch (idx) {
        case 0:
            return TL_MTA_PKG_ATTR;
        case 1:
            return TL_MTA_PKG_UNLINK;
        case 2:
            return TL_MTA_PKG_CREATE;
        case 3:
            return TL_MTA_PKG_DATA;
        default:
            return -1;
    }
}

static __always_inline int meta_type_to_idx(u16 type) {
    switch (type) {
        case TL_MTA_PKG_ATTR: /* fop: truncate operations */
            return 0;
        case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
            return 1;
        case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
            return 2;
        case TL_MTA_PKG_DATA: /* I/O: write operations */
            return 3;
        default:
            return -1;
    }
}

static __always_inline const char *meta_type_to_str(u16 type) {
    switch (type) {
        case TL_MTA_PKG_ATTR: /* fop: truncate operations */
            return "pkg_attr";
        case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
            return "pkg_unlink";
        case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
            return "pkg_create";
        case TL_MTA_PKG_DATA: /* I/O: write operations */
            return "pkg_data";
        default:
            return "unknown";
    }
}

#define TL_ALLOC_TYPE(flags) (flags & TL_TYPE_MSK)
#define TL_ALLOC_HINT(flags) (flags & TL_ALLOC_HINT_MSK)

#define TL_ALLOC_MTA_TYPE(flags) (flags & TL_MTA_TYPE_MSK)

typedef struct tl_dnode {
    u64 num;
} tl_dnode_t;

typedef struct tl_mnode {
    /* metadata is allocated in 64B granularity in a 4KiB block */
    u64 bm;
    // for OPU update only
    u8 tail;
} tl_mnode_t;

typedef struct tl_node {
    union {
        /* data node */
        struct {
            struct rb_node node;
        };

        /* meta node */
        struct {
            struct hlist_node hnode;
            struct list_head list;
        };
    };
    u64 blk;
    union {
        struct tl_dnode dnode;
        struct tl_mnode mnode;
    };
} tl_node_t;

typedef struct data_mgr {
    struct rb_root_cached free_tree;
    spinlock_t spin;
    u64 blk_size;
} data_mgr_t;

typedef struct victim_node {
    struct list_head list;
    tl_node_t *node;
} victim_node_t;

typedef struct gc_ops {
    unsigned long (*victim_selection)(void *alloc, struct list_head *,
                                      struct list_head *, u64, u64 *);
    int (*migration)(void *alloc, struct list_head *, u8, u64);
    int (*post_clean)(void *alloc, struct list_head *);
} gc_ops_t;

typedef struct typed_meta_mgr {
    struct list_head free_list;
    // For OPU update only
    struct list_head pend_list;
    DECLARE_HASHTABLE(used_blks, 7);
    spinlock_t spin;
} typed_meta_mgr_t;

typedef struct meta_mgr {
    typed_meta_mgr_t tmeta_mgrs[TL_MTA_TYPE_NUM];
    u64 meta_entries_perblk;
    u64 meta_entries_mask;
    gc_ops_t *gc_ops;
    // granularity of meta block
    u64 meta_size;
} meta_mgr_t;

#define TL_ALLOC_IPU 0x1  // in place update
#define TL_ALLOC_OPU 0x2  // out of place update

typedef struct tl_allocator {
    data_mgr_t data_manager;
    meta_mgr_t meta_manager;
    struct range_node rng;
    int cpuid;
    u8 mode;
    void *private;
} tl_allocator_t;

typedef struct tlalloc_param {
    u32 req;
    u16 flags;
    struct range_node _ret_rng;
    u32 _ret_allocated;
    tl_node_t *_ret_node;
} tlalloc_param_t;

#define TLFREE_BLK 0x8000000000000000

typedef struct tlfree_param {
    u16 flags;
    u64 blk;
    union {
        struct {
            u64 num;
        };
        struct {
            u32 entrynr;
            u32 entrynum;
        };
    };
    /* reuse the highest bit of freed to represent whether the block is
     * released.  */
    u64 freed;
} tlfree_param_t;

typedef struct tlrestore_param {
    u16 flags;
    u64 blk;
    union {
        struct {
            u64 num;
        };
        struct {
            u32 entrynr;
            u32 entrynum;
        };
    };
    struct list_head affected_nodes;
} tlrestore_param_t;

void tl_build_free_param(tlfree_param_t *param, u64 blk, u64 num, u16 flags);
void tl_build_alloc_param(tlalloc_param_t *param, u64 req, u16 flags);
void tl_build_restore_param(tlrestore_param_t *param, u64 blk, u64 num,
                            u16 flags);
int tl_alloc_init(tl_allocator_t *alloc, int cpuid, u64 blk, u64 num,
                  u32 blk_size, u32 meta_size, u8 mode, gc_ops_t *gc_ops);
s32 tlalloc(tl_allocator_t *alloc, tlalloc_param_t *param);
unsigned long tlgc(tl_allocator_t *alloc, unsigned long max);
void tlfree(tl_allocator_t *alloc, tlfree_param_t *param);
void tlrestore(tl_allocator_t *alloc, tlrestore_param_t *param);
void tl_destory(tl_allocator_t *alloc);

#endif /* _HK_TLALLOC_H */