#ifndef _HK_SUPER_H
#define _HK_SUPER_H

#include "killer.h"

#define DEV_HANDLER_PTR(sbi) (&((sbi)->fast_dev.td))

// KILLER fast device type
typedef struct hk_dev { 
    struct thread_data td;
} hk_dev_t;

/*
 * hk super-block data in DRAM
 */
struct hk_sb_info {
    struct super_block *sb; /* pointer to VFS super block */
    struct hk_super_block *hk_sb; /* DRAM copy of primary SB (i.e., First SB) */
    unsigned long magic;
    
    unsigned long num_blocks;

    /* Mount options */
    unsigned long bpi;
    unsigned long blocksize;
    unsigned long initsize;
    unsigned long s_mount_opt;

    hk_dev_t fast_dev;

    int cpus;

    u32 pblk_sz;
    u32 lblk_sz;

    /* bitmaps for saving packages allocation info */
    u64 bm_start;
    u64 bm_size;
    u64 fs_start;
    u64 tl_per_type_bm_reserved_blks;
    atomic64_t vtail;
    // struct obj_mgr *obj_mgr;
    // struct hk_inode_info_header *rih; /* root header */

    /* for read-ahead */
    size_t ra_win;
    atomic64_t num_readers;

    /* per cpu structure */
    // struct hk_layout_info *layouts;
    u32 num_layout;
    u64 per_layout_blks; /* aligned blks */

    /* 32-bits per-core ino allocator */
    // struct inode_mgr *inode_mgr;

    /* for dynamic workload */
    struct {
        spinlock_t lock;
        int hist_start;
        int hist_end;
        size_t histories[HK_HISTORY_WINDOWS];
    } dw;
};

static inline struct hk_sb_info *HK_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

#endif