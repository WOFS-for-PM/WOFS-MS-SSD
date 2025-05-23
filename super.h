#ifndef _HK_SUPER_H
#define _HK_SUPER_H

#include "killer.h"

#define KILLER_BLK_SIZE (4 * 1024)
#define KILLER_MTA_SIZE (64)  // 64B grained
#define KILLER_BLK_SHIFT (12)
#define KILLER_MTA_SHIFT (6)

#define DEV_HANDLER_PTR(sbi, n) (&((sbi)->fast_dev.tds[(n)]))
#define CUR_DEV_HANDLER_PTR(sb) DEV_HANDLER_PTR(HK_SB(sb), hk_get_cpuid(sb))

// KILLER fast device type
typedef struct hk_dev {
    struct thread_data *tds;
} hk_dev_t;

struct hk_super_block {
    /* static fields. they never change after file system creation.
     * checksum only validates up to s_start_dynamic field below
     */
    __le32 s_sum;   /* checksum of this sb plus private data appended at the end
                       of this sb */
    __le32 s_magic; /* magic signature */
    __le32 s_padding32;
    __le32 s_blocksize;     /* blocksize in bytes */
    __le64 s_size;          /* total size of fs in bytes */
    char s_volume_name[16]; /* volume name */

    /* all the dynamic fields should go here */
    /* s_mtime and s_wtime should be together and their order should not be
     * changed. we use an 8 byte write to update both of them atomically
     */
    __le32 s_mtime; /* mount time */
    __le32 s_wtime; /* write time */

    __le32 s_last_layout;  /* 0 for lfs, 1 for local, 2 for pack, cannot be
                              changed now */
    __le32 s_valid_umount; /* is valid umount ? */

    __le64 s_vtail;

} __attribute((__packed__));

/*
 * hk super-block data in DRAM
 */
struct hk_sb_info {
    struct super_block *sb;       /* pointer to VFS super block */
    struct hk_super_block *hk_sb; /* DRAM copy of primary SB (i.e., First SB) */
    unsigned long magic;

    unsigned long num_blocks;

    /* Mount options */
    unsigned long bpi;
    unsigned long blocksize;
    unsigned long initsize;
    unsigned long s_mount_opt;

    hk_dev_t fast_dev;
    void *virt_addr;
    bool dax;

    int cpus;

    u32 blk_sz;

    /* data */
    u64 d_addr;
    u64 d_size;
    u64 d_blks;

    /* bitmaps for saving packages allocation info */
    u64 bm_start;
    u64 bm_size;
    void *hk_bms;

    u64 fs_start;
    u64 tl_per_type_bm_reserved_blks;
    atomic64_t vtail;
    struct obj_mgr *obj_mgr;
    struct hk_inode_info_header *rih; /* root header */

    /* for read-ahead */
    size_t ra_win;
    atomic64_t num_readers;

    /* per cpu structure */
    struct hk_layout_info *layouts;
    u32 num_layout;
    u64 per_layout_blks; /* aligned blks */

    /* 32-bits per-core ino allocator */
    struct hk_inode_mgr *inode_mgr;

    /* for dynamic workload */
    struct {
        spinlock_t lock;
        int hist_start;
        int hist_end;
        size_t histories[HK_HISTORY_WINDOWS];
    } dw;

#ifdef AGING_WORKLOAD_SIZE
    size_t aging_pos;
    size_t recover_blks;
    size_t counter;
#endif

    u32 locality_test;
};

static inline struct hk_sb_info *HK_SB(struct super_block *sb) {
    return sb->s_fs_info;
}

static u64 inline hk_inc_and_get_vtail(struct hk_sb_info *sbi) {
    return (u64)atomic64_add_return(1, &sbi->vtail);
}

#endif