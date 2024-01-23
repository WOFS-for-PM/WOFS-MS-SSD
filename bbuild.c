#include "killer.h"

int meta_type_to_bmblk(u16 type) {
    switch (type) {
        case TL_MTA_PKG_ATTR: /* fop: truncate operations */
            return BMBLK_ATTR;
        case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
            return BMBLK_UNLINK;
        case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
            return BMBLK_CREATE;
        case TL_MTA_PKG_DATA: /* I/O: write operations */
            return BMBLK_DATA;
        default:
            return -1;
    }
}

static inline u8 *__hk_get_bm_addr(struct hk_sb_info *sbi, void *buf,
                                   u32 bmblk) {
    u8 *bm;
    if (buf) {
        io_dispatch_read(sbi, (u64)HK_BM_ADDR(sbi, sbi->bm_start, bmblk), buf,
                         BMBLK_SIZE(sbi));
        bm = buf;
    } else {
        if (sbi->dax) {
            assert(sbi->hk_bms == NULL);
            bm = HK_BM_ADDR(sbi, sbi->bm_start, bmblk);
        } else {
            assert(sbi->hk_bms);
            bm = HK_BM_ADDR(sbi, sbi->hk_bms, bmblk);
        }
    }
    return bm;
}

unsigned long hk_get_bm_size(struct super_block *sb) {
    return BMBLK_SIZE(HK_SB(sb)) * BMBLK_NUM;
}

static void commit_bm(struct hk_sb_info *sbi, u8 *bm, u64 blk, u16 bmblk) {
    // NOTE: bm is either in dax device or in hk_bms
    if (sbi->dax) {
        /* NOTE: the bm is then fenced together with the first */
        /* written entry in the corresponding container */
        hk_flush_buffer(bm + (blk >> 3), CACHELINE_SIZE, false);
    } else {
        // make sure block aligned to avoid overwrite
        u64 dev_blk_addr = round_down(
            (u64)HK_BM_ADDR(sbi, sbi->bm_start, bmblk) + (blk >> 3), HK_BLK_SZ);
        u64 buf_blk_addr = round_down((u64)bm + (blk >> 3), HK_BLK_SZ);
        int handle = io_dispatch_write_thru(sbi, dev_blk_addr,
                                            (void *)buf_blk_addr, HK_BLK_SZ);
        io_dispatch_fence(sbi, handle);
    }
}

void hk_set_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk) {
    u8 *bm;
    unsigned long flags = 0;
    struct super_block *sb = sbi->sb;
    INIT_TIMING(time);

    HK_START_TIMING(imm_set_bm_t, time);

    bm = __hk_get_bm_addr(sbi, NULL, bmblk);

    hk_unlock_bm(sb, bmblk, &flags);
    set_bit(blk, (unsigned long *)bm);
    commit_bm(sbi, bm, blk, bmblk);
    hk_lock_bm(sb, bmblk, &flags);

    HK_END_TIMING(imm_set_bm_t, time);
}

void hk_clear_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk) {
    u8 *bm;
    unsigned long flags = 0;
    struct super_block *sb = sbi->sb;
    INIT_TIMING(time);

    HK_START_TIMING(imm_clear_bm_t, time);

    bm = __hk_get_bm_addr(sbi, NULL, bmblk);

    hk_unlock_bm(sb, bmblk, &flags);
    clear_bit(blk, (unsigned long *)bm);
    commit_bm(sbi, bm, blk, bmblk);
    hk_lock_bm(sb, bmblk, &flags);

    HK_END_TIMING(imm_clear_bm_t, time);
}