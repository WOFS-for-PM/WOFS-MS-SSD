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
        memcpy(buf, HK_BM_ADDR(sbi, bmblk), BMBLK_SIZE(sbi));
        bm = buf;
    } else {
        bm = HK_BM_ADDR(sbi, bmblk);
    }
    return bm;
}

unsigned long hk_get_bm_size(struct super_block *sb) {
    return BMBLK_SIZE(HK_SB(sb)) * BMBLK_NUM;
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
    /* NOTE: the bm is then fenced together with the first */
    /* written entry in the corresponding container */
    hk_flush_buffer(bm + (blk >> 3), CACHELINE_SIZE, false);
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
    /* NOTE: the bm is then fenced together with the first */
    /* written entry in the corresponding container */
    hk_flush_buffer(bm + (blk >> 3), CACHELINE_SIZE, false);
    hk_lock_bm(sb, bmblk, &flags);

    HK_END_TIMING(imm_clear_bm_t, time);
}