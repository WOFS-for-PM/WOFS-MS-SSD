#ifndef _HK_BBUILD_H_
#define _HK_BBUILD_H_

#define BMBLK_ATTR 0
#define BMBLK_UNLINK 1
#define BMBLK_CREATE 2
#define BMBLK_DATA 3
#define BMBLK_NUM (4)

#define BMBLK_SIZE(sbi) (sbi->tl_per_type_bm_reserved_blks << PAGE_SHIFT)

#define HK_BM_ADDR(sbi, bmblk_type) \
    (u8 *)((u64)sbi->bm_start +     \
           (bmblk_type *            \
            (sbi->tl_per_type_bm_reserved_blks << KILLER_BLK_SHIFT)))

#endif