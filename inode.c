#include "killer.h"

void *hk_inode_get_slot(struct hk_inode_info_header *sih, u64 offset) {
    struct hk_inode_info *si = sih->si;
    BUG_ON(!si);
    u32 ofs_blk = GET_ALIGNED_BLKNR(offset);
    obj_ref_data_t *ref = NULL;

    ref = (obj_ref_data_t *)linix_get(&sih->ix, ofs_blk);
    if (!ref) {
        return NULL;
    }

    /* check if offset is in ref */
    if (offset >= ref->ofs &&
        offset < ref->ofs + ((u64)ref->num << KILLER_BLK_SHIFT)) {
        return ref;
    }

    hk_dbg("offset %lu (%lu) is not in ref [%lu, %lu] ([%lu, %lu]), "
           "inconsistency happened\n",
           offset, ofs_blk, ref->ofs,
           ref->ofs + ((u64)ref->num << KILLER_BLK_SHIFT),
           GET_ALIGNED_BLKNR(ref->ofs),
           GET_ALIGNED_BLKNR(ref->ofs + ((u64)ref->num << KILLER_BLK_SHIFT)));
    BUG_ON(1);
    return NULL;
}

void hk_init_header(struct super_block *sb, struct hk_inode_info_header *sih,
                    u16 i_mode) {
    int slots = HK_LINIX_SLOTS;

    sih->i_size = 0;
    sih->ino = 0;
    sih->i_blocks = 0;

    if (!S_ISLNK(i_mode)) {
        // TODO: guess slots
        // slots = hk_guess_slots(sb);
        linix_init(&sih->ix, slots);
    } else { /* symlink only need one block */
        linix_init(&sih->ix, 1);
    }

    hash_init(sih->dirs);
    sih->i_num_dentrys = 0;

    sih->i_mode = i_mode;
    sih->i_flags = 0;

    sih->latest_fop.latest_attr = NULL;
    sih->latest_fop.latest_inode = NULL;
    sih->latest_fop.latest_inline_attr = 0;

    sih->si = NULL;
}