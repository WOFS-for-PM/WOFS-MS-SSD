#include "killer.h"

static int __hk_init_free_ilist_percore(struct super_block *sb, int cpuid,
                                        bool is_init) {
    struct hk_sb_info *sbi = HK_SB(sb);
    hk_inode_mgr_t *mgr = sbi->inode_mgr;
    imap_t *imap = &sbi->obj_mgr->prealloc_imap;
    struct hk_inode_info_header *cur;
    int bkt, inums_percore;
    u64 start_ino, end_ino;

    inums_percore = HK_NUM_INO / sbi->cpus;
    start_ino = cpuid * inums_percore;
    if (cpuid == 0) {
        start_ino = HK_RESV_NUM;
        inums_percore -= HK_RESV_NUM;
    }
    end_ino = start_ino + inums_percore;

    if (is_init) {
        // [start_ino, end_ino)
        range_insert_range(&mgr->ilists[cpuid], start_ino, end_ino,
                           default_compare);
    } else {
        /* First insert all values */
        __hk_init_free_ilist_percore(sb, cpuid, true);
        /* Second filter out those existing value */
        hash_for_each(imap->map, bkt, cur, hnode) {
            range_remove_range(&mgr->ilists[cpuid], cur->ino, cur->ino + 1,
                               default_compare);
        }
    }

    mgr->ilist_init[cpuid] = true;

    return 0;
}

int hk_inode_mgr_init(struct hk_sb_info *sbi, hk_inode_mgr_t *mgr) {
    int i, cpus = sbi->cpus;
    mgr->sbi = sbi;

    mgr->ilists = kcalloc(cpus, sizeof(struct rb_root_cached), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        mgr->ilists[i] = RB_ROOT_CACHED;
    mgr->ilist_locks = kcalloc(cpus, sizeof(spinlock_t), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        spin_lock_init(&mgr->ilist_locks[i]);
    mgr->ilist_init = kcalloc(cpus, sizeof(bool), GFP_KERNEL);
    for (i = 0; i < cpus; i++)
        mgr->ilist_init[i] = false;

    return 0;
}

int hk_inode_mgr_alloc(hk_inode_mgr_t *mgr, u32 *ret_ino) {
    u32 ino = (u32)-1;
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    unsigned long req = 1;

    INIT_TIMING(new_hk_ino_time);

    HK_START_TIMING(new_HK_inode_t, new_hk_ino_time);

    int cpuid, start_cpuid;

    cpuid = hk_get_cpuid(sb);
    start_cpuid = cpuid;

    do {
        spin_lock(&mgr->ilist_locks[cpuid]);
        if (unlikely(mgr->ilist_init[cpuid] == false)) {
            __hk_init_free_ilist_percore(sb, cpuid, false);
        }
        if (!RB_EMPTY_ROOT(&mgr->ilists[cpuid].rb_root)) {
            ino = range_try_pop_N_once(&mgr->ilists[cpuid], &req);
            if (req == 0) {
                ino = (u32)-1;
            }
            spin_unlock(&mgr->ilist_locks[cpuid]);
            break;
        }
        spin_unlock(&mgr->ilist_locks[cpuid]);
        cpuid = (cpuid + 1) % sbi->cpus;
    } while (cpuid != start_cpuid);

    if (ino == (u32)-1) {
        hk_info("No free inode\n");
        BUG_ON(1);
    }

    if (ret_ino)
        *ret_ino = ino;

    HK_END_TIMING(new_HK_inode_t, new_hk_ino_time);
    return 0;
}

static int __hk_get_cpuid_by_ino(struct super_block *sb, u64 ino) {
    struct hk_sb_info *sbi = HK_SB(sb);
    int cpuid = 0;
    int inums_percore = HK_NUM_INO / sbi->cpus;
    cpuid = ino / inums_percore;
    return cpuid;
}

int hk_inode_mgr_free(hk_inode_mgr_t *mgr, u32 ino) {
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    int err = 0;

    int cpuid;
    cpuid = __hk_get_cpuid_by_ino(sb, ino);
    spin_lock(&mgr->ilist_locks[cpuid]);
    err =
        range_insert_range(&mgr->ilists[cpuid], ino, ino + 1, default_compare);
    spin_unlock(&mgr->ilist_locks[cpuid]);

    return err;
}

int hk_inode_mgr_destroy(hk_inode_mgr_t *mgr) {
    struct hk_sb_info *sbi = mgr->sbi;
    if (mgr) {
        int cpuid;
        for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
            range_remove_range(&mgr->ilists[cpuid], 0, HK_NUM_INO,
                               default_compare);
        }
        kfree(mgr);
    }
    return 0;
}

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