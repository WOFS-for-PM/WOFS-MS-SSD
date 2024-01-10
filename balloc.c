#include "killer.h"

u64 hk_prepare_layout(struct super_block *sb, int cpuid, u64 blks,
                      enum hk_layout_type type, u64 *blks_prepared, bool zero) {
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];
    u64 target_addr = layout->layout_start;

    tlalloc_param_t param;
    tl_allocator_t *allocator = &layout->allocator;
    int ret = 0;

    tl_build_alloc_param(&param, blks, TL_BLK);
    ret = tlalloc(allocator, &param);
    if (ret) {
        return 0;
    }

    hk_dbg("%s: alloc blk range: %llu - %llu\n", __func__, param._ret_rng.low,
           param._ret_rng.high);

    target_addr = get_ps_blk_addr(sbi, param._ret_rng.low);
    if (blks_prepared != NULL) {
        *blks_prepared = param._ret_allocated;
    }

    if (zero) {
        // TODO:
        hk_notimpl();
    }

    if (!IS_ALIGNED(TRANS_ADDR_TO_OFS(sbi, target_addr), HK_BLK_SZ)) {
        hk_warn("%s: target_addr [%llu] is not aligned to BLOCK\n", __func__,
                TRANS_ADDR_TO_OFS(sbi, target_addr));
    }

    hk_dbg("%s: prepare addr 0x%llx, virt addr start @0x%llx\n", __func__,
           target_addr, sbi->virt_addr);

    return target_addr;
}

int hk_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero,
                    struct hk_layout_prep *prep) {
    struct hk_sb_info *sbi = HK_SB(sb);
    int i, cpuid;
    int start_cpuid;
    u64 blks_prepared = 0;
    u64 target_addr;
    INIT_TIMING(alloc_time);
    HK_START_TIMING(new_data_blocks_t, alloc_time);

    start_cpuid = hk_get_cpuid(sb);

    prep->blks_prepared = 0;
    prep->cpuid = -1;
    prep->target_addr = 0;

    for (i = 0; i < sbi->num_layout; i++) {
        cpuid = (start_cpuid + i) % sbi->num_layout;

        target_addr = hk_prepare_layout(sb, cpuid, *blks, LAYOUT_PACK,
                                        &blks_prepared, zero);
        if (target_addr == 0) {
            continue;
        }

        prep->blks_prepared = blks_prepared;
        prep->cpuid = cpuid;
        prep->target_addr = target_addr;
        *blks -= blks_prepared;
        break;
    }

    HK_END_TIMING(new_data_blocks_t, alloc_time);
    return prep->blks_prepared == 0 ? -1 : 0;
}

int hk_layouts_init(struct hk_sb_info *sbi, int cpus) {
    struct hk_layout_info *layout;
    int cpuid, ret = 0;
    u64 size_per_layout;
    u64 blks_per_layout;
    // use ipu (in-place update) alloc for dax, otherwise for opu.
    u8 alloc_mode = sbi->dax ? TL_ALLOC_IPU : TL_ALLOC_OPU;

    size_per_layout = round_down(sbi->d_size / cpus, HK_BLK_SZ);
    sbi->per_layout_blks = size_per_layout / HK_BLK_SZ;
    sbi->num_layout = cpus;
    sbi->layouts = (struct hk_layout_info *)kcalloc(
        cpus, sizeof(struct hk_layout_info), GFP_KERNEL);
    if (sbi->layouts == NULL) {
        ret = -ENOMEM;
        goto out;
    }

    for (cpuid = 0; cpuid < cpus; cpuid++) {
        layout = &sbi->layouts[cpuid];
        layout->layout_start = sbi->d_addr + size_per_layout * cpuid;
        if (cpuid == cpus - 1) {
            size_per_layout =
                round_down((sbi->d_size - cpuid * size_per_layout), HK_BLK_SZ);
        }
        blks_per_layout = size_per_layout / HK_BLK_SZ;
        layout->cpuid = cpuid;
        layout->layout_blks = blks_per_layout;
        layout->layout_end = layout->layout_start + size_per_layout;
        mutex_init(&layout->layout_lock);

        layout->allocator.private = sbi;
        tl_alloc_init(&layout->allocator, cpuid,
                      get_ps_blk(sbi, layout->layout_start),
                      layout->layout_blks, HK_BLK_SZ, KILLER_MTA_SIZE,
                      alloc_mode, &hk_gc_ops);

        hk_dbg("layout[%d]: 0x%llx-0x%llx, total_blks: %llu\n", cpuid,
               layout->layout_start, layout->layout_end, layout->layout_blks);
    }

out:
    return ret;
}

int hk_layouts_free(struct hk_sb_info *sbi) {
    struct hk_layout_info *layout;

    int cpuid;
    if (sbi->layouts) {
        for (cpuid = 0; cpuid < sbi->num_layout; cpuid++) {
            layout = &sbi->layouts[cpuid];
            tl_destory(&layout->allocator);
        }
        kfree(sbi->layouts);
    }
    return 0;
}

#define __readonly

extern u32 bm_weight(u8 *bm, u32 len);
extern u8 bm_test(u8 *bm, u32 i);

static unsigned long hk_victim_selection(void *_alloc,
                                         __readonly struct list_head *pend_list,
                                         struct list_head *victim_list,
                                         u64 blks_remain,
                                         u64 *blks_to_reserve) {
    tl_allocator_t *alloc = _alloc;
    unsigned long blks_to_reclaim = 0;
    // valid entries count
    unsigned long ve_cnt = 0, ve_cur_node;
    tl_node_t *node;
    victim_node_t *vict_node;
    u64 entries_perblk = alloc->meta_manager.meta_entries_perblk;
    u64 blk_size = alloc->data_manager.blk_size;

    *blks_to_reserve = 0;
    list_for_each_entry(node, pend_list, list) {
        ve_cur_node = bm_weight((u8 *)&node->mnode.bm, entries_perblk);

        if (round_up((ve_cnt + ve_cur_node), blk_size) / entries_perblk >
            blks_remain) {
            break;
        }

        ve_cnt += ve_cur_node;
        blks_to_reclaim += 1;

        vict_node = kmalloc(sizeof(victim_node_t), GFP_ATOMIC);
        vict_node->node = node;
        list_add_tail(&vict_node->list, victim_list);
    }

    *blks_to_reserve = ve_cnt % entries_perblk == 0
                           ? ve_cnt / entries_perblk
                           : ve_cnt / entries_perblk + 1;

    return blks_to_reclaim;
}

extern int reserve_pkg_space_in_layout(obj_mgr_t *mgr,
                                       struct hk_layout_info *layout,
                                       u64 *ps_addr, u32 num, u16 m_alloc_type);

static __always_inline u32 meta_type_to_size(u16 m_alloc_type) {
    switch (m_alloc_type) {
        case TL_MTA_PKG_ATTR: /* fop: truncate operations */
            return MTA_PKG_ATTR_SIZE;
        case TL_MTA_PKG_UNLINK: /* fop: unlink operations */
            return MTA_PKG_UNLINK_SIZE;
        case TL_MTA_PKG_CREATE: /* fop: create/mkdir operations */
            return MTA_PKG_CREATE_SIZE;
        case TL_MTA_PKG_DATA: /* I/O: write operations */
            return MTA_PKG_DATA_SIZE;
        default:
            return -1;
    }
}

static int hk_migration(void *_alloc, struct list_head *victim_list,
                        u8 m_alloc_type_idx, u64 blks_to_reserve) {
    tl_node_t *node;
    victim_node_t *vict_node;
    tlfree_param_t free_param;
    // current allocator is frozen here
    // use TL_NO_LOCK to avoid lock contention
    tl_allocator_t *alloc = (tl_allocator_t *)_alloc;
    struct hk_sb_info *sbi = (struct hk_sb_info *)alloc->private;
    struct super_block *sb = sbi->sb;
    struct hk_layout_info *layout = &sbi->layouts[alloc->cpuid];
    obj_mgr_t *mgr = sbi->obj_mgr;
    u64 old_ps_addr = (u64)-1, ps_addr = 0, entry_addr;
    u16 m_alloc_type = idx_to_meta_type(m_alloc_type_idx);
    u32 entry_size = meta_type_to_size(m_alloc_type);
    u32 entries_perblk = HK_BLK_SZ / entry_size;
    u32 num;
    obj_ref_hdr_t *ref_hdr;
    int ret, i;

    // TODO: maintain reserve index for migration (file index)
    switch (m_alloc_type) {
        case TL_MTA_PKG_DATA:
            num = MTA_PKG_DATA_BLK;
            break;
        case TL_MTA_PKG_ATTR:
            num = MTA_PKG_ATTR_BLK;
            break;
        case TL_MTA_PKG_UNLINK:
            num = MTA_PKG_UNLINK_BLK;
            break;
        case TL_MTA_PKG_CREATE:
            num = MTA_PKG_CREATE_BLK;
            break;
        default:
            hk_notimpl();
    }

    list_for_each_entry(vict_node, victim_list, list) {
        node = vict_node->node;
        if (sbi->dax) {
            // TODO:
        } else {
            char block[HK_BLK_SZ], *p;
            ret = io_read(CUR_DEV_HANDLER_PTR(sb), node->blk << HK_BLK_SZ_BITS,
                          block, HK_BLK_SZ, O_IO_DROP);
            assert(!ret);

            p = block;
            for (i = 0; i < entries_perblk; i += entry_size) {
                if (bm_test((u8 *)&node->mnode.bm, i)) {
                    // The allocation is supposed to be successful
                    // since the allocator is frozen and passed checks
                    ret = reserve_pkg_space_in_layout(
                        mgr, layout, &ps_addr, num,
                        TL_ALLOC_HINT_NO_LOCK | m_alloc_type);
                    assert(!ret);
                    if (round_down(old_ps_addr, HK_BLK_SZ) !=
                        round_down(ps_addr, HK_BLK_SZ)) {
                        // we now evict the old ps_addr
                        io_flush(CUR_DEV_HANDLER_PTR(sb), old_ps_addr,
                                 HK_BLK_SZ);
                        io_fence(CUR_DEV_HANDLER_PTR(sb));
                    }

                    io_write(CUR_DEV_HANDLER_PTR(sb), ps_addr, p, entry_size,
                             O_IO_CACHED);

                    old_ps_addr = ps_addr;

                    // update reference for all entry
                    entry_addr = get_ps_entry_addr(sbi, node->blk, i);
                    ref_hdr = obj_mgr_get_obj2ref(
                        mgr, get_ps_offset(sbi, entry_addr));
                    ret = obj_mgr_alter_obj2ref(mgr, ref_hdr,
                                                get_ps_offset(sbi, ps_addr));
                    assert(!ret);

                    // invalidate the old entry
                    tl_build_free_param(
                        &free_param, node->blk,
                        ((u64)i << 32) | ((u32)entry_size),
                        TL_MTA | m_alloc_type | TL_ALLOC_HINT_NO_LOCK);
                    tlfree(alloc, &free_param);
                }
                p += entry_size;
            }
        }
    }

    if (sbi->dax) {
        // TODO:
    } else {
        io_flush(CUR_DEV_HANDLER_PTR(sb), ps_addr, HK_BLK_SZ);
        io_fence(CUR_DEV_HANDLER_PTR(sb));
    }

    return 0;
}

static int hk_post_clean(void *_alloc, struct list_head *victim_list) {
    struct list_head *pos, *n;
    victim_node_t *vict_node;

    list_for_each_safe(pos, n, victim_list) {
        vict_node = list_entry(pos, victim_node_t, list);
        list_del(pos);
        kfree(vict_node);
    }

    return 0;
}

gc_ops_t hk_gc_ops = {
    .victim_selection = hk_victim_selection,
    .migration = hk_migration,
    .post_clean = hk_post_clean,
};