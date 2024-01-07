#include "killer.h"

u64 hk_prepare_layout(struct super_block *sb, int cpuid, u64 blks,
                      enum hk_layout_type type, u64 *blks_prepared, bool zero) {
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_layout_info *layout = &sbi->layouts[cpuid];
    u64 target_addr = layout->layout_start;
    unsigned long irq_flags = 0;

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

    hk_dbg("%s: prepare addr 0x%llx, virt addr start @0x%llx", __func__,
           target_addr, sbi->virt_addr);

    return target_addr;
}

int hk_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero,
                    struct hk_layout_prep *prep) {
    struct hk_layout_info *layout;
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
        layout = &sbi->layouts[cpuid];

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
    int cpuid;
    u64 size_per_layout;
    u64 blks_per_layout;
    int ret = 0;

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
        tl_alloc_init(&layout->allocator, cpuid,
                      get_ps_blk(sbi, layout->layout_start),
                      layout->layout_blks, HK_BLK_SZ, KILLER_MTA_SIZE);
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
