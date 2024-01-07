#include <assert.h>
#include "backend/common.h"
#include "killer.h"
#include "stats.h"

int measure_timing;
int wprotect;
int support_clwb;

static inline void set_default_opts(struct hk_sb_info *sbi) {
    set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->cpus = 1;  // TODO: num_online_cpus();
    hk_info("%d cpus online\n", sbi->cpus);
}

// Only support NVMe for now in Userspace
static int hk_register_device_info(struct super_block *sb,
                                   struct hk_sb_info *sbi) {
    int ret;
    int *options, sq_poll_cpu = -1;
    options = kzalloc(sizeof(int), GFP_KERNEL);
    *options = sq_poll_cpu;

    sbi->fast_dev.tds =
        kcalloc(sbi->cpus, sizeof(struct thread_data), GFP_KERNEL);
    if (!sbi->fast_dev.tds) {
        hk_err("failed to allocate thread_data array\n");
        return -ENOMEM;
    }

    io_register(false);

    for (int i = 0; i < sbi->cpus; i++) {
        ret = thread_data_init(DEV_HANDLER_PTR(sbi, i), IO_DEPTH, HK_BLK_SZ,
                               DEV_PATH, options);
        BUG_ON(ret);

        ret = io_open(DEV_HANDLER_PTR(sbi, i), "uring");
        BUG_ON(ret);
    }

    sbi->virt_addr = NULL;
    sbi->dax = false;

    return 0;
}

static int hk_unregister_device_info(struct super_block *sb,
                                     struct hk_sb_info *sbi) {
    int ret;

    for (int i = 0; i < sbi->cpus; i++) {
        ret = io_close(DEV_HANDLER_PTR(sbi, i));
        BUG_ON(ret);
        thread_data_cleanup(DEV_HANDLER_PTR(sbi, i));
    }

    io_unregister();

    return 0;
}

static int hk_super_constants_init(struct hk_sb_info *sbi) {
    struct super_block *sb = sbi->sb;

    sbi->blk_sz = HK_BLK_SZ;
    sbi->bm_start = round_up(
        (u64)sbi->virt_addr + KILLER_SUPER_BLKS * HK_BLK_SZ, HK_BLK_SZ);
    sbi->tl_per_type_bm_reserved_blks =
        (round_up(((sbi->initsize >> PAGE_SHIFT) >> 3), HK_BLK_SZ) >>
         HK_BLK_SZ_BITS);
    sbi->bm_size = hk_get_bm_size(sb);
    sbi->fs_start = round_up(sbi->bm_start + sbi->bm_size, HK_BLK_SZ);

    sbi->d_addr = sbi->fs_start;
    sbi->d_size = sbi->initsize - (sbi->d_addr - (u64)sbi->virt_addr);
    sbi->d_blks = sbi->d_size / HK_BLK_SZ;

    return 0;
}

static int hk_features_init(struct hk_sb_info *sbi) {
    int i, ret = 0;
    struct super_block *sb = sbi->sb;

    /* Inode List Related */
    sbi->inode_mgr =
        (struct inode_mgr *)kmalloc(sizeof(struct inode_mgr), GFP_KERNEL);
    if (!sbi->inode_mgr)
        return -ENOMEM;

    // ret = inode_mgr_init(sbi, sbi->inode_mgr);
    // if (ret < 0)
    //     return ret;

    /* zero out vtail */
    atomic64_set(&sbi->vtail, 0);
    sbi->obj_mgr =
        (struct obj_mgr *)kmalloc(sizeof(struct obj_mgr), GFP_KERNEL);
    if (!sbi->obj_mgr) {
        // inode_mgr_destroy(sbi->inode_mgr);
        return -ENOMEM;
    }
    ret = obj_mgr_init(sbi, sbi->cpus, sbi->obj_mgr);
    if (ret) {
        // inode_mgr_destroy(sbi->inode_mgr);
        return ret;
    }

    // hk_dw_init(&sbi->dw, HK_LINIX_SLOTS);

    return 0;
}

int hk_fill_super(struct super_block *sb, void *data, int silent) {
    int ret;
    struct hk_sb_info *sbi;

    INIT_TIMING(mount_time);
    HK_START_TIMING(mount_t, mount_time);

    sbi = kzalloc(sizeof(struct hk_sb_info), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    sb->s_fs_info = sbi;
    sbi->sb = sb;

    set_default_opts(sbi);

    sbi->magic = KILLER_SUPER_MAGIC;

    if (sbi->cpus > POSSIBLE_MAX_CPU) {
        hk_warn("killer does't support more than " __stringify(
            POSSIBLE_MAX_CPU) " cpus for now.\n");
        goto out;
    }

    ret = hk_register_device_info(sb, sbi);
    if (ret) {
        goto out;
    }

    hk_super_constants_init(sbi);

    hk_features_init(sbi);

    hk_layouts_init(sbi, sbi->cpus);

out:
    HK_END_TIMING(mount_t, mount_time);
    return 0;
}

void hk_put_super(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);

    hk_unregister_device_info(sb, sbi);

    kfree(sbi);

    sb->s_fs_info = NULL;
}