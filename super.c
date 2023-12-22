#include "killer.h"

int measure_timing;
int wprotect;
int support_clwb;

static inline void set_default_opts(struct hk_sb_info *sbi) {
    set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->cpus = num_online_cpus();
    hk_info("%d cpus online\n", sbi->cpus);
}

// Only support NVMe for now in Userspace
static int hk_get_device_info(struct super_block *sb, struct hk_sb_info *sbi) {
    int ret;

    assert(!ioring_test());
    
    ret = thread_data_init(&sbi->fast_dev.td, IO_DEPTH, HK_BLK_SZ, DEV_PATH);
    if (ret) {
        BUG_ON(1);
    }
    
    ret = ioring_init(&sbi->fast_dev.td, -1);
    if (ret) {
        BUG_ON(1);
    }

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

    if (sbi->cpus > POSSIBLE_MAX_CPU) {
        hk_warn("killer does't support more than " __stringify(
            POSSIBLE_MAX_CPU) " cpus for now.\n");
        goto out;
    }

    ret = hk_get_device_info(sb, sbi);
    if (ret) {
        goto out;
    }

out:
    return 0;
}

void hk_put_super(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    
    ioring_cleanup(&sbi->fast_dev.td);
    thread_data_cleanup(&sbi->fast_dev.td);

    kfree(sbi);
    sb->s_fs_info = NULL;
}