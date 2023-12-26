#include <assert.h>
#include "backend/common.h"
#include "killer.h"
#include "stats.h"

int measure_timing;
int wprotect;
int support_clwb;

#define DEV_HANDLER_PTR(sbi) &((sbi)->fast_dev.td)

static inline void set_default_opts(struct hk_sb_info *sbi) {
    set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->cpus = num_online_cpus();
    hk_info("%d cpus online\n", sbi->cpus);
}

// Only support NVMe for now in Userspace
static int hk_get_device_info(struct super_block *sb, struct hk_sb_info *sbi) {
    int ret;
    int *options, sq_poll_cpu = -1;
    options = kzalloc(sizeof(int), GFP_KERNEL);
    *options = sq_poll_cpu;

    io_register();
    ret = thread_data_init(DEV_HANDLER_PTR(sbi), IO_DEPTH, HK_BLK_SZ, DEV_PATH,
                           options);
    BUG_ON(ret);

    ret = io_open(DEV_HANDLER_PTR(sbi), "uring");
    BUG_ON(ret);

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
    HK_END_TIMING(mount_t, mount_time);
    return 0;
}

void hk_put_super(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    
    io_close(DEV_HANDLER_PTR(sbi));
    thread_data_cleanup(DEV_HANDLER_PTR(sbi));

    kfree(sbi);

    io_unregister();
    sb->s_fs_info = NULL;
}