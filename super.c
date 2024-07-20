#include "killer.h"
#include "stats.h"

int measure_timing;
int wprotect;
int support_clwb;
unsigned int hk_dbgmask;

static struct kmem_cache *hk_inode_cachep;

static void init_once(void *foo) {
    struct hk_inode_info *vi = foo;

    inode_init_once(&vi->vfs_inode);
}

static int __init init_inodecache(void) {
    hk_inode_cachep =
        kmem_cache_create("hk_inode_cache", sizeof(struct hk_inode_info), 0,
                          (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), init_once);
    if (hk_inode_cachep == NULL)
        return -ENOMEM;
    return 0;
}

static void destroy_inodecache(void) {
    /*
     * Make sure all delayed rcu free inodes are flushed before
     * we destroy cache.
     */
    if (hk_inode_cachep) {
        kmem_cache_destroy(hk_inode_cachep);
        hk_inode_cachep = NULL;
    }
}

static struct inode *hk_alloc_inode(struct super_block *sb) {
    struct hk_inode_info *vi;

    vi = kmem_cache_alloc(hk_inode_cachep, GFP_NOFS);
    if (!vi)
        return NULL;

    vi->header = NULL;

    return &vi->vfs_inode;
}

static void hk_destroy_inode(struct inode *inode) {
    struct hk_inode_info *vi = HK_I(inode);

    kmem_cache_free(hk_inode_cachep, vi);
}

struct super_operations hk_sops = {
    .alloc_inode = hk_alloc_inode,
    .destroy_inode = hk_destroy_inode,
    .evict_inode = NULL,
};

static int __init hk_create_slab_caches(void) {
    init_inodecache();
    init_obj_ref_inode_cache();
    init_obj_ref_attr_cache();
    init_obj_ref_dentry_cache();
    init_obj_ref_data_cache();
    init_claim_req_cache();
    init_hk_inode_info_header_cache();
    init_tl_node_cache();
    return 0;
}

void hk_destory_slab_caches(void) {
    destroy_inodecache();
    destroy_obj_ref_inode_cache();
    destroy_obj_ref_attr_cache();
    destroy_obj_ref_dentry_cache();
    destroy_obj_ref_data_cache();
    destroy_claim_req_cache();
    destroy_hk_inode_info_header_cache();
    destroy_tl_node_cache();
}

static inline void set_default_opts(struct hk_sb_info *sbi) {
    set_opt(sbi->s_mount_opt, ERRORS_CONT);
    sbi->cpus = 1;  // TODO: num_online_cpus();
    hk_info("%d cpus online\n", sbi->cpus);
}

enum {
    Opt_bpi,
    Opt_init,
    Opt_mode,
    Opt_uid,
    Opt_gid,
    Opt_dax,
    Opt_measure_timing,
    Opt_history_w,
    Opt_wprotect,
    Opt_err_cont,
    Opt_err_panic,
    Opt_err_ro,
    Opt_dbgmask,
    Opt_err,
    Opt_locality_test
};

static const match_table_t tokens = {
    {Opt_bpi, "bpi=%u"},
    {Opt_init, "init"},
    {Opt_mode, "mode=%o"},
    {Opt_uid, "uid=%u"},
    {Opt_gid, "gid=%u"},
    {Opt_dax, "dax"},
    {Opt_measure_timing, "measure_timing"},
    {Opt_history_w, "history_w"},
    {Opt_wprotect, "wprotect"},
    {Opt_err_cont, "errors=continue"},
    {Opt_err_panic, "errors=panic"},
    {Opt_err_ro, "errors=remount-ro"},
    {Opt_dbgmask, "dbgmask=%u"},
    {Opt_locality_test, "locality_test=%u"},
    {Opt_err, NULL},
};

static int hk_parse_options(char *options, struct hk_sb_info *sbi,
                            bool remount) {
    char *p;
    substring_t args[MAX_OPT_ARGS];
    int option;

    if (!options)
        return 0;

    sbi->locality_test = 0;
    while ((p = strsep(&options, ",")) != NULL) {
        int token;

        if (!*p)
            continue;

        token = match_token(p, tokens, args);
        switch (token) {
            case Opt_init:
                if (remount)
                    goto bad_opt;
                set_opt(sbi->s_mount_opt, FORMAT);
                break;
            case Opt_err_panic:
                clear_opt(sbi->s_mount_opt, ERRORS_CONT);
                clear_opt(sbi->s_mount_opt, ERRORS_RO);
                set_opt(sbi->s_mount_opt, ERRORS_PANIC);
                break;
            case Opt_err_ro:
                clear_opt(sbi->s_mount_opt, ERRORS_CONT);
                clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
                set_opt(sbi->s_mount_opt, ERRORS_RO);
                break;
            case Opt_err_cont:
                clear_opt(sbi->s_mount_opt, ERRORS_RO);
                clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
                set_opt(sbi->s_mount_opt, ERRORS_CONT);
                break;
            case Opt_dax:
                set_opt(sbi->s_mount_opt, DAX);
                break;
            case Opt_measure_timing:
                measure_timing = 1;
                break;
            case Opt_history_w:
                set_opt(sbi->s_mount_opt, HISTORY_W);
                break;
            case Opt_locality_test:
                if (match_int(&args[0], &option))
                    goto bad_val;
                sbi->locality_test = option;
                break;
            case Opt_wprotect:
                if (remount)
                    goto bad_opt;
                set_opt(sbi->s_mount_opt, PROTECT);
                hk_info("hk: Enabling new Write Protection (CR0.WP)\n");
                break;
            case Opt_dbgmask:
                if (match_int(&args[0], &option))
                    goto bad_val;
                hk_dbgmask = option;
                break;
            default: {
                goto bad_opt;
            }
        }
    }

    return 0;

bad_val:
    hk_info("Bad value '%s' for mount option '%s'\n", args[0].from, p);
    return -EINVAL;
bad_opt:
    hk_info("Bad mount option: \"%s\"\n", p);
    return -EINVAL;
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
    sbi->initsize = 16L * 1024 * 1024 * 1024;

    return 0;
}

static int hk_unregister_device_info(struct super_block *sb,
                                     struct hk_sb_info *sbi) {
    int ret;

    for (int i = 0; i < sbi->cpus; i++) {
        io_dispatch_drain(sbi, i);
        io_dispatch_fence(sbi, i);
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

    if (!sbi->dax) {
        sbi->hk_bms = (u8 *)kzalloc(sbi->bm_size, GFP_KERNEL);
        if (!sbi->hk_bms) {
            hk_err("failed to allocate bitmap\n");
            return -ENOMEM;
        }
        hk_info("%s: allocated %llu bytes for bitmap\n", __func__,
                sbi->bm_size);
    }

    return 0;
}

static int hk_misc_init(struct hk_sb_info *sbi) {
    struct super_block *sb = sbi->sb;

    sbi->rih = NULL;

    if (sbi->s_mount_opt & KILLER_MOUNT_FORMAT) {
        sbi->rih = hk_alloc_hk_inode_info_header();
        if (!sbi->rih)
            return -ENOMEM;
        /* do not init dyn array */
        hk_init_header(sb, sbi->rih, S_IFPSEUDO);
        /* reinit modes */
        sbi->rih->i_mode = 0x777 | S_IFDIR;
    }

    return 0;
}

static int hk_misc_exit(struct hk_sb_info *sbi) {
    return 0;
}

static int hk_features_init(struct hk_sb_info *sbi) {
    int ret = 0;

    /* Inode List Related */
    sbi->inode_mgr =
        (struct hk_inode_mgr *)kmalloc(sizeof(struct hk_inode_mgr), GFP_KERNEL);
    if (!sbi->inode_mgr)
        return -ENOMEM;

    ret = hk_inode_mgr_init(sbi, sbi->inode_mgr);
    if (ret < 0)
        return ret;

    /* zero out vtail */
    atomic64_set(&sbi->vtail, 0);
    sbi->obj_mgr =
        (struct obj_mgr *)kmalloc(sizeof(struct obj_mgr), GFP_KERNEL);
    if (!sbi->obj_mgr) {
        hk_inode_mgr_destroy(sbi->inode_mgr);
        return -ENOMEM;
    }
    ret = obj_mgr_init(sbi, sbi->cpus, sbi->obj_mgr);
    if (ret) {
        hk_inode_mgr_destroy(sbi->inode_mgr);
        return ret;
    }

    // hk_dw_init(&sbi->dw, HK_LINIX_SLOTS);

    return 0;
}

static int hk_features_exit(struct hk_sb_info *sbi) {
    obj_mgr_destroy(sbi->obj_mgr);
    hk_inode_mgr_destroy(sbi->inode_mgr);
    return 0;
}

static void hk_set_blocksize(struct super_block *sb, unsigned long size) {
    int bits;

    bits = fls(size) - 1;
    sb->s_blocksize_bits = bits;
    sb->s_blocksize = (1 << bits);
}

/* Update checksum for the DRAM copy */
static inline void hk_update_super_crc(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    u32 crc = 0;

    sbi->hk_sb->s_wtime = get_seconds();
    sbi->hk_sb->s_sum = 0;
    crc = hk_crc32c(~0, (__u8 *)sbi->hk_sb + sizeof(__le32),
                    sizeof(struct hk_super_block));
    sbi->hk_sb->s_sum = crc;
}

static inline void hk_sync_super(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    void *super, *super_redund;
    int handle = 0;

    super = hk_get_super(sb, KILLER_FIRST_SUPER_BLK);
    handle = io_dispatch_write_thru(sbi, (u64)super, sbi->hk_sb, HK_BLK_SZ);
    io_dispatch_fence(sbi, handle);

    super_redund = hk_get_super(sb, KILLER_SECOND_SUPER_BLK);
    handle =
        io_dispatch_write_thru(sbi, (u64)super_redund, sbi->hk_sb, HK_BLK_SZ);
    io_dispatch_fence(sbi, handle);
}

static int hk_format_meta(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    int handle = io_dispatch_clear(sbi, sbi->bm_start, sbi->bm_size);
    io_dispatch_fence(sbi, handle);
    return 0;
}

static int hk_format_killer(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);
    void *super, *super_redund;
    int handle;

    super = hk_get_super(sb, KILLER_FIRST_SUPER_BLK);
    handle = io_dispatch_clear(sbi, (u64)super, HK_BLK_SZ);
    io_dispatch_fence(sbi, handle);

    super_redund = hk_get_super(sb, KILLER_SECOND_SUPER_BLK);
    handle = io_dispatch_clear(sbi, (u64)super_redund, HK_BLK_SZ);
    io_dispatch_fence(sbi, handle);

    hk_format_meta(sb);
    return 0;
}

static inline void hk_mount_over(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);

    sbi->hk_sb->s_valid_umount = HK_INVALID_UMOUNT;
    hk_update_super_crc(sb);

    hk_sync_super(sb);
}

static int hk_init(struct super_block *sb, unsigned long size) {
    unsigned long blocksize;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret;
    INIT_TIMING(init_time);

    HK_START_TIMING(new_init_t, init_time);
    hk_info("creating an empty hunter of size %lu\n", size);

    sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);
    sbi->blocksize = blocksize = HK_BLK_SZ;
    hk_set_blocksize(sb, blocksize);

    hk_dbg("max file name len %d\n", (unsigned int)HK_NAME_LEN);

    hk_format_killer(sb);

    hk_inode_mgr_prefault(sbi, sbi->inode_mgr);

    sbi->hk_sb->s_size = size;
    sbi->hk_sb->s_blocksize = blocksize;
    sbi->hk_sb->s_magic = KILLER_SUPER_MAGIC;
    hk_update_super_crc(sb);

    /* Flush In-DRAM superblock into NVM */
    hk_sync_super(sb);

    in_pkg_param_t create_param;
    in_create_pkg_param_t in_create_param;
    out_pkg_param_t out_param;
    out_create_pkg_param_t out_create_param;

    hk_inode_mgr_restore(sbi->inode_mgr, HK_ROOT_INO);

    in_create_param.create_type = CREATE_FOR_NORMAL;
    in_create_param.new_ino = HK_ROOT_INO;
    create_param.private = &in_create_param;
    out_param.private = &out_create_param;
    create_param.cur_pkg_addr = 0;
    create_param.bin = false;

    ret = create_new_inode_pkg(sbi, 0777 | S_IFDIR, "/", sbi->rih, NULL,
                               &create_param, &out_param);

    if (ret) {
        hk_err("Create root inode failed\n");
        return ret;
    }
    hk_info("Root Inode is initialized at %llx\n",
            get_ps_offset(sbi, out_param.addr));

    HK_END_TIMING(new_init_t, init_time);
    hk_info("hk initialization finish\n");
    return ret;
}

int hk_fill_super(struct super_block *sb, void *data, int silent) {
    int ret;
    struct inode *root_i = NULL;
    struct hk_sb_info *sbi;

    INIT_TIMING(mount_time);
    HK_START_TIMING(mount_t, mount_time);

    sbi = kzalloc(sizeof(struct hk_sb_info), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    sbi->hk_sb = kzalloc(sizeof(struct hk_super_block), GFP_KERNEL);
    if (!sbi->hk_sb) {
        kfree(sbi);
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sbi->sb = sb;

    set_default_opts(sbi);

    sbi->magic = KILLER_SUPER_MAGIC;

    if (sbi->cpus > POSSIBLE_MAX_CPU) {
        ret = -EINVAL;
        hk_warn("killer does't support more than " __stringify(
            POSSIBLE_MAX_CPU) " cpus for now.\n");
        goto out;
    }

    ret = hk_register_device_info(sb, sbi);
    if (ret) {
        goto out;
    }

    ret = hk_parse_options(data, sbi, 0);
    if (ret) {
        hk_err("%s: Failed to parse hk command line options.", __func__);
        goto out;
    }

    hk_super_constants_init(sbi);

    hk_misc_init(sbi);

    hk_features_init(sbi);

    hk_layouts_init(sbi, sbi->cpus);

    if (sbi->s_mount_opt & KILLER_MOUNT_FORMAT) {
        ret = hk_init(sb, sbi->initsize);
        if (ret) {
            hk_err("%s: root init error.", __func__);
            goto out;
        }
        goto setup;
    }

setup:
    sb->s_op = &hk_sops;

    root_i = hk_iget(sb, HK_ROOT_INO);
    if (IS_ERR(root_i)) {
        ret = PTR_ERR(root_i);
        hk_err("%s: failed to get root inode", __func__);

        goto out;
    }

    sb->s_root = d_make_root(root_i);
    if (!sb->s_root) {
        hk_err("get hk root inode failed\n");
        ret = -ENOMEM;
        goto out;
    }

    hk_mount_over(sb);

    ret = 0;

out:
    HK_END_TIMING(mount_t, mount_time);
    return ret;
}

extern int hk_show_stats(void);

void hk_put_super(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);

    if (measure_timing)
        hk_show_stats();

    hk_unregister_device_info(sb, sbi);

    hk_misc_exit(sbi);
    hk_layouts_free(sbi);
    hk_features_exit(sbi);

    kfree(sbi);

    sb->s_fs_info = NULL;
}

int init_hk_fs(void) {
    int ret;
    ret = hk_create_slab_caches();
    if (ret) {
        hk_err("Failed to create slab caches\n");
        return ret;
    }
    assert(sizeof(off_t) == 8);
    return 0;
}

void exit_hk_fs(void) {
    hk_destory_slab_caches();
}