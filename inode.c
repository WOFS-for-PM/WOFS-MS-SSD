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

int hk_inode_mgr_prefault(struct hk_sb_info *sbi, hk_inode_mgr_t *mgr) {
    int cpuid;
    for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
        __hk_init_free_ilist_percore(sbi->sb, cpuid, true);
    }
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

int hk_inode_mgr_restore(hk_inode_mgr_t *mgr, u32 ino) {
    struct hk_sb_info *sbi = mgr->sbi;
    struct super_block *sb = sbi->sb;
    int err = 0;

    int cpuid;
    cpuid = __hk_get_cpuid_by_ino(sb, ino);
    spin_lock(&mgr->ilist_locks[cpuid]);
    err =
        range_remove_range(&mgr->ilists[cpuid], ino, ino + 1, default_compare);
    spin_unlock(&mgr->ilist_locks[cpuid]);

    return err;
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

    if (S_ISPSEUDO(i_mode)) {
        linix_init(&sih->ix, 0);
    } else if (!S_ISLNK(i_mode)) {
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

extern void *hk_lookup_d_obj_ref_lists(d_root_t *root, u32 ino, u8 type);

static int __hk_rebuild_data(struct hk_sb_info *sbi,
                             struct hk_inode_info_header *sih, u32 ino) {
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    d_root_t *root;
    d_obj_ref_list_t *data_list;
    struct list_head *pos;
    obj_ref_data_t *ref;
    data_update_t data_update;
    int i;
    int ret = 0;

    HK_ASSERT(S_ISREG(sih->i_mode));

    if (!sih->ix.slots) {
        ret = linix_init(&sih->ix, HK_LINIX_SLOTS);
        if (ret) {
            hk_err("Init inode data index failed\n");
            return ret;
        }
    } else {
        /* opened already */
        goto out;
    }

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, data);
        data_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DATA);
        if (data_list) {
            list_for_each(pos, &data_list->list) {
                ref = list_entry(pos, obj_ref_data_t, node);

                data_update.build_from_exist = true;
                data_update.exist_ref = ref;
                data_update.addr = ref->hdr.addr;
                data_update.blk = get_ps_blk(sbi, ref->data_offset);
                data_update.ofs = ref->ofs;
                data_update.num = ref->num;
                data_update.i_cmtime = sih->i_mtime;
                data_update.i_size = sih->i_size;

                ur_dram_data(obj_mgr, sih, &data_update);
            }
        }
        rls_droot(root, data);
    }

out:
    return ret;
}

static int __hk_rebuild_dirs(struct hk_sb_info *sbi,
                             struct hk_inode_info_header *sih, u32 ino) {
    obj_mgr_t *obj_mgr = sbi->obj_mgr;
    d_root_t *root;
    d_obj_ref_list_t *dentry_list;
    struct list_head *pos;
    // struct hk_obj_dentry *obj_dentry;
    obj_ref_dentry_t *ref;
    // struct super_block *sb = sbi->sb;
    int i, ret = 0;

    HK_ASSERT(S_ISDIR(sih->i_mode));

    /* TODO: check opened ? */

    for (i = 0; i < obj_mgr->num_d_roots; i++) {
        root = &obj_mgr->d_roots[i];
        use_droot(root, dentry);
        dentry_list = hk_lookup_d_obj_ref_lists(root, ino, OBJ_DENTRY);
        if (dentry_list) {
            list_for_each(pos, &dentry_list->list) {
                ref = list_entry(pos, obj_ref_dentry_t, node);
                // TODO: Insert into dir table, since the name is in the
                // storage, we need to perform I/O
                // TODO: We may write more general I/O wrapper
                // obj_dentry =
                //     (struct hk_obj_dentry *)get_ps_addr(sbi, ref->hdr.addr);
                if (ref->target_ino == ino && ino == HK_ROOT_INO) /* root */
                    continue;
                hk_notimpl();
                // ret = hk_insert_dir_table(sb, sih, obj_dentry->name,
                //                           strlen(obj_dentry->name), ref);
                // if (ret) {
                //     hk_err(sb, "insert ref %p into dir table failed, ret
                //     %d\n",
                //            ref, ret);
                //     return ret;
                // }
            }
        }
        rls_droot(root, dentry);
    }

    return ret;
}

static int __hk_rebuild_inode(struct super_block *sb, struct hk_inode_info *si,
                              u32 ino, bool build_blks) {
    struct hk_inode_info_header *sih = si->header;
    struct hk_sb_info *sbi = HK_SB(sb);
    int ret = 0;

    BUG_ON(sih);
    sih = obj_mgr_get_imap_inode(sbi->obj_mgr, ino);
    if (!sih) {
        return -ENOENT;
    }
    si->header = sih;

    sih->ino = ino;
    if (build_blks) {
        switch (__le16_to_cpu(sih->i_mode) & S_IFMT) {
            case S_IFLNK:
            case S_IFREG:
                ret = __hk_rebuild_data(sbi, sih, ino);
                break;
            case S_IFDIR:
                ret = __hk_rebuild_dirs(sbi, sih, ino);
                break;
            default:
                break;
        }
    }

    return ret;
}

static int __hk_fill_vfs_inode(struct super_block *sb, struct inode *inode,
                               u64 ino) {
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct hk_sb_info *sbi = HK_SB(sb);
    dev_t rdev = 0;
    int ret = -EIO;

    u64 create_pkg_addr =
        get_ps_addr(sbi, sih->latest_fop.latest_inode->hdr.addr);
    if (!create_pkg_addr) {
        hk_err("Failed to get create pkg addr\n");
        goto bad_inode;
    }

    // TODO: Do not bother storage entity now
    // struct hk_obj_inode *obj_inode = (struct hk_obj_inode *)create_pkg_addr;

    inode->i_mode = sih->i_mode;

    // inode->i_generation = obj_inode->i_generation;
    // hk_set_inode_flags(inode, obj_inode->i_xattr,
    //                    le32_to_cpu(obj_inode->i_flags));

    // inode->i_blocks = sih->i_blocks;
    // inode->i_mapping->a_ops = &hk_aops_dax;

    /* Update size and time after rebuild the tree */
    inode->i_size = sih->i_size;
    inode->i_atime.tv_sec = sih->i_atime;
    inode->i_ctime.tv_sec = sih->i_ctime;
    inode->i_mtime.tv_sec = sih->i_mtime;
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec =
        0;
    set_nlink(inode, sih->i_links_count);
    // rdev = le32_to_cpu(obj_inode->dev.rdev);

    switch (inode->i_mode & S_IFMT) {
        case S_IFREG:
            inode->i_op = &hk_file_inode_operations;
            inode->i_fop = &hk_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &hk_dir_inode_operations;
            inode->i_fop = &hk_dir_operations;
            break;
        case S_IFLNK:
            // fall through
            inode->i_op = &hk_symlink_inode_operations;
            break;
        default:
            inode->i_op = &hk_special_inode_operations;
            init_special_inode(inode, inode->i_mode, rdev);
            break;
    }

    return 0;

bad_inode:
    make_bad_inode(inode);
    return ret;
}

static void hk_set_inode_flags(struct inode *inode, bool i_xattr,
                               unsigned int flags) {
    inode->i_flags &=
        ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
    if (flags & FS_SYNC_FL)
        inode->i_flags |= S_SYNC;
    if (flags & FS_APPEND_FL)
        inode->i_flags |= S_APPEND;
    if (flags & FS_IMMUTABLE_FL)
        inode->i_flags |= S_IMMUTABLE;
    if (flags & FS_NOATIME_FL)
        inode->i_flags |= S_NOATIME;
    if (flags & FS_DIRSYNC_FL)
        inode->i_flags |= S_DIRSYNC;
    if (!i_xattr)
        inode_has_no_xattr(inode);
    inode->i_flags |= S_DAX;
}

struct inode *hk_create_inode(enum hk_new_inode_type type, struct inode *dir,
                              u64 ino, umode_t mode, size_t size, dev_t rdev,
                              const struct qstr *qstr) {
    struct super_block *sb;
    struct inode *inode;
    struct hk_inode_info *si;
    struct hk_inode_info_header *sih = NULL;
    int errval;
    unsigned int i_flags;
    unsigned long i_xattr = 0;
    INIT_TIMING(new_inode_time);

    HK_START_TIMING(new_vfs_inode_t, new_inode_time);
    sb = dir->i_sb;
    inode = new_inode(sb);
    if (!inode) {
        errval = -ENOMEM;
        goto fail2;
    }

    inode_init_owner(inode, dir, mode);
    inode->i_blocks = inode->i_size = 0;
    inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

    inode->i_generation = 0;
    inode->i_size = size;
    inode->i_mode = mode;

    /* chosen inode is in ino */
    if (ino == 0) {
        hk_dbg("%s: create inode without ino initialized\n", __func__);
        BUG_ON(1);
    } else {
        inode->i_ino = ino;
    }

    switch (type) {
        case TYPE_CREATE:
            inode->i_op = &hk_file_inode_operations;
            inode->i_fop = &hk_file_operations;
            break;
        case TYPE_MKNOD:
            init_special_inode(inode, mode, rdev);
            inode->i_op = &hk_special_inode_operations;
            break;
        case TYPE_SYMLINK:
            inode->i_op = &hk_symlink_inode_operations;
            break;
        case TYPE_MKDIR:
            inode->i_op = &hk_dir_inode_operations;
            inode->i_fop = &hk_dir_operations;
            set_nlink(inode, 2);
            break;
        default:
            hk_dbg("Unknown new inode type %d\n", type);
            break;
    }

    i_flags = hk_mask_flags(mode, dir->i_flags);
    si = HK_I(inode);
    sih = si->header;
    if (!sih) {
        sih = hk_alloc_hk_inode_info_header();
        if (!sih) {
            errval = -ENOMEM;
            goto fail1;
        }
        hk_dbg("%s: allocate new sih for inode %llu\n", __func__, ino);
        si->header = sih;
    }
    hk_init_header(sb, sih, inode->i_mode);
    sih->ino = ino;
    sih->si = si;
    sih->i_flags = i_flags;

    i_xattr = 0;

    hk_set_inode_flags(inode, i_xattr, i_flags);

    if (insert_inode_locked(inode) < 0) {
        hk_dbg("hk_new_inode failed ino %lx\n", inode->i_ino);
        errval = -EINVAL;
        goto fail1;
    }

    HK_END_TIMING(new_vfs_inode_t, new_inode_time);
    return inode;

fail1:
    make_bad_inode(inode);
    iput(inode);

fail2:
    HK_END_TIMING(new_vfs_inode_t, new_inode_time);
    return ERR_PTR(errval);
}

struct inode *hk_iget(struct super_block *sb, unsigned long ino) {
    struct hk_inode_info *si;
    struct inode *inode;
    int err;

    inode = iget_locked(sb, ino);
    if (unlikely(!inode)) {
        hk_err("%s: No memory\n", __func__);
        return ERR_PTR(-ENOMEM);
    }

    /* The inode is already exsited */
    if (!(inode->i_state & I_NEW))
        return inode;

    si = HK_I(inode);

    hk_dbg("%s: inode %lu\n", __func__, ino);

    err = __hk_rebuild_inode(sb, si, ino, true);
    if (err) {
        hk_dbg("%s: failed to rebuild inode %lu, ret %d\n", __func__, ino, err);
        goto fail;
    }

    err = __hk_fill_vfs_inode(sb, inode, ino);
    if (unlikely(err)) {
        hk_dbg("%s: failed to read inode %lu\n", __func__, ino);
        goto fail;
    }

    inode->i_ino = ino;

    unlock_new_inode(inode);
    return inode;

fail:
    iget_failed(inode);
    return ERR_PTR(err);
}