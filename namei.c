#include "killer.h"

int hk_insert_dir_table(struct super_block *sb,
                        struct hk_inode_info_header *sih, const char *name,
                        int namelen, void *direntry) {
    obj_ref_dentry_t *ref_dentry = direntry;
    hk_dbg("%s: insert %s hash %lu\n", __func__, name, ref_dentry->hash);
    hash_add(sih->dirs, &ref_dentry->hnode, ref_dentry->hash);

    return 0;
}

static void *__hk_search_dir_table(struct super_block *sb,
                                   struct hk_inode_info_header *sih,
                                   const char *name, int namelen) {
    // struct hk_sb_info *sbi = HK_SB(sb);
    void *cur = NULL;
    unsigned long hash;

    hash = BKDRHash(name, namelen);

    obj_ref_dentry_t *ref_dentry = NULL;
    // struct hk_obj_dentry *dentry;
    hash_for_each_possible(sih->dirs, ref_dentry, hnode, hash) {
        // TODO: Blah, we just assume that the hash is unique
        if (ref_dentry->hash != hash)
            continue;
        // dentry = get_pm_addr(sbi, ref_dentry->hdr.addr);
        // if (strcmp(dentry->name, name) == 0) {
        //     cur = ref_dentry;
        //     break;
        // }
    }

    return cur;
}

static ino_t __hk_inode_by_name(struct inode *dir, struct qstr *entry,
                                void **ret_entry) {
    struct super_block *sb = dir->i_sb;
    struct hk_inode_info *si = HK_I(dir);
    struct hk_inode_info_header *sih = si->header;
    obj_ref_dentry_t *ref_dentry;
    const unsigned char *name;
    unsigned long name_len;
    ino_t ino;

    name = entry->name;
    name_len = entry->len;

    ref_dentry = __hk_search_dir_table(sb, sih, (const char *)name, name_len);
    if (!ref_dentry) {
        hk_dbg("%s: %s not found\n", __func__, name);
        return -1;
    }

    ino = ref_dentry->target_ino;
    if (ret_entry)
        *ret_entry = ref_dentry;

    return ino;
}

static struct dentry *hk_lookup(struct inode *dir, struct dentry *dentry,
                                unsigned int flags) {
    struct inode *inode = NULL;
    void *ref;
    ino_t ino;
    INIT_TIMING(lookup_time);

    HK_START_TIMING(lookup_t, lookup_time);
    if (dentry->d_name.len > HK_NAME_LEN) {
        hk_dbg("%s: namelen %u exceeds limit\n", __func__, dentry->d_name.len);
        return ERR_PTR(-ENAMETOOLONG);
    }

    hk_dbg("%s: %s\n", __func__, dentry->d_name.name);
    ino = __hk_inode_by_name(dir, &dentry->d_name, &ref);
    hk_dbg("%s: ino %lu\n", __func__, ino);

    if (ino != -1) {
        inode = hk_iget(dir->i_sb, ino);
        if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM) ||
            inode == ERR_PTR(-EACCES)) {
            hk_err("%s: get inode failed: %lu\n", __func__, (unsigned long)ino);
            return ERR_PTR(-EIO);
        }
    }

    HK_END_TIMING(lookup_t, lookup_time);
    return d_splice_alias(inode, dentry);
}

static int __hk_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                       bool excl, dev_t rdev, enum hk_new_inode_type type) {
    struct inode *inode = NULL;
    int err = PTR_ERR(inode);
    struct super_block *sb = dir->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    u32 ino;

    hk_dbg("%s: %s\n", __func__, dentry->d_name.name);
    hk_dbg("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

    in_pkg_param_t param;
    in_create_pkg_param_t in_create_param;
    out_pkg_param_t out_param;
    out_create_pkg_param_t out_create_param;
    obj_ref_dentry_t *ref_dentry;

    err = hk_inode_mgr_alloc(sbi->inode_mgr, &ino);
    if (ino == -1)
        goto out_err;

    /* ino is initialized by create_new_inode_pkg() */
    inode = hk_create_inode(type, dir, ino, mode, 0, rdev, &dentry->d_name);
    if (IS_ERR(inode))
        goto out_err;

    in_create_param.create_type = CREATE_FOR_NORMAL;
    if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
        in_create_param.rdev = rdev;
    } else {
        in_create_param.rdev = 0;
    }
    in_create_param.new_ino = ino;
    param.bin = false;
    param.private = &in_create_param;
    param.cur_pkg_addr = 0;
    out_param.private = &out_create_param;

    err = create_new_inode_pkg(sbi, mode, (const char *)dentry->d_name.name,
                               HK_IH(inode), HK_IH(dir), &param, &out_param);
    if (err) {
        goto out_err;
    }

    ref_dentry = ((out_create_pkg_param_t *)out_param.private)->ref;
    err = hk_insert_dir_table(sb, HK_IH(dir), (const char *)dentry->d_name.name,
                              strlen((const char *)dentry->d_name.name),
                              ref_dentry);
    if (err) {
        goto out_err;
    }

    d_instantiate(dentry, inode);
    unlock_new_inode(inode);

    return err;

out_err:
    hk_err("%s return %d\n", __func__, err);
    return err;
}

static int hk_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                     bool excl) {
    int err = 0;
    INIT_TIMING(create_time);
    HK_START_TIMING(create_t, create_time);
    err = __hk_create(dir, dentry, mode, excl, 0, TYPE_CREATE);
    HK_END_TIMING(create_t, create_time);
    return err;
}

const struct inode_operations hk_dir_inode_operations = {
    .create = hk_create,
    .lookup = hk_lookup,
    // .link = hk_link,
    // .unlink = hk_unlink,
    // .symlink = hk_symlink,
    // .mkdir = hk_mkdir,
    // .rmdir = hk_rmdir,
    // .mknod = hk_mknod,
    // .rename = hk_rename,
    // .setattr = hk_notify_change,
    // .get_acl = NULL,
};

const struct inode_operations hk_special_inode_operations = {
    // .setattr = hk_notify_change,
    // .get_acl = NULL,
};