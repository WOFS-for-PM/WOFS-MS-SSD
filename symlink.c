#include "killer.h"

int hk_block_symlink(struct super_block *sb, struct inode *inode,
                     const char *symname, int len, void *out_blk_addr) {
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    struct hk_layout_prep prep;
    unsigned long blks = 0;
    u64 blk_addr = 0;
    // unsigned long irq_flags = 0;
    int ret = 0;

    obj_ref_data_t *ref = NULL;
    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, 0);
    if (ref) {
        blk_addr = get_ps_addr(sbi, ref->data_offset);
    }

    if (blk_addr == 0) {
        blks = 1;
        ret = hk_alloc_blocks(sb, &blks, true, &prep);
        if (ret) {
            hk_dbg("%s: alloc blocks failed\n", __func__);
            ret = -ENOSPC;
            return ret;
        }
        blk_addr = prep.target_addr;
    }

    /* the block is zeroed already */
    io_dispatch_write_thru(sbi, blk_addr, (void *)symname, len);

    if (out_blk_addr) {
        *(u64 *)out_blk_addr = blk_addr;
    }

    return 0;
}

/* FIXME: Temporary workaround */
static int hk_readlink_copy(char __user *buffer, int buflen, const char *link) {
    int len = PTR_ERR(link);

    if (IS_ERR(link))
        goto out;

    len = strlen(link);
    if (len > (unsigned int)buflen)
        len = buflen;

    if (copy_to_user(buffer, link, len))
        len = -EFAULT;
out:
    return len;
}

static int hk_readlink(struct dentry *dentry, char __user *buffer, int buflen) {
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    obj_ref_data_t *ref = NULL;
    u64 blk_addr;
    void *target_addr;
    int ret;

    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, 0);
    blk_addr = get_ps_addr(sbi, ref->data_offset);

    target_addr = io_dispatch_mmap(sbi, blk_addr, HK_BLK_SZ, IO_D_PROT_READ);
    ret = hk_readlink_copy(buffer, buflen, target_addr);
    io_dispatch_munmap(sbi, target_addr);

    return ret;
}

static const char *hk_get_link(struct dentry *dentry, struct inode *inode,
                               struct delayed_call *done) {
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    char *link;

    obj_ref_data_t *ref = NULL;
    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, 0);

    if (sbi->dax)
        link = (char *)get_ps_addr(sbi, ref->data_offset);
    else
        link = inode->i_link;

    return link;
}

const struct inode_operations hk_symlink_inode_operations = {
    .readlink = hk_readlink,
    .get_link = hk_get_link,
    // .setattr = hk_notify_change,
};
