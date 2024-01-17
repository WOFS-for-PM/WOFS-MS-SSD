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
    // TODO: I/O
    hk_notimpl();
    // hk_memunlock_block(sb, (void *)blk_addr, &irq_flags);
    memcpy_to_pmem_nocache((void *)blk_addr, symname, len);
    // hk_memlock_block(sb, (void *)blk_addr, &irq_flags);

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
    // TODO: I/O
    hk_notimpl();
    // if (copy_to_user(buffer, link, len))
    //     len = -EFAULT;
out:
    return len;
}

static int hk_readlink(struct dentry *dentry, char __user *buffer, int buflen) {
    struct inode *inode = dentry->d_inode;
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    u64 blk_addr;

    obj_ref_data_t *ref = NULL;
    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, 0);
    blk_addr = get_ps_addr(sbi, ref->data_offset);

    return hk_readlink_copy(buffer, buflen, (char *)blk_addr);
}

static const char *hk_get_link(struct dentry *dentry, struct inode *inode,
                               struct delayed_call *done) {
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    u64 blk_addr;

    obj_ref_data_t *ref = NULL;
    ref = (obj_ref_data_t *)hk_inode_get_slot(sih, 0);

    hk_notimpl();
    // TODO: I/O
    blk_addr = get_ps_addr(sbi, ref->data_offset);

    return (char *)blk_addr;
}

const struct inode_operations hk_symlink_inode_operations = {
    .readlink = hk_readlink,
    .get_link = hk_get_link,
    // .setattr = hk_notify_change,
};
