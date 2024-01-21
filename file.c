#define _GNU_SOURCE
#include <fcntl.h>

#include "killer.h"

/* Check whether partial content can be written in the allocated block. */
/* `overflow` indicates that the [pos, pos + len) can not be written */
/* in the current block. */
static __always_inline bool hk_check_in_place_append(
    struct hk_inode_info_header *sih, loff_t pos, size_t len, bool *overflow,
    size_t *out_size) {
    loff_t end_pos = pos + len - 1;
    loff_t allocated_size = sih->i_blocks << KILLER_BLK_SHIFT;

    *overflow = false;

    if (pos >= allocated_size) {
        *out_size = 0;
        return false;
    }

    if (end_pos >= allocated_size) {
        *overflow = true;
    }

    *out_size = min((unsigned long)(allocated_size - pos), len);

    return true;
}

static size_t hk_try_in_place_append_write(struct hk_inode_info *si, loff_t pos,
                                           size_t len, unsigned char *content) {
    bool in_place = false, overflow = false;
    struct hk_inode_info_header *sih = si->header;
    struct super_block *sb = si->vfs_inode.i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    // unsigned long irq_flags = 0;
    void *ref;
    size_t out_size = 0;

    INIT_TIMING(io_time);

    in_place = hk_check_in_place_append(sih, pos, len, &overflow, &out_size);
    // hk_info("ino: %ld, i_size: %ld, i_blocks: %ld, in_place: %d, overflow:
    // %d, written: %lu\n",
    //         sih->ino, sih->i_size, sih->i_blocks, in_place, overflow,
    //         written);
    if (in_place) {
        ref = hk_inode_get_slot(sih, pos);
        if (!ref) {
            BUG_ON(1);
        }

        obj_ref_data_t *ref_data = (obj_ref_data_t *)ref;
        void *target = (void *)get_ps_addr_by_data_ref(sbi, ref_data, pos);

        assert(sbi->dax == true);

        HK_START_TIMING(memcpy_w_media_t, io_time);
        io_dispatch_write_thru(sbi, (u64)target, content, out_size);
        HK_END_TIMING(memcpy_w_media_t, io_time);

        /* NOTE: we delay cross-block write to newly allocated block. Thus
         * achieving WO. */
        /*       atomicity can be guaranteed since either the append is OK
         * or not. */
        if (overflow == false) {
            update_data_pkg(sbi, sih, get_ps_addr(sbi, ref_data->hdr.addr), 1,
                            UPDATE_SIZE_FOR_APPEND, pos + out_size);
        }
    }

    return out_size;
}

static __always_inline bool hk_check_overlay(struct hk_inode_info *si,
                                             u64 index) {
    bool is_overlay = false;
    struct hk_inode_info_header *sih = si->header;

    if (index < sih->ix.num_slots &&
        (u64)hk_inode_get_slot(sih, (index << KILLER_BLK_SHIFT)) != 0) {
        is_overlay = true;
    }

    return is_overlay;
}

static bool hk_try_cow(struct hk_inode_info *si, u64 cur_addr, u64 index,
                       u64 start_index, u64 end_index, loff_t each_ofs,
                       size_t *each_size, loff_t offset, size_t len) {
    struct super_block *sb = si->vfs_inode.i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info_header *sih = si->header;
    bool is_overlay = false;
    u64 blk_addr;
    u32 blks_to_write = 0;
    unsigned long irq_flags = 0;
    INIT_TIMING(partial_time);

    HK_START_TIMING(partial_block_t, partial_time);
    is_overlay = hk_check_overlay(si, index);

    if (is_overlay) {
        if (index == start_index) {
            if (each_ofs) {
                obj_ref_data_t *ref = NULL;
                ref = (obj_ref_data_t *)hk_inode_get_slot(
                    sih, (index << PAGE_SHIFT));
                blk_addr =
                    get_ps_addr_by_data_ref(sbi, ref, (index << PAGE_SHIFT));

                io_dispatch_copy(sbi, cur_addr, blk_addr, each_ofs);

                *each_size -= each_ofs;
            }
        }
        blks_to_write = GET_ALIGNED_BLKNR(*each_size + each_ofs - 1);
        index += blks_to_write;
        /* possible addr of end_index */
        cur_addr += ((u64)blks_to_write << PAGE_SHIFT);
        if (index == end_index) {
            each_ofs = (offset + len) & (HK_BLK_SZ - 1);
            if (each_ofs) {
                obj_ref_data_t *ref = NULL;
                ref = (obj_ref_data_t *)hk_inode_get_slot(sih, offset + len);
                if (ref) {
                    blk_addr = get_ps_addr_by_data_ref(sbi, ref, offset + len);

                    io_dispatch_copy(sbi, cur_addr + each_ofs, blk_addr,
                                     HK_BLK_SZ - each_ofs);
                } else {
                    io_dispatch_clear(sbi, cur_addr + each_ofs,
                                      HK_BLK_SZ - each_ofs);
                }
                *each_size -= (HK_BLK_SZ - each_ofs);
            }
        }
    } else {
        if (index == start_index && each_ofs != 0) {
            io_dispatch_unlock_range(sb, (void *)cur_addr, each_ofs,
                                     &irq_flags);
            io_dispatch_clear(sbi, cur_addr, each_ofs);
            io_dispatch_lock_range(sb, (void *)cur_addr, each_ofs, &irq_flags);
            *each_size -= each_ofs;
        }
        blks_to_write = GET_ALIGNED_BLKNR(*each_size + each_ofs - 1);
        index += blks_to_write;
        /* possible addr of end_index */
        cur_addr += ((u64)blks_to_write << PAGE_SHIFT);
        if (index == end_index) {
            each_ofs = (offset + len) & (HK_BLK_SZ - 1);
            if (each_ofs) {
                io_dispatch_clear(sbi, cur_addr + each_ofs,
                                  HK_BLK_SZ - each_ofs);
                *each_size -= (HK_BLK_SZ - each_ofs);
            }
        }
    }

    HK_END_TIMING(partial_block_t, partial_time);
    return is_overlay;
}

static int do_write(struct inode *inode, struct hk_layout_prep *prep,
                    loff_t ofs, size_t size, unsigned char *content,
                    u64 index_cur, u64 start_index, u64 end_index,
                    size_t *out_size) {
    struct super_block *sb = inode->i_sb;
    struct hk_sb_info *sbi = HK_SB(sb);
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    u64 blks_prepared, blks_prep_to_use, addr;
    /* for pack, i.e., write-once */
    in_pkg_param_t in_param;
    out_pkg_param_t out_param;
    size_t each_size;
    loff_t each_ofs;
    int ret = 0;

    INIT_TIMING(io_time);

    addr = prep->target_addr;
    blks_prepared = prep->blks_prepared;
    blks_prep_to_use = prep->blks_prep_to_use;
    *out_size = 0;

    each_ofs = ofs & (HK_BLK_SZ - 1);
    each_size = blks_prep_to_use * HK_BLK_SZ;

    hk_try_cow(si, addr, index_cur, start_index, end_index, each_ofs,
               &each_size, ofs, size);

    HK_START_TIMING(memcpy_w_media_t, io_time);
    io_dispatch_write_thru(sbi, addr + each_ofs, content, each_size);
    HK_END_TIMING(memcpy_w_media_t, io_time);

    in_param.bin = false;
    ret = create_data_pkg(sbi, sih, addr, (index_cur << PAGE_SHIFT), each_size,
                          blks_prepared, &in_param, &out_param);
    if (ret) {
        return ret;
    }

    *out_size = each_size;
    return 0;
}

static __always_inline void hk_use_prepared_blocks(struct hk_layout_prep *prep,
                                                   unsigned long *blks,
                                                   unsigned long blks_orig,
                                                   bool *extend) {
    if (prep->blks_prepared > blks_orig) {
        prep->blks_prep_to_use = blks_orig;
    } else {
        prep->blks_prep_to_use = prep->blks_prepared;
        if (*extend) {
            // hk_warn("%s: blks_prepared %lu, blks_orig %lu\n",
            //         __func__, prep->blks_prepared, blks_orig);
            /* revert to non-extend */
            *blks = blks_orig - prep->blks_prepared;
            *extend = false;
        }
    }
}

ssize_t do_hk_file_write(struct file *filp, const char __user *buf, size_t len,
                         loff_t *ppos) {
    struct inode *inode = file_inode(filp);
    struct super_block *sb = inode->i_sb;
    struct hk_inode_info *si = HK_I(inode);
    struct hk_inode_info_header *sih = si->header;
    unsigned long index, start_index, end_index;
    unsigned long blks, blks_allocated, blks_orig;
    bool append_like = false, extend = false;
    unsigned char *pbuf = (unsigned char *)buf;
    struct hk_layout_prep prep;
    size_t out_size = 0;
    ssize_t written = 0;
    size_t error = 0;
    int ret = 0;
    loff_t pos;

    INIT_TIMING(write_time);

    if (len == 0)
        return 0;

    HK_START_TIMING(write_t, write_time);

    if (!access_ok(buf, len)) {
        error = -EFAULT;
        goto out;
    }

    pos = *ppos;

    if (filp->f_flags & O_APPEND) {
        append_like = true;
        pos = i_size_read(inode);
    }

    if (pos == i_size_read(inode)) {
        append_like = true;
    }

    // force non-append-like write for non-dax
    if (!HK_SB(sb)->dax) {
        append_like = false;
    }

    error = file_remove_privs(filp);
    if (error)
        goto out;

    /* if append write, i.e., pos == file size, try to perform in-place write */
    if (append_like) {
        out_size = hk_try_in_place_append_write(si, pos, len, pbuf);

        pos += out_size;
        len -= out_size;
        pbuf += out_size;
        written += out_size;
    }

    out_size = 0;

    start_index = index = pos >> PAGE_SHIFT;    /* Start from which blk */
    end_index = (pos + len - 1) >> PAGE_SHIFT;  /* End till which blk */
    blks = blks_orig = (end_index - index + 1); /* Total blks to be written */
    blks_allocated = 0;
    if (append_like) {
        /* try extend blks to be allocted */
        if (blks < HK_EXTEND_NUM_BLOCKS) {
            blks = HK_EXTEND_NUM_BLOCKS;
            extend = true;
        }
    }

    inode->i_ctime = inode->i_mtime = current_time(inode);

    hk_dbg("%s: inode %lu, offset %lld, size %lu, blks %lu\n", __func__,
           inode->i_ino, pos, len, blks);

    if (len != 0) {
        while (index <= end_index) {
            ret = hk_alloc_blocks(sb, &blks, false, &prep);
            if (ret) {
                hk_dbg("%s alloc blocks failed %d, %d allocated\n", __func__,
                       ret, blks_allocated);
                goto out;
            }
            hk_use_prepared_blocks(&prep, &blks, blks_orig, &extend);

            do_write(inode, &prep, pos, len, pbuf, index, start_index,
                     end_index, &out_size);

            pos += out_size;
            len -= out_size;
            pbuf += out_size;
            written += out_size;

            index += prep.blks_prep_to_use;
            blks_allocated += prep.blks_prepared;
        }
    }

    sih->i_blocks = max(sih->i_blocks, start_index + blks_allocated);

    inode->i_blocks = sih->i_blocks;

    hk_dbg("%s: len %lu\n", __func__, len);

    *ppos = pos;
    if (pos > inode->i_size) {
        i_size_write(inode, pos);
        sih->i_size = pos;
    }

out:

    HK_END_TIMING(write_t, write_time);
    return written ? written : error;
}

// ==================== Hookers ====================
int hk_open(struct inode *inode, struct file *filp) {
    return generic_file_open(inode, filp);
}

ssize_t hk_file_read(struct file *filp, char __user *buf, size_t len,
                     loff_t *ppos) {
    return 0;
}

ssize_t hk_file_write(struct file *filp, const char __user *buf, size_t len,
                      loff_t *ppos) {
    struct inode *inode = file_inode(filp);
    int ret;

    if (len == 0)
        return 0;

    sb_start_write(inode->i_sb);
    inode_lock(inode);

    ret = do_hk_file_write(filp, buf, len, ppos);

    inode_unlock(inode);
    sb_end_write(inode->i_sb);

    return ret;
}

static loff_t hk_llseek(struct file *filp, loff_t offset, int whence) {
    if (whence != SEEK_DATA && whence != SEEK_HOLE)
        return generic_file_llseek(filp, offset, whence);

    return -EINVAL;
}

const struct inode_operations hk_file_inode_operations;

const struct file_operations hk_file_operations = {
    .llseek = hk_llseek,
    .read = hk_file_read,
    .write = hk_file_write,
    // .read_iter = hk_rw_iter,
    // .write_iter = hk_rw_iter,
    // .mmap = NULL, /* TODO: Not support mmap yet */
    // .mmap_supported_flags = MAP_SYNC,
    .open = hk_open,
    // .fsync = hk_fsync,
    // .flush = hk_flush,
    // .unlocked_ioctl = hk_ioctl,
    .fallocate = NULL, /* TODO: Not support yet */
#ifdef CONFIG_COMPAT
    .compat_ioctl = hk_compat_ioctl,
#endif
};