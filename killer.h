#ifndef _KILLER_H
#define _KILLER_H

#include "killer_config.h"

#ifndef __KERNEL__
#include "./backend/common.h"
#include "./linux/linux_port.h"

int port_test(void);

#endif

/*
 * Debug code
 */
#ifdef KBUILD_MODNAME
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "[" KBUILD_MODNAME "]: " fmt
#endif
#endif

/* #define hk_dbg(s, args...)		pr_debug(s, ## args) */
#ifdef DEBUG
#define hk_dbg(s, args...) pr_info("cpu-%d: "s, smp_processor_id(), ##args)
#else
#define hk_dbg(s, args...)
#endif
#define hk_dbg1(s, args...)
#define hk_warn(s, args...) pr_warn(s, ##args)
#define hk_info(s, args...) pr_info("cpu-%d: "s, smp_processor_id(), ##args)
#define hk_err(s, args...)                                 \
    do {                                                   \
        pr_error("cpu-%d: "s, smp_processor_id(), ##args); \
        BUG_ON(1);                                         \
    } while (0);

#define hk_notimpl(s, args...)                               \
    do {                                                     \
        pr_warn("%s: not implemented: "s, __func__, ##args); \
        assert(0);                                           \
    } while (0)

#define clear_opt(o, opt) (o &= ~KILLER_MOUNT_##opt)
#define set_opt(o, opt) (o |= KILLER_MOUNT_##opt)
#define test_opt(sb, opt) (HK_SB(sb)->s_mount_opt & KILLER_MOUNT_##opt)

#define TRANS_ADDR_TO_OFS(sbi, addr) \
    (addr == 0 ? 0 : ((u64)(addr) - (u64)(sbi)->virt_addr))
#define TRANS_OFS_TO_ADDR(sbi, ofs) \
    (ofs == 0 ? 0 : ((u64)(ofs) + (sbi)->virt_addr))
#define GET_ALIGNED_BLKNR(ofs_addr) ((ofs_addr) >> KILLER_BLK_SHIFT)

/* ======================= ANCHOR: Global values ========================= */
extern int measure_timing;
extern int wprotect;

#include "rng_lock.h"
#include "stats.h"
#include "bbuild.h"
#include "tlalloc.h"
#include "linix.h"
#include "objm.h"
#include "super.h"
#include "inode.h"
#include "balloc.h"
#include "generic_cachep.h"

#define KILLER_O_ATOMIC 010

void print_debug(int fd);

int *hk_errno();

int hk_mkfs(int flag);

int hk_init(int flag);

int hk_mkdir(const char *pathname, uint16_t mode);

int hk_stat(const char *pathname, struct stat *buf);  // TODO

int hk_fstat(int fd, struct stat *buf);  // TODO

// int  hk_fstat64 (int fd, struct stat64 *buf);

int hk_lstat(const char *pathname, struct stat *buf);  // TODO

int hk_statvfs(const char *path, struct statvfs *buf);  // TODO

int hk_fstatvfs(int fd, struct statvfs *buf);  // TODO

int hk_fstatfs(int fd, struct statfs *buf);  // ******

int hk_truncate(const char *path, off_t length);

int hk_ftruncate(int fd, off_t len);

int hk_open(const char *pathname, int flags, ...);

int hk_openat(int dirfd, const char *pathname, int flags, ...);

int hk_creat(const char *pathname, uint16_t mode);

int hk_close(int fd);

ssize_t hk_write(int fd, const void *buf, size_t count);

ssize_t hk_pwrite(int fd, const void *buf, size_t count, off_t offset);

ssize_t hk_read(int fd, void *buf, size_t count);

ssize_t hk_pread(int fd, void *buf, size_t count, off_t offset);

int hk_link(const char *oldpath, const char *newpath);  // TODO

int hk_unlink(const char *pathname);  // TODO

int hk_rmdir(const char *pathname);  // TODO

int hk_rename(const char *oldpath, const char *newpath);  // ******

DIR *hk_opendir(const char *_pathname);  // ******

struct dirent *hk_readdir(DIR *dirp);  // ******

int hk_closedir(DIR *dirp);  // ******

int hk_chdir(const char *path);  // TODO

char *hk_getcwd(char *buf, int size);  // TODO

int hk_lseek(int fd, int offset, int whence);  // ******

int hk_access(const char *pathname, int mode);  // ******

int hk_fcntl(int fd, int cmd, ...);  // ******

/* ======================= ANCHOR: inode.c ========================= */
// extern const struct address_space_operations hk_aops_dax;
// void hk_init_inode(struct inode *inode, struct hk_inode *pi);
// int hk_init_free_inode_list(struct super_block *sb, bool is_init);
// int hk_init_free_inode_list_percore(struct super_block *sb, int cpuid, bool
// is_init); int inode_mgr_init(struct hk_sb_info *sbi, inode_mgr_t *mgr); int
// inode_mgr_alloc(inode_mgr_t *mgr, u32 *ret_ino); int
// inode_mgr_free(inode_mgr_t *mgr, u32 ino); int inode_mgr_destroy(inode_mgr_t
// *mgr); int inode_mgr_restore(inode_mgr_t *mgr, u32 ino); struct inode
// *hk_iget_opened(struct super_block *sb, unsigned long ino); struct inode
// *hk_iget(struct super_block *sb, unsigned long ino);
void *hk_inode_get_slot(struct hk_inode_info_header *sih, u64 offset);
void hk_init_header(struct super_block *sb, struct hk_inode_info_header *sih,
                    u16 i_mode);

/* ======================= ANCHOR: bbuild.c ========================= */
unsigned long hk_get_bm_size(struct super_block *sb);
void hk_set_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk);
void hk_clear_bm(struct hk_sb_info *sbi, u16 bmblk, u64 blk);
// int hk_recovery(struct super_block *sb);
// int hk_save_layouts(struct super_block *sb);
// int hk_save_regions(struct super_block *sb);

/* ======================= ANCHOR: balloc.c ========================= */
// u64 get_version(struct hk_sb_info *sbi);
int hk_layouts_init(struct hk_sb_info *sbi, int cpus);
int hk_layouts_free(struct hk_sb_info *sbi);
// int hk_find_gaps(struct super_block *sb, int cpuid);
// unsigned long hk_count_free_blocks(struct super_block *sb);
int hk_alloc_blocks(struct super_block *sb, unsigned long *blks, bool zero,
                    struct hk_layout_prep *prep);
// int hk_release_layout(struct super_block *sb, int cpuid, u64 blks,
//                       bool rls_all);

/* ======================= ANCHOR: objm.c ========================= */
obj_ref_inode_t *ref_inode_create(u64 addr, u32 ino);
void ref_inode_destroy(obj_ref_inode_t *ref);
obj_ref_attr_t *ref_attr_create(u64 addr, u32 ino, u16 from_pkg, u64 dep_ofs);
void ref_attr_destroy(obj_ref_attr_t *ref);
obj_ref_dentry_t *ref_dentry_create(u64 addr, const char *name, u32 len,
                                    u32 ino, u32 parent_ino);
void ref_dentry_destroy(obj_ref_dentry_t *ref);
obj_ref_data_t *ref_data_create(u64 addr, u32 ino, u64 ofs, u32 num,
                                u64 data_offset);
void ref_data_destroy(obj_ref_data_t *ref);
int obj_mgr_init(struct hk_sb_info *sbi, u32 cpus, obj_mgr_t *mgr);
void obj_mgr_destroy(obj_mgr_t *mgr);
int obj_mgr_load_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_unload_dobj_control(obj_mgr_t *mgr, void *obj_ref, u8 type);
int obj_mgr_get_dobjs(obj_mgr_t *mgr, int cpuid, u32 ino, u8 type,
                      void **obj_refs);
int obj_mgr_load_imap_control(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int obj_mgr_unload_imap_control(obj_mgr_t *mgr,
                                struct hk_inode_info_header *sih);
struct hk_inode_info_header *obj_mgr_get_imap_inode(obj_mgr_t *mgr, u32 ino);
int reclaim_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih,
                      data_update_t *update);
int reclaim_dram_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int reclaim_dram_create(obj_mgr_t *mgr, struct hk_inode_info_header *sih,
                        obj_ref_dentry_t *ref);
int reclaim_dram_unlink(obj_mgr_t *mgr, struct hk_inode_info_header *sih);
int ur_dram_data(obj_mgr_t *mgr, struct hk_inode_info_header *sih,
                 data_update_t *update);
int ur_dram_latest_attr(obj_mgr_t *mgr, struct hk_inode_info_header *sih,
                        attr_update_t *update);
int ur_dram_latest_inode(obj_mgr_t *mgr, struct hk_inode_info_header *sih,
                         inode_update_t *update);
int check_pkg_valid(void *obj_start, u32 len, struct hk_obj_hdr *last_obj_hdr);
int create_new_inode_pkg(struct hk_sb_info *sbi, u16 mode, const char *name,
                         struct hk_inode_info_header *sih,
                         struct hk_inode_info_header *psih,
                         in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_unlink_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih, obj_ref_dentry_t *ref,
                      in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int update_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 hdr_addr, u64 num_kv_pairs, ...);
int create_data_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    u64 data_addr, off_t offset, size_t size, u64 num,
                    in_pkg_param_t *in_param, out_pkg_param_t *out_param);
int create_attr_pkg(struct hk_sb_info *sbi, struct hk_inode_info_header *sih,
                    int link_change, int size_change, in_pkg_param_t *in_param,
                    out_pkg_param_t *out_param);
int create_rename_pkg(struct hk_sb_info *sbi, const char *new_name,
                      obj_ref_dentry_t *ref, struct hk_inode_info_header *sih,
                      struct hk_inode_info_header *psih,
                      struct hk_inode_info_header *npsih,
                      out_pkg_param_t *unlink_out_param,
                      out_pkg_param_t *create_out_param);
int create_symlink_pkg(struct hk_sb_info *sbi, u16 mode, const char *name,
                       const char *symname, u32 ino, u64 symaddr,
                       struct hk_inode_info_header *sih,
                       struct hk_inode_info_header *psih,
                       out_pkg_param_t *data_out_param,
                       out_pkg_param_t *create_out_param);

/* ======================= ANCHOR: Static Utils ========================= */
static inline int hk_get_cpuid(struct super_block *sb) {
    struct hk_sb_info *sbi = HK_SB(sb);

    return smp_processor_id() % sbi->cpus;
}

static inline void sfence(void) {
    asm volatile("sfence\n" : :);
}

static inline u32 hk_crc32c(u32 crc, const u8 *data, size_t len) {
    u8 *ptr = (u8 *)data;
    u64 acc = crc; /* accumulator, crc32c value in lower 32b */
    u32 csum;

    /* This inline assembly implementation should be equivalent
     * to the kernel's crc32c_intel_le_hw() function used by
     * crc32c(), but this performs better on test machines.
     */
    while (len > 8) {
        asm volatile(/* 64b quad words */
                     "crc32q (%1), %0"
                     : "=r"(acc)
                     : "r"(ptr), "0"(acc));
        ptr += 8;
        len -= 8;
    }

    while (len > 0) {
        asm volatile(/* trailing bytes */
                     "crc32b (%1), %0"
                     : "=r"(acc)
                     : "r"(ptr), "0"(acc));
        ptr++;
        len--;
    }

    csum = (u32)acc;

    return csum;
}

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
                                         unsigned int size) {
    int ret;
    hk_notimpl();
    return ret;
}

static inline int hk_is_protected(struct super_block *sb) {
    return wprotect;
}

static inline void hk_unlock_range(struct super_block *sb, void *p,
                                   unsigned long len, unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    if (hk_is_protected(sb)) {
        if (sbi->dax) {
            hk_notimpl();
        } else {
            // Do nothing
        }
    }
}

static inline void hk_lock_range(struct super_block *sb, void *p,
                                 unsigned long len, unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    if (hk_is_protected(sb)) {
        if (sbi->dax) {
            hk_notimpl();
        } else {
            // Do nothing
        }
    }
}

static inline void hk_unlock_bm(struct super_block *sb, u16 bmblk,
                                unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    void *addr = HK_BM_ADDR(sbi, bmblk);
    u64 size = BMBLK_SIZE(sbi);

    hk_unlock_range(sb, (void *)addr, size, flags);
}

static inline void hk_lock_bm(struct super_block *sb, u16 bmblk,
                              unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    void *addr = HK_BM_ADDR(sbi, bmblk);
    u64 size = BMBLK_SIZE(sbi);

    hk_lock_range(sb, (void *)addr, size, flags);
}

static u64 inline get_ps_addr(struct hk_sb_info *sbi, u64 offset) {
    return (u64)sbi->virt_addr + offset;
}

static u64 inline get_ps_addr_by_data_ref(struct hk_sb_info *sbi,
                                          obj_ref_data_t *ref,
                                          u64 in_file_offset) {
    BUG_ON(!ref);
    if (in_file_offset < ref->ofs) {
        return 0;
    }
    return get_ps_addr(sbi, ref->data_offset) + in_file_offset - ref->ofs;
}

static u64 inline get_ps_offset(struct hk_sb_info *sbi, u64 addr) {
    return addr - (u64)sbi->virt_addr;
}

static u64 inline get_ps_blk_offset(struct hk_sb_info *sbi, u64 blk) {
    return (blk << KILLER_BLK_SHIFT);
}

static u64 inline get_ps_blk(struct hk_sb_info *sbi, u64 addr) {
    return (u64)(get_ps_offset(sbi, addr) >> KILLER_BLK_SHIFT);
}

static u64 inline get_layout_idx(struct hk_sb_info *sbi, u64 offset) {
    u64 idx = (offset - get_ps_offset(sbi, sbi->fs_start)) /
              (sbi->per_layout_blks << KILLER_BLK_SHIFT);
    return idx >= sbi->num_layout ? sbi->num_layout - 1 : idx;
}

static u64 inline get_ps_blk_addr(struct hk_sb_info *sbi, u32 blk) {
    return (u64)sbi->virt_addr + ((u64)blk << KILLER_BLK_SHIFT);
}

static u64 inline get_ps_entry_addr(struct hk_sb_info *sbi, u32 blk,
                                    u32 entrynr) {
    return get_ps_blk_addr(sbi, blk) + ((u64)entrynr << KILLER_MTA_SHIFT);
}

static inline struct tl_allocator *get_tl_allocator(struct hk_sb_info *sbi,
                                                    u64 offset) {
    u64 idx = get_layout_idx(sbi, offset);
    return &sbi->layouts[idx].allocator;
}

static inline void hk_flush_buffer(void *buf, uint32_t len, bool fence) {
    // uint32_t i;

    // len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
    // if (support_clwb) {
    //     for (i = 0; i < len; i += CACHELINE_SIZE)
    //         _mm_clwb(buf + i);
    // } else {
    //     for (i = 0; i < len; i += CACHELINE_SIZE)
    //         _mm_clflush(buf + i);
    // }
    // if (fence)
    //     PERSISTENT_BARRIER();
    hk_notimpl();
}

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length) {
    unsigned int seed = 131;  // 31 131 1313 13131 131313 etc..
    unsigned long hash = 0;
    int i;

    for (i = 0; i < length; i++)
        hash = hash * seed + (*str++);

    return hash;
}

#define use_droot(droot, type) (spin_lock(&droot->type##_lock))
#define rls_droot(droot, type) (spin_unlock(&droot->type##_lock))

#endif