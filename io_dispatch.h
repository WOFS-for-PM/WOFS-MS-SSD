#ifndef _IO_DISPATCH_H
#define _IO_DISPATCH_H

#include "killer.h"

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length) {
    uint64_t dummy1, dummy2;
    uint64_t qword = ((uint64_t)dword << 32) | dword;

    BUG_ON(length > ((u64)1 << 32));

    asm volatile("movl %%edx,%%ecx\n"
                 "andl $63,%%edx\n"
                 "shrl $6,%%ecx\n"
                 "jz 9f\n"
                 "1:	 movnti %%rax,(%%rdi)\n"
                 "2:	 movnti %%rax,1*8(%%rdi)\n"
                 "3:	 movnti %%rax,2*8(%%rdi)\n"
                 "4:	 movnti %%rax,3*8(%%rdi)\n"
                 "5:	 movnti %%rax,4*8(%%rdi)\n"
                 "8:	 movnti %%rax,5*8(%%rdi)\n"
                 "7:	 movnti %%rax,6*8(%%rdi)\n"
                 "8:	 movnti %%rax,7*8(%%rdi)\n"
                 "leaq 64(%%rdi),%%rdi\n"
                 "decl %%ecx\n"
                 "jnz 1b\n"
                 "9:	movl %%edx,%%ecx\n"
                 "andl $7,%%edx\n"
                 "shrl $3,%%ecx\n"
                 "jz 11f\n"
                 "10:	 movnti %%rax,(%%rdi)\n"
                 "leaq 8(%%rdi),%%rdi\n"
                 "decl %%ecx\n"
                 "jnz 10b\n"
                 "11:	 movl %%edx,%%ecx\n"
                 "shrl $2,%%ecx\n"
                 "jz 12f\n"
                 "movnti %%eax,(%%rdi)\n"
                 "12:\n"
                 : "=D"(dummy1), "=d"(dummy2)
                 : "D"(dest), "a"(qword), "d"(length)
                 : "memory", "rcx");
}

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
                                         unsigned int size) {
    int ret;
    hk_notimpl();
    return ret;
}

static inline void PERSISTENT_BARRIER(void) {
    asm volatile("sfence\n" : :);
}

static inline void io_dispatch_unlock_range(struct super_block *sb, void *p,
                                            unsigned long len,
                                            unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    if (hk_is_protected(sb)) {
        if (sbi->dax) {
            hk_notimpl();
        } else {
            // Do nothing
        }
    }
}

static inline void io_dispatch_lock_range(struct super_block *sb, void *p,
                                          unsigned long len,
                                          unsigned long *flags) {
    struct hk_sb_info *sbi = HK_SB(sb);
    if (hk_is_protected(sb)) {
        if (sbi->dax) {
            hk_notimpl();
        } else {
            // Do nothing
        }
    }
}

#define IO_DISPATCH_START_WRITE 0
#define IO_DISPATCH_START_UPDATE 1
#define IO_DISPATCH_START_READ 2

#define IO_DISPATCH_DAX_REGION_SIZE 4096

#define IO_DISPATCH_START_DAX_REGION_VALUE(sbi, dev_addr, size, mode, \
                                           target_addr)               \
    {                                                                 \
        if (sbi->dax) {                                               \
            target_addr = (typeof(target_addr))dev_addr;              \
        } else {                                                      \
            int handle = hk_get_cpuid(sbi->sb);                       \
            assert(size <= sbi->fast_dev.tds[handle].bs);             \
            assert(sbi->fast_dev.tds[handle].bs <=                    \
                   IO_DISPATCH_DAX_REGION_SIZE);                      \
            char buf[IO_DISPATCH_DAX_REGION_SIZE];                    \
            target_addr = (typeof(target_addr))buf;                   \
            /* must read first if mode is IO_DISPATCH_START_UPDATE or \
             * IO_DISPATCH_START_READ*/                               \
            if (mode == IO_DISPATCH_START_UPDATE ||                   \
                mode == IO_DISPATCH_START_READ) {                     \
                io_read(DEV_HANDLER_PTR(sbi, handle), dev_addr, buf,  \
                        sbi->fast_dev.tds[handle].bs, O_IO_DROP);     \
            }                                                         \
        }
// manipulate `target_addr` here like normal memory
// commit the modifed region
static inline int IO_DISPATCH_COMMIT_REGION_VALUE(struct hk_sb_info *sbi,
                                                  u64 dev_addr, u64 size,
                                                  u64 target_addr) {
    int region_handle = 0;
    if (sbi->dax) {
        hk_flush_buffer((void *)dev_addr, size, true);
    } else {
        get_handle_by_addr(sbi, (u64)dev_addr);
        assert(region_handle >= 0);
        io_write(DEV_HANDLER_PTR(sbi, region_handle), (off_t)dev_addr,
                 (void *)target_addr, size, O_IO_CACHED);
#ifdef MODE_STRICT
        io_clwb(DEV_HANDLER_PTR(sbi, region_handle), (off_t)dev_addr, size);
        io_fence(DEV_HANDLER_PTR(sbi, region_handle));
#endif
    }
    return region_handle;
}
#define IO_DISPATCH_COMMIT_REGION_VALUE_SAFE(sbi, dev_addr, size, target_addr) \
    ({                                                                         \
        int region_handle = 0;                                                 \
        unsigned long irq_flags = 0;                                           \
        io_dispatch_unlock_range(sbi->sb, (void *)dev_addr, size, &irq_flags); \
        region_handle =                                                        \
            IO_DISPATCH_COMMIT_REGION_VALUE(sbi, dev_addr, size, target_addr); \
        io_dispatch_lock_range(sbi->sb, (void *)dev_addr, size, &irq_flags);   \
        region_handle;                                                         \
    })
#define IO_DISPATCH_END_DAX_REGION_VALUE(sbi) }

static inline void io_dispatch_wbinvd(struct hk_sb_info *sbi, int handle,
                                      u64 dev_addr, size_t size) {
    if (sbi->dax) {
        // Do nothing
    } else {
        io_wbinvd(DEV_HANDLER_PTR(sbi, handle), dev_addr, size);
    }
}

static inline void io_dispatch_clwb(struct hk_sb_info *sbi, int handle,
                                    u64 dev_addr, size_t size) {
    if (sbi->dax) {
        hk_flush_buffer((void *)dev_addr, size, false);
    } else {
        io_clwb(DEV_HANDLER_PTR(sbi, handle), dev_addr, size);
    }
}

static inline void io_dispatch_flush(struct hk_sb_info *sbi, int handle,
                                     u64 dev_addr, size_t size) {
    struct super_block *sb = sbi->sb;
    unsigned long irq_flags;

    io_dispatch_unlock_range(sb, (void *)dev_addr, size, &irq_flags);
    if (sbi->dax) {
        hk_flush_buffer((void *)dev_addr, size, false);
    } else {
        io_flush(DEV_HANDLER_PTR(sbi, handle), dev_addr, size);
    }
    io_dispatch_lock_range(sb, (void *)dev_addr, size, &irq_flags);
}

static inline void io_dispatch_fence(struct hk_sb_info *sbi, int handle) {
    if (sbi->dax) {
        PERSISTENT_BARRIER();
    } else {
        io_fence(DEV_HANDLER_PTR(sbi, handle));
    }
}

static inline void io_dispatch_read(struct hk_sb_info *sbi, u64 dev_addr,
                                    void *dst, size_t size) {
    if (sbi->dax) {
        memcpy_to_pmem_nocache(dst, (void *)dev_addr, size);
    } else {
        io_read(CUR_DEV_HANDLER_PTR(sbi->sb), dev_addr, dst, size, O_IO_DROP);
    }
}

static inline void io_dispatch_copy(struct hk_sb_info *sbi, u64 dev_dst_addr,
                                    u64 dev_src_addr, size_t size) {
    unsigned long irq_flags = 0;

    io_dispatch_unlock_range(sbi->sb, (void *)dev_dst_addr, size, &irq_flags);
    if (sbi->dax) {
        memcpy_to_pmem_nocache((void *)dev_dst_addr, (void *)dev_src_addr,
                               size);
    } else {
        char *buf = kmalloc(size, GFP_KERNEL);
        io_read(CUR_DEV_HANDLER_PTR(sbi->sb), dev_src_addr, buf, size,
                O_IO_DROP);
        io_write(CUR_DEV_HANDLER_PTR(sbi->sb), dev_dst_addr, buf, size,
                 O_IO_DROP);
        kfree(buf);
    }
    io_dispatch_lock_range(sbi->sb, (void *)dev_dst_addr, size, &irq_flags);
}

void io_dispatch_clear(struct hk_sb_info *sbi, u64 dev_addr, size_t size);
int io_dispatch_write_thru(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                           size_t size);
int io_dispatch_write_thru_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                  void *src, size_t size, int handle);
int io_dispatch_write_cached(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                             size_t size);
int io_dispatch_write_cached_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                    void *src, size_t size, int handle);
#endif