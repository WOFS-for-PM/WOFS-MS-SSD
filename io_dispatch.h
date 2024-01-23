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

#define IO_D_PROT_WRITE 0x0001
#define IO_D_PROT_READ 0x0002

#define IO_D_MAX_MMAP_SIZE 4096

#define IO_DISPATCH_MMAP(sbi, dev_addr, size, prot, target_addr)        \
    {                                                                   \
        if (sbi->dax) {                                                 \
            target_addr = (typeof(target_addr))dev_addr;                \
        } else {                                                        \
            int handle = get_handle_by_addr(sbi, (u64)dev_addr);        \
            assert(size <= sbi->fast_dev.tds[handle].bs);               \
            assert(sbi->fast_dev.tds[handle].bs <= IO_D_MAX_MMAP_SIZE); \
            char buf[IO_D_MAX_MMAP_SIZE];                               \
            target_addr = (typeof(target_addr))buf;                     \
            /* must read first if prot require                          \
             * IO_D_PROT_READ*/                                         \
            if ((prot & IO_D_PROT_READ)) {                              \
                io_read(DEV_HANDLER_PTR(sbi, handle), dev_addr, buf,    \
                        sbi->fast_dev.tds[handle].bs, O_IO_DROP);       \
            }                                                           \
        }

// FIXME: for the prot that requires IO_D_PROT_READ, there exists double-copy
// problem, a possible solution is add another io_read to directly manipulate
// io_u buffer, and sync turn the read buffer as write to accomplish this task.
// TODO: add io_rmw() to avoid double-copy
static inline void *io_dispatch_mmap(struct hk_sb_info *sbi, u64 dev_addr,
                                     u64 size, int prot) {
    void *target_addr = NULL;
    if (sbi->dax) {
        target_addr = (typeof(target_addr))dev_addr;
    } else {
        int handle = get_handle_by_addr(sbi, (u64)dev_addr);
        target_addr = kmalloc(size, GFP_KERNEL);
        if ((prot & IO_D_PROT_READ)) {
            io_read(DEV_HANDLER_PTR(sbi, handle), dev_addr, target_addr, size,
                    O_IO_DROP);
        }
    }
    return target_addr;
}

// manipulate `target_addr` here like normal memory

// commit the modifed region
static inline int io_dispatch_msync(struct hk_sb_info *sbi, u64 dev_addr,
                                    u64 size, u64 target_addr) {
    int region_handle = 0;
    if (sbi->dax) {
        hk_flush_buffer((void *)dev_addr, size, true);
    } else {
        region_handle = get_handle_by_addr(sbi, (u64)dev_addr);
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

static inline int io_dispatch_msync_safe(struct hk_sb_info *sbi, u64 dev_addr,
                                         u64 size, u64 target_addr) {
    int region_handle = 0;
    unsigned long irq_flags = 0;
    io_dispatch_unlock_range(sbi->sb, (void *)dev_addr, size, &irq_flags);
    region_handle = io_dispatch_msync(sbi, dev_addr, size, target_addr);
    io_dispatch_lock_range(sbi->sb, (void *)dev_addr, size, &irq_flags);
    return region_handle;
}

#define IO_DISPATCH_MUNMAP(sbi) }

static inline void io_dispatch_munmap(struct hk_sb_info *sbi,
                                      void *target_addr) {
    if (sbi->dax) {
        // Do nothing
    } else {
        kfree(target_addr);
    }
}

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

static inline void io_dispatch_drain(struct hk_sb_info *sbi, int handle) {
    if (sbi->dax) {
        // Do nothing
    } else {
        io_drain(DEV_HANDLER_PTR(sbi, handle));
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
        int handle = get_handle_by_addr(sbi, (u64)dev_src_addr);
        io_read(CUR_DEV_HANDLER_PTR(sbi->sb), dev_src_addr, buf, size,
                O_IO_DROP);

        io_write(DEV_HANDLER_PTR(sbi, handle), dev_dst_addr, buf, size,
                 O_IO_DROP);
        kfree(buf);
    }
    io_dispatch_lock_range(sbi->sb, (void *)dev_dst_addr, size, &irq_flags);
}

int io_dispatch_clear(struct hk_sb_info *sbi, u64 dev_addr, size_t size);
int io_dispatch_write_thru(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                           size_t size);
int io_dispatch_write_thru_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                  void *src, size_t size, int handle);
int io_dispatch_write_cached(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                             size_t size);
int io_dispatch_write_cached_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                    void *src, size_t size, int handle);
#endif