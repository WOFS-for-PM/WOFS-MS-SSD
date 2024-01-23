#include "killer.h"

static inline bool __is_rmw(struct hk_sb_info *sbi, int handle, u64 addr,
                            size_t size) {
    int bs = DEV_HANDLER_PTR(sbi, handle)->bs;
    // when `addr` is not aligned to `bs` or `addr+size` is not aligned to `bs`,
    // it is a read-modify-write
    return (addr & (bs - 1)) || (size) & (bs - 1);
}

static inline int try_rmw(struct hk_sb_info *sbi, u64 addr, char *content,
                          size_t size, int handle) {
    char *buf = kmalloc(size, GFP_KERNEL);
    u64 bias = addr & (sbi->fast_dev.tds[0].bs - 1);

    if (handle == -1)
        handle = hk_get_cpuid(sbi->sb);
    else
        assert(handle >= 0 && handle < sbi->cpus);

    if (__is_rmw(sbi, handle, addr, size)) {
        pr_warn("%s: addr %llx size %lx\n", __func__, addr, size);
        // read-modify-write
        io_read(DEV_HANDLER_PTR(sbi, handle), addr, buf, size, O_IO_DROP);
        if (content)
            memcpy(buf + bias, content, size);
        else
            memset(buf + bias, 0, size);
        io_write(DEV_HANDLER_PTR(sbi, handle), addr, buf, size, O_IO_DROP);
    } else {
        io_write(DEV_HANDLER_PTR(sbi, handle), addr, content, size, O_IO_DROP);
    }

    kfree(buf);

    return handle;
}

int io_dispatch_clear(struct hk_sb_info *sbi, u64 dev_addr, size_t size) {
    struct super_block *sb = sbi->sb;
    unsigned long irq_flags = 0;
    int handle = 0;
    io_dispatch_unlock_range(sb, (void *)dev_addr, size, &irq_flags);

    if (sbi->dax) {
        memset_nt((void *)dev_addr, 0, size);
    } else {
        handle = try_rmw(sbi, dev_addr, NULL, size, -1);
    }

    io_dispatch_lock_range(sb, (void *)dev_addr, size, &irq_flags);
    return handle;
}

int io_dispatch_write_thru_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                  void *src, size_t size, int handle) {
    struct super_block *sb = sbi->sb;
    unsigned long irq_flags;

    io_dispatch_unlock_range(sb, (void *)dev_addr, size, &irq_flags);

    if (sbi->dax) {
        memcpy_to_pmem_nocache((void *)dev_addr, src, size);
    } else {
        handle = try_rmw(sbi, dev_addr, src, size, handle);
    }

    io_dispatch_lock_range(sb, (void *)dev_addr, size, &irq_flags);

    return handle;
}

int io_dispatch_write_cached_handle(struct hk_sb_info *sbi, u64 dev_addr,
                                    void *src, size_t size, int handle) {
    if (sbi->dax) {
        memcpy((void *)dev_addr, src, size);
    } else {
        assert(handle >= 0 && handle < sbi->cpus);
        io_write(DEV_HANDLER_PTR(sbi, handle), dev_addr, src, size,
                 O_IO_CACHED);
    }
    return handle;
}

int io_dispatch_write_thru(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                           size_t size) {
    // for fence
    int handle = get_handle_by_addr(sbi, dev_addr);
    return io_dispatch_write_thru_handle(sbi, dev_addr, src, size, handle);
}

int io_dispatch_write_cached(struct hk_sb_info *sbi, u64 dev_addr, void *src,
                             size_t size) {
    // for flush + fence
    int handle = get_handle_by_addr(sbi, dev_addr);
    return io_dispatch_write_cached_handle(sbi, dev_addr, src, size, handle);
}