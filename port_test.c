#include "killer.h"
#include "tlalloc.h"

#define PORT_TEST_BLOCK_SIZE 4096
#define PORT_TEST_MTA_SIZE 64

#undef pr_milestone

#define RED "\033[0;31m"
#define BLACK "\033[0m"
#define BOLD "\033[1m"

#define pr_milestone(fmt, ...)           \
    printf(RED BOLD "["                  \
                    "MILESTONE (KILLER)" \
                    "]: " fmt BLACK,     \
           ##__VA_ARGS__)

static int __test;
#define DEFINE_UNIT_TEST(name, FUNC)                                         \
    __maybe_unused static int name(void) {                                   \
        __test++;                                                            \
        pr_milestone("PORT UNIT TEST [%d]: %s\n", __test, __func__);         \
        FUNC;                                                                \
        pr_milestone("PORT UNIT TEST [%d]: %s Success\n", __test, __func__); \
        return 0;                                                            \
    }

DEFINE_UNIT_TEST(alloc_test, {
    tl_allocator_t *allocators;
    int cpus = num_online_cpus();
    int cpu = 0;
    int ret;
    unsigned long blk_start = 0;
    unsigned long total_blks = 4 * 1024 * 1024;
    unsigned long per_blks = total_blks / cpus;

    allocators = kmalloc(sizeof(tl_allocator_t) * cpus, GFP_KERNEL);
    for (cpu = 0; cpu < cpus; cpu++) {
        ret = tl_alloc_init(&allocators[cpu], cpu, blk_start, per_blks,
                            PORT_TEST_BLOCK_SIZE, PORT_TEST_MTA_SIZE);
        assert(ret == 0);
        blk_start += per_blks;
    }

    tlalloc_param_t param;

    // alloc block for each cpu
    for (cpu = 0; cpu < cpus; cpu++) {
        tl_build_alloc_param(&param, 1, TL_BLK);
        ret = tlalloc(&allocators[cpu], &param);
        assert(param._ret_allocated == 1);
        assert(param._ret_rng.low == cpu * per_blks);
    }

    // alloc mta (four slot) for each cpu
    for (cpu = 0; cpu < cpus; cpu++) {
        tl_build_alloc_param(&param, 4, TL_MTA | TL_MTA_PKG_ATTR);
        ret = tlalloc(&allocators[cpu], &param);
        unsigned long blk = param._ret_rng.low;
        unsigned long entrynr = param._ret_rng.high;
        assert(blk == cpu * per_blks + 1);
        assert(entrynr == 0);
    }

    // alloc mta (four slot) for each cpu, again
    for (cpu = 0; cpu < cpus; cpu++) {
        tl_build_alloc_param(&param, 4, TL_MTA | TL_MTA_PKG_ATTR);
        ret = tlalloc(&allocators[cpu], &param);
        unsigned long blk = param._ret_rng.low;
        unsigned long entrynr = param._ret_rng.high;
        assert(blk == cpu * per_blks + 1);
        assert(entrynr == 4);
    }

    for (cpu = 0; cpu < cpus; cpu++) {
        tl_destory(&allocators[cpu]);
    }
    kfree(allocators);
});

extern struct super_operations hk_sops;
extern struct super_block sb;

#ifndef DEBUG
DEFINE_UNIT_TEST(obj_test, {
#else
__maybe_unused static int obj_test(void) {
#endif
    int ret;

    // Init allocator
    tl_allocator_t allocator;
    ret = tl_alloc_init(&allocator, 0, 0, 1024 * 1024, PORT_TEST_BLOCK_SIZE,
                        PORT_TEST_MTA_SIZE);
    assert(!ret);

    // Init super
    struct hk_sb_info *sbi = HK_SB(&sb);
    struct inode *inode = hk_sops.alloc_inode(&sb);
    struct hk_inode_info *info = HK_I(inode);
    struct hk_inode_info_header *sih;

    // Create an Inode
    info->header = hk_alloc_hk_inode_info_header();
    sih = info->header;
    sih->ino = 0;
    hk_init_header(&sb, sih, S_IFREG | 0644);
    sih->si = info;

    // Alloc a block from address space
    struct hk_layout_prep prep;
    unsigned long blks = 1;
    unsigned long blk = 0;
    ret = hk_alloc_blocks(&sb, &blks, false, &prep);
    assert(!ret);
    blk = prep.target_addr >> KILLER_BLK_SHIFT;
    assert(blk != 0);

    // I/O: write data to the block and read it back
    char buf[4096];
    in_pkg_param_t in_param;
    out_pkg_param_t out_param;
    u64 data_addr = blk << KILLER_BLK_SHIFT;
    off_t offset = 0;
    size_t size = 4096;
    u64 num = 1;  // we can extend this write.
    u64 index = offset / 4096;

    memset(buf, 'a', size);
    io_write(CUR_DEV_HANDLER_PTR(&sb), data_addr, buf, size, O_IO_DROP);
    in_param.bin = false;
    // TODO: metadata block is pure log in non-dax mode, so that once
    //       the metadata block is full, we flush-fence and invalidate
    create_data_pkg(sbi, sih, data_addr, offset, size, num, &in_param,
                    &out_param);

    memset(buf, 0, size);

    obj_ref_data_t *ref = hk_inode_get_slot(sih, index);
    assert(ref);
    data_addr = 0;
    data_addr = get_ps_addr_by_data_ref(sbi, ref, (index << KILLER_BLK_SHIFT));
    assert(data_addr == (blk << KILLER_BLK_SHIFT));
    io_read(CUR_DEV_HANDLER_PTR(&sb), data_addr, buf, size, O_IO_DROP);
    for (int i = 0; i < size; i++) {
        assert(buf[i] == 'a');
    }

    // Destroy the Inode
    hk_free_hk_inode_info_header(sih);
    hk_sops.destroy_inode(inode);
#ifndef DEBUG
})
#else
}
#endif

int port_test(void) {
    int ret = 0;
    ret = alloc_test();
    assert(ret == 0);
    ret = obj_test();
    assert(ret == 0);
    return ret;
}