#include "killer.h"
#include "tlalloc.h"
#include "usyscall.h"

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
#define DEFINE_UNIT_TEST_START(name)            \
    __maybe_unused static int name(void *arg) { \
        __test++;                               \
        pr_milestone("PORT UNIT TEST [%d]: %s\n", __test, __func__);

#define DEFINE_UNIT_TEST_END(name)                                       \
    pr_milestone("PORT UNIT TEST [%d]: %s Success\n", __test, __func__); \
    return 0;                                                            \
    }

extern struct super_operations hk_sops;
extern struct super_block sb;

DEFINE_UNIT_TEST_START(alloc_test) {
    tl_allocator_t *allocators;
    struct hk_sb_info *sbi = HK_SB(&sb);
    int cpus = num_online_cpus();
    int cpu = 0, ret, i;
    unsigned long blk_start = 0;
    unsigned long total_blks = 4 * 1024 * 1024;
    unsigned long per_blks = total_blks / cpus;
    u8 mode = *((u8 *)arg);

    allocators = kmalloc(sizeof(tl_allocator_t) * cpus, GFP_KERNEL);
    for (cpu = 0; cpu < cpus; cpu++) {
        allocators[cpu].private = sbi;
        ret = tl_alloc_init(&allocators[cpu], cpu, blk_start, per_blks,
                            PORT_TEST_BLOCK_SIZE, PORT_TEST_MTA_SIZE, mode,
                            &hk_gc_ops);
        assert(ret == 0);
        blk_start += per_blks;
    }

    tlalloc_param_t alloc_param;
    tlfree_param_t free_param;

    // alloc block for each cpu
    for (cpu = 0; cpu < cpus; cpu++) {
        tl_build_alloc_param(&alloc_param, 1, TL_BLK);
        ret = tlalloc(&allocators[cpu], &alloc_param);
        assert(alloc_param._ret_allocated == 1);
        assert(alloc_param._ret_rng.low == cpu * per_blks);
    }

    for (cpu = 0; cpu < cpus; cpu++) {
        // alloc mta (four slot) for each cpu
        for (i = 0; i < 64; i += 4) {
            tl_build_alloc_param(&alloc_param, 4, TL_MTA | TL_MTA_PKG_ATTR);
            ret = tlalloc(&allocators[cpu], &alloc_param);
            unsigned long blk = alloc_param._ret_rng.low;
            unsigned long entrynr = alloc_param._ret_rng.high;
            assert(blk == cpu * per_blks + 1);
            assert(entrynr == i);
        }
        // wipe out the first half of mta
        for (i = 0; i < 32; i += 4) {
            unsigned long blk = cpu * per_blks + 1;
            unsigned long entrynr = i;
            tl_build_free_param(&free_param, blk, (entrynr << 32 | 4),
                                TL_MTA | TL_MTA_PKG_ATTR);
            tlfree(&allocators[cpu], &free_param);
        }
        // alloc mta (four slot) for each cpu
        for (i = 0; i < 32; i += 4) {
            tl_build_alloc_param(&alloc_param, 4, TL_MTA | TL_MTA_PKG_ATTR);
            ret = tlalloc(&allocators[cpu], &alloc_param);
            unsigned long blk = alloc_param._ret_rng.low;
            unsigned long entrynr = alloc_param._ret_rng.high;
            if (mode == TL_ALLOC_OPU) {
                assert(blk == cpu * per_blks + 2);
                assert(entrynr == i);
            } else {
                assert(blk == cpu * per_blks + 1);
                assert(entrynr == i);
            }
        }
    }

    for (cpu = 0; cpu < cpus; cpu++) {
        tl_destory(&allocators[cpu]);
    }
    kfree(allocators);
}
DEFINE_UNIT_TEST_END(alloc_test)

DEFINE_UNIT_TEST_START(inode_mgr_test) {
    hk_inode_mgr_t *mgr = kmalloc(sizeof(hk_inode_mgr_t), GFP_KERNEL);
    hk_inode_mgr_t *orig_mgr = NULL;
    struct hk_sb_info *sbi = HK_SB(&sb);
    int ret;
    u32 ino;

    // for test
    orig_mgr = sbi->inode_mgr;
    sbi->inode_mgr = mgr;
    ret = hk_inode_mgr_init(sbi, mgr);
    assert(!ret);

    ret = hk_inode_mgr_alloc(mgr, &ino);
    assert(!ret);
    assert(ino != HK_ROOT_INO);
    assert(ino == HK_RESV_NUM + 1);

    // alloc all inodes
    for (int i = 1; i < HK_NUM_INO - (HK_RESV_NUM + 1); i++) {
        ret = hk_inode_mgr_alloc(mgr, &ino);
        assert(!ret);
        assert(ino != HK_ROOT_INO);
        assert(ino == i + (HK_RESV_NUM + 1));
    }

    // free all inodes
    for (int i = 0; i < HK_NUM_INO - (HK_RESV_NUM + 1); i++) {
        ret = hk_inode_mgr_free(mgr, i + (HK_RESV_NUM + 1));
        assert(!ret);
    }

    // Alloc again
    ret = hk_inode_mgr_alloc(mgr, &ino);
    assert(!ret);
    assert(ino != HK_ROOT_INO);
    assert(ino == HK_RESV_NUM + 1);

    hk_inode_mgr_destroy(mgr);
    sbi->inode_mgr = orig_mgr;
}
DEFINE_UNIT_TEST_END(inode_mgr_test)

// Before GC
// | c-cont (1) | dat (1) | d-cont (1) | dat (2) | ... | dat (64) |
//
// After GC
// | c-cont (1) | dat (1) | empty | dat (2) | ... | dat (64) | d-cont (1) |
DEFINE_UNIT_TEST_START(obj_test) {
    int ret, iter, cpu;
    in_pkg_param_t in_param;
    out_pkg_param_t out_param;

    // Init super
    struct hk_sb_info *sbi = HK_SB(&sb);
    struct inode *inode = hk_sops.alloc_inode(&sb);
    struct hk_inode_info *info = HK_I(inode);
    struct hk_inode_info_header *sih;

    // Create an Inode
    in_create_pkg_param_t in_create_param;
    out_create_pkg_param_t out_create_param;
    info->header = hk_alloc_hk_inode_info_header();
    sih = info->header;
    sih->ino = 0;
    hk_init_header(&sb, sih, S_IFREG | 0644);
    sih->si = info;

    in_create_param.create_type = CREATE_FOR_NORMAL;
    in_create_param.rdev = 0;
    in_param.bin = false;
    in_param.private = &in_create_param;
    in_param.cur_pkg_addr = 0;
    out_param.private = &out_create_param;
    create_new_inode_pkg(sbi, S_IFREG, "mock", sih, NULL, &in_param,
                         &out_param);
    io_wbinvd(CUR_DEV_HANDLER_PTR(&sb), out_param.addr, MTA_PKG_DATA_SIZE);
    io_fence(CUR_DEV_HANDLER_PTR(&sb));

    // Alloc a block from address space
    struct hk_layout_prep prep;
    unsigned long blks = 1;
    unsigned long blk = 0;

    // I/O: write data to the block and read it back
    char buf[4096];
    size_t written_size = 4096;
    // we test gc functionality (when a meta block is full)
    // it will be inserted to the gc list.
    int loop = 64;
    u64 num = 1;  // we can extend this write.
    off_t offset = 0;

    for (iter = 0; iter < loop; iter++) {
        // alloc a block
        blks = 1;
        ret = hk_alloc_blocks(&sb, &blks, false, &prep);
        assert(!ret);
        blk = prep.target_addr >> KILLER_BLK_SHIFT;
        // pr_info("alloc blk %lu for %d\n", blk, iter);
        assert(blk != 0);
        u64 data_addr = prep.target_addr;

        // write data to the block
        memset(buf, (char)('a' + iter), written_size);
        io_write(CUR_DEV_HANDLER_PTR(&sb), data_addr, buf, written_size,
                 O_IO_DROP);

        // create package
        in_param.bin = false;
        create_data_pkg(sbi, sih, data_addr, offset, written_size, num,
                        &in_param, &out_param);

        memset(buf, 0, written_size);

        // read data back
        obj_ref_data_t *ref = hk_inode_get_slot(sih, offset);
        assert(ref);
        data_addr = get_ps_addr_by_data_ref(sbi, ref, offset);
        assert(data_addr == (blk << KILLER_BLK_SHIFT));
        io_read(CUR_DEV_HANDLER_PTR(&sb), data_addr, buf, written_size,
                O_IO_DROP);
        for (int i = 0; i < written_size; i++) {
            assert(buf[i] == (char)('a' + iter));
        }

        offset += written_size;

        // flush the metadata block
        // NOTE: this is redundant
        try_evict_meta_block(sbi, out_param.addr);
    }

    // Start GC
    unsigned long gced = 0;
    for (cpu = 0; cpu < sbi->cpus; cpu++) {
        gced += tlgc(&sbi->layouts[cpu].allocator, 1);
    }
    assert(gced == 1);

    offset = 0;
    // Re-read the data
    for (iter = 0; iter < loop; iter++) {
        memset(buf, 0, written_size);
        obj_ref_data_t *ref = hk_inode_get_slot(sih, offset);
        assert(ref);
        u64 data_addr = get_ps_addr_by_data_ref(sbi, ref, offset);

        io_read(CUR_DEV_HANDLER_PTR(&sb), data_addr, buf, written_size,
                O_IO_DROP);
        for (int i = 0; i < written_size; i++) {
            assert(buf[i] == (char)('a' + iter));
        }

        offset += written_size;
    }

    // `put_super` free the inode
    // hk_free_hk_inode_info_header(sih);
    // Destroy the Inode
    hk_sops.destroy_inode(inode);
}
DEFINE_UNIT_TEST_END(obj_test)

struct inode_operations vfs_test_dir_iops;
struct file_operations vfs_test_file_ops;
// temp determine whether the file "test" is created
static int created = 0;

static struct dentry *vfs_test_lookup(struct inode *dir, struct dentry *dentry,
                                      unsigned int flags) {
    struct inode *inode = NULL;
    struct super_block *sb = dir->i_sb;

    if (!strcmp((const char *)dentry->d_name.name, "test")) {
        if (created)
            inode = iget_locked(sb, 1);
    }

    return d_splice_alias(inode, dentry);
}

int vfs_test_create(struct inode *dir, struct dentry *dentry, umode_t mode,
                    bool excl) {
    struct inode *inode = NULL;
    struct super_block *sb = dir->i_sb;

    inode = new_inode(sb);
    if (!inode) {
        return -ENOMEM;
    }

    inode->i_ino = 1;
    inode->i_op = NULL;
    inode->i_fop = &vfs_test_file_ops;

    created = 1;

    d_instantiate(dentry, inode);
    return 0;
}

struct inode_operations vfs_test_dir_iops = {
    .lookup = vfs_test_lookup,
    .create = vfs_test_create,
};

struct file_operations vfs_test_file_ops = {
    .llseek = generic_file_llseek,
};

DEFINE_UNIT_TEST_START(vfs_test) {
    struct inode *inode = alloc_inode(&sb);
    struct dentry *orig_root;
    inode->i_op = &vfs_test_dir_iops;
    inode->i_mode = S_IFDIR | 0755;

    orig_root = sb.s_root;
    sb.s_root = d_make_root(inode);

    int fd = usys_open("/tmp/test", O_RDWR, 0644);
    assert(fd < 0);

    fd = usys_open("/test", O_RDWR, 0644);
    assert(fd == -ENOENT);

    fd = usys_open("/test", O_CREAT | O_RDWR, 0644);
    assert(fd >= 0);

    usys_close(fd);

    iput(inode);
    sb.s_root = orig_root;
}
DEFINE_UNIT_TEST_END(vfs_test)

DEFINE_UNIT_TEST_START(io_dispatch_test) {
    struct hk_sb_info *sbi = HK_SB(&sb);
    char *buf = "God, I am a test string";
    char read_buf[PAGE_SIZE];
    int handle, region_handle;

    handle = io_dispatch_write_thru(sbi, 0, buf, strlen(buf));
    io_dispatch_fence(sbi, handle);
    io_dispatch_read(sbi, 0, read_buf, strlen(buf));
    assert(!memcmp(buf, read_buf, strlen(buf)));

    char *target_addr =
        io_dispatch_mmap(sbi, 0, strlen(buf), IO_D_PROT_WRITE | IO_D_PROT_READ);
    target_addr[0] = 'g';
    target_addr[5] = 'i';
    region_handle =
        io_dispatch_msync_safe(sbi, 0, strlen(buf), (u64)target_addr);
    io_dispatch_munmap(sbi, target_addr);

    io_dispatch_flush(sbi, region_handle, 0, strlen(buf));
    io_dispatch_fence(sbi, region_handle);

    io_dispatch_read(sbi, 0, read_buf, strlen(buf));
    assert(!memcmp(read_buf, "god, i am a test string", strlen(buf)));
}
DEFINE_UNIT_TEST_END(io_dispatch_test)

int port_test(void) {
    int ret = 0;
    u8 mode;

    // alloc test
    mode = TL_ALLOC_OPU;
    ret = alloc_test(&mode);
    assert(!ret);
    mode = TL_ALLOC_IPU;
    ret = alloc_test(&mode);
    assert(!ret);

    // inode mgr test
    ret = inode_mgr_test(NULL);
    assert(!ret);

    // obj test for NVMe SSD
    // we must GC
    ret = obj_test(NULL);
    assert(!ret);

    // vfs test
    ret = vfs_test(NULL);
    assert(!ret);

    // io dispatch test
    ret = io_dispatch_test(NULL);
    assert(!ret);

    return ret;
}