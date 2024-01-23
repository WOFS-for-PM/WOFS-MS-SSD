#include "killer.h"

// clang-format off
const char *Timingstring[TIMING_NUM] = {
    /* Init */
    "================ Initialization ================", 
    "init", 
    "mount",
    "new_init", 
    "recovery",

    /* Namei operations */
    "============= Directory operations =============", 
    "create", 
    "lookup",
    "link", 
    "unlink", 
    "symlink", 
    "mkdir", 
    "rmdir", 
    "mknod", 
    "rename", 
    "readdir",
    "setattr", 
    "setsize",

    /* I/O operations */
    "================ I/O operations ================", 
    "read", 
    "do_cow_write",
    "cow_write", 
    "get_block", 
    "write", 
    "handle_partial_block",

    /* Memory operations */
    "============== Memory operations ===============", 
    "memcpy_read_media",
    "memcpy_write_media", 
    "memcpy_write_back_to_media",

    /* Memory management */
    "============== Memory management ===============", 
    "alloc_blocks",
    "new_data_blocks", 
    "free_blocks", 
    "free_data_blocks", 
    "free_log_blocks",
    "reserve_pkg", 
    "reserve_pkg_in_layout", 
    "tl_alloc_meta", 
    "tl_alloc_blk",

    /* Transaction */
    "================= Transaction ==================", 
    "transaction_new_inode",
    "transaction_new_data", 
    "transaction_new_unlink", 
    "transaction_new_attr",
    "transaction_new_rename", 
    "transaction_new_link", 
    "transaction_new_symlink",
    "write_once_commit",

    /* Others */
    "================ Miscellaneous =================", 
    "fsync", 
    "write_pages",
    "fallocate", 
    "direct_IO", 
    "free_old_entry", 
    "delete_file_tree",
    "delete_dir_tree", 
    "new_vfs_inode", 
    "new_hk_inode", 
    "free_inode",
    "free_inode_log", 
    "evict_inode", 
    "test_perf", 
    "wprotect",
    "bitmap_find_free", 
    "process_reclaim_request", 
    "data_claim",

    /* Rebuild */
    "=================== Rebuild ====================", 
    "rebuild_dir",
    "rebuild_file", 
    "imm_set_bitmap", 
    "imm_clear_bitmap",

    /* Meta Operations */
    "=================== Meta ===================", 
    "valid_summary_header",
    "invalid_summary_header", 
    "request_valid_block", 
    "request_invalid_block",
    "prepare_request", 
    "commit_newattr",

    "=================== LinIX ===================", 
    "linix_set", 
    "linix_get"
};
// clang-format on

u64 Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];
#ifdef __KERNEL__
DEFINE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
DEFINE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
void hk_get_timing_stats(void) {
    int i;
    int cpu;

    for (i = 0; i < TIMING_NUM; i++) {
        Timingstats[i] = 0;
        Countstats[i] = 0;
        for_each_possible_cpu(cpu) {
            Timingstats[i] += per_cpu(Timingstats_percpu[i], cpu);
            Countstats[i] += per_cpu(Countstats_percpu[i], cpu);
        }
    }
}

static void hk_clear_timing_stats(void) {
    int i;
    int cpu;

    for (i = 0; i < TIMING_NUM; i++) {
        Countstats[i] = 0;
        Timingstats[i] = 0;
        for_each_possible_cpu(cpu) {
            per_cpu(Timingstats_percpu[i], cpu) = 0;
            per_cpu(Countstats_percpu[i], cpu) = 0;
        }
    }
}
#else
atomic_uint_least64_t Timingstats_percpu[TIMING_NUM];
atomic_uint_least64_t Countstats_percpu[TIMING_NUM];
void hk_get_timing_stats(void) {
    int i;

    for (i = 0; i < TIMING_NUM; i++) {
        Timingstats[i] =
            atomic_load_explicit(&Timingstats_percpu[i], memory_order_relaxed);
        Countstats[i] =
            atomic_load_explicit(&Countstats_percpu[i], memory_order_relaxed);
    }
}
static void hk_clear_timing_stats(void) {
}
#endif  // __KERNEL__

void hk_clear_stats(void) {
    hk_clear_timing_stats();
}

int hk_show_stats(void) {
    int i;

    hk_get_timing_stats();

    hk_info("=========== HUNTER kernel timing stats ===========\n");
    for (i = 0; i < TIMING_NUM; i++) {
        /* Title */
        if (Timingstring[i][0] == '=') {
            hk_info("\n%s\n\n", Timingstring[i]);
            continue;
        }

        if (measure_timing || Timingstats[i]) {
            hk_info("%s: count %llu, timing %llu, average %llu\n",
                    Timingstring[i], Countstats[i], Timingstats[i],
                    Countstats[i] ? Timingstats[i] / Countstats[i] : 0);
        } else {
            hk_info("%s: count %llu\n", Timingstring[i], Countstats[i]);
        }
    }

    hk_info("\n");
    return 0;
}