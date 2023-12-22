/*
 * HUNTER File System statistics
 *
 * Copyright 2022-2023 Regents of the University of Harbin Institute of
 * Technology, Shenzhen Computer science and technology, Yanqi Pan
 * <deadpoolmine@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _HK_STATS_H
#define _HK_STATS_H

#include "killer.h"

/* ======================= Timing ========================= */
enum timing_category {
    /* Init */
    init_title_t,
    init_t,
    mount_t,
    new_init_t,
    recovery_t,

    /* Namei operations */
    namei_title_t,
    create_t,
    lookup_t,
    link_t,
    unlink_t,
    symlink_t,
    mkdir_t,
    rmdir_t,
    mknod_t,
    rename_t,
    readdir_t,
    setattr_t,
    setsize_t,

    /* I/O operations */
    io_title_t,
    read_t,
    do_cow_write_t,
    cow_write_t,
    get_block_t,
    write_t,
    partial_block_t,

    /* Memory operations */
    memory_title_t,
    memcpy_r_media_t, /* Memory copy read NVMM time */
    memcpy_w_media_t, /* Memory copy write NVMM time */
    memcpy_w_wb_t,

    /* Memory management */
    mm_title_t,
    new_blocks_t,
    new_data_blocks_t,
    free_blocks_t,
    free_data_t,
    free_log_t,
    reserve_pkg_t,
    reserve_pkg_in_layout_t,
    tl_alloc_meta_t,
    tl_alloc_blk_t,

    /* Transaction */
    trans_title_t,
    new_inode_trans_t,
    new_data_trans_t,
    new_unlink_trans_t,
    new_attr_trans_t,
    new_rename_trans_t,
    new_link_trans_t,
    new_symlink_trans_t,
    wr_once_t,

    /* Others */
    others_title_t,
    fsync_t,
    write_pages_t,
    fallocate_t,
    direct_IO_t,
    free_old_t,
    delete_file_tree_t,
    delete_dir_tree_t,
    new_vfs_inode_t,
    new_HK_inode_t,
    free_inode_t,
    free_inode_log_t,
    evict_inode_t,
    perf_t,
    wprotect_t,
    bm_search_t,
    process_claim_req_t,
    data_claim_t,

    /* Rebuild */
    rebuild_title_t,
    rebuild_dir_t,
    rebuild_blks_t,
    imm_set_bm_t,
    imm_clear_bm_t,

    /* Meta Operations */
    meta_title_t,
    sm_valid_t,
    sm_invalid_t,
    request_valid_t,
    request_invalid_t,
    prepare_request_t,
    commit_newattr_t,

    /* Linix */
    linix_title_t,
    linix_set_t,
    linix_get_t,

    /* Sentinel */
    TIMING_NUM,
};

extern const char *Timingstring[TIMING_NUM];
extern u64 Timingstats[TIMING_NUM];
extern u64 Countstats[TIMING_NUM];

#ifdef __KERNEL___
DECLARE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
DECLARE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);

#define HK_END_TIMING(name, start)                                    \
    {                                                                 \
        if (measure_timing) {                                         \
            INIT_TIMING(end);                                         \
            getrawmonotonic(&end);                                    \
            __this_cpu_add(Timingstats_percpu[name],                  \
                           (end.tv_sec - start.tv_sec) * 1000000000 + \
                               (end.tv_nsec - start.tv_nsec));        \
            __this_cpu_add(Countstats_percpu[name], 1);               \
        }                                                             \
    }
#else
extern atomic_uint_least64_t Timingstats_percpu[TIMING_NUM];
extern atomic_uint_least64_t Countstats_percpu[TIMING_NUM];

#define HK_END_TIMING(name, start)                                      \
    {                                                                   \
        if (measure_timing) {                                           \
            INIT_TIMING(end);                                           \
            getrawmonotonic(&end);                                      \
            atomic_fetch_add(&Timingstats_percpu[name],                 \
                             (end.tv_sec - start.tv_sec) * 1000000000 + \
                                 (end.tv_nsec - start.tv_nsec));        \
            atomic_fetch_add(&Countstats_percpu[name], 1);              \
        }                                                               \
    }
#endif

typedef struct timespec timing_t;

#define INIT_TIMING(X) timing_t X = {0}

#define HK_START_TIMING(name, start) \
    {                                \
        if (measure_timing)          \
            getrawmonotonic(&start); \
    }
#endif /* _HK_STATS_H */
