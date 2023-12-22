#ifndef _HK_INODE_H
#define _HK_INODE_H

#include "killer.h"

/*
 * hk-specific inode state kept in DRAM
 */
struct hk_inode_info_header {
    struct hlist_node hnode;
    struct hk_inode_info *si;
    u32 ino;
    struct linix ix;                        /* Linear Index for blks in use */
    DECLARE_HASHTABLE(dirs, HK_HASH_BITS7); /* Hash table for dirs */
    u64 i_num_dentrys;                      /* Dentrys tail */
    int num_vmas;
    unsigned short i_mode; /* Dir or file? */
    unsigned int i_flags;
    unsigned long i_size;
    unsigned long i_blocks;
    u32 i_ctime;
    u32 i_mtime;
    u32 i_atime; /* Access time */
    u32 i_uid;   /* Owner Uid */
    u32 i_gid;   /* Group Id */
    u16 i_links_count;

    struct {
        // obj_ref_inode_t *latest_inode;
        // obj_ref_attr_t *latest_attr;
        u64 latest_inline_attr;
    } latest_fop;
};

#endif