#ifndef _LINIX_H
#define _LINIX_H

#include "killer.h"

struct linslot;

#define IX_SLOT_SZ sizeof(struct linslot)

struct linslot {
    u64 blk_addr;
};

struct linix {
    u64 num_slots;
    struct linslot *slots;
};

static inline int linix_init(struct linix *ix, u64 num_slots) {
    ix->num_slots = num_slots;
    if (num_slots == 0) {
        ix->slots = NULL;
    } else {
        ix->slots = kvcalloc(ix->num_slots, sizeof(struct linslot), GFP_KERNEL);
    }
    return 0;
}

static inline int linix_destroy(struct linix *ix) {
    if (ix->slots) {
        kvfree(ix->slots);
        ix->slots = NULL;
    } else {
        hk_warn("double free in linix_destroy\n");
        BUG_ON(1);
    }
    return 0;
}

static inline void *__must_check kvrealloc(void *old_ptr, size_t old_size, size_t new_size,
                             gfp_t mode) {
    void *buf;

    buf = kvmalloc(new_size, mode);
    if (buf) {
        memcpy(buf, old_ptr, ((old_size < new_size) ? old_size : new_size));
        kvfree(old_ptr);
    }

    return buf;
}

/* This should be changed to kvmalloc */
static inline int linix_extend(struct linix *ix) {
    struct linslot *new_slots;
    new_slots = kvrealloc(ix->slots, ix->num_slots * IX_SLOT_SZ,
                          2 * ix->num_slots * IX_SLOT_SZ, GFP_KERNEL);

    if (new_slots == NULL) {
        return -1;
    }
    memset(new_slots + ix->num_slots, 0, ix->num_slots * IX_SLOT_SZ);

    ix->num_slots = 2 * ix->num_slots;
    ix->slots = new_slots;

    return 0;
}

static inline int linix_shrink(struct linix *ix) {
    struct linslot *new_slots;
    new_slots = kvrealloc(ix->slots, ix->num_slots * IX_SLOT_SZ,
                          ix->num_slots / 2 * IX_SLOT_SZ, GFP_KERNEL);

    if (new_slots == NULL) {
        return -1;
    }

    ix->num_slots = ix->num_slots / 2;
    ix->slots = new_slots;

    return 0;
}

/* TODO: Customizing measuring time  */
/* return the value of index */
static inline u64 linix_get(struct linix *ix, u64 index) {
    u64 blk_addr;
    INIT_TIMING(index_time);
    HK_START_TIMING(linix_get_t, index_time);
    if (index >= ix->num_slots) {
        HK_END_TIMING(linix_get_t, index_time);
        return 0;
    }
    blk_addr = ix->slots[index].blk_addr;
    HK_END_TIMING(linix_get_t, index_time);
    return blk_addr;
}

/* Inode Lock must be held before linix insert, and blk_addr */
static inline int linix_insert(struct linix *ix, u64 index, u64 blk_addr,
                               bool extend) {
    INIT_TIMING(index_time);
    HK_START_TIMING(linix_set_t, index_time);
    if (extend) {
        while (index >= ix->num_slots) {
            linix_extend(ix);
        }
    }

    if (index >= ix->num_slots) {
        HK_END_TIMING(linix_set_t, index_time);
        return -1;
    }

    ix->slots[index].blk_addr = blk_addr;
    HK_END_TIMING(linix_set_t, index_time);
    return 0;
}

/* last_index is the last valid index determined by user */
static inline int linix_delete(struct linix *ix, u64 index, u64 last_index,
                               bool shrink) {
    ix->slots[index].blk_addr = 0;

    if (shrink && ix->num_slots > HK_LINIX_SLOTS) {
        if (last_index + 1 <= ix->num_slots / 2) {
            linix_shrink(ix);
        }
    }

    return 0;
}

#endif