#include "killer.h"

enum hk_layout_type {
    LAYOUT_APPEND = 0,
    LAYOUT_GAP,
    /* for pack, i.e., write-once layout */
    LAYOUT_PACK
};

struct hk_layout_info {
    mutex_t layout_lock;

    u32 cpuid;
    u64 layout_start;
    u64 layout_end;
    u64 layout_blks;

    tl_allocator_t allocator;
};

struct hk_layout_prep {
    int cpuid;
    u64 target_addr;
    u64 blks_prepared;
    u64 blks_prep_to_use;
};
