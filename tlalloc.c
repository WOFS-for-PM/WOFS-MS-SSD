/**
 * Copyright (C) 2022 Deadpool
 *
 * Two Layer PM Allocator: allocate blocks and meta blocks/entries
 *
 * This file is part of hunter-userspace.
 *
 * hunter-userspace is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * hunter-userspace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with hunter-userspace.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "killer.h"

#define UINT8_SHIFT 3
#define UINT8_MASK 0x07

#define UINT32_BITS 32
#define UINT64_BITS 64

void tl_dump_data_mgr(data_mgr_t *data_mgr);

/* max supply for consecutive 8 bits */
static const u64 bm64_consecutive_masks[8][64] = {
    /* 1 */
    {0x0000000000000001, 0x0000000000000002, 0x0000000000000004,
     0x0000000000000008, 0x0000000000000010, 0x0000000000000020,
     0x0000000000000040, 0x0000000000000080, 0x0000000000000100,
     0x0000000000000200, 0x0000000000000400, 0x0000000000000800,
     0x0000000000001000, 0x0000000000002000, 0x0000000000004000,
     0x0000000000008000, 0x0000000000010000, 0x0000000000020000,
     0x0000000000040000, 0x0000000000080000, 0x0000000000100000,
     0x0000000000200000, 0x0000000000400000, 0x0000000000800000,
     0x0000000001000000, 0x0000000002000000, 0x0000000004000000,
     0x0000000008000000, 0x0000000010000000, 0x0000000020000000,
     0x0000000040000000, 0x0000000080000000, 0x0000000100000000,
     0x0000000200000000, 0x0000000400000000, 0x0000000800000000,
     0x0000001000000000, 0x0000002000000000, 0x0000004000000000,
     0x0000008000000000, 0x0000010000000000, 0x0000020000000000,
     0x0000040000000000, 0x0000080000000000, 0x0000100000000000,
     0x0000200000000000, 0x0000400000000000, 0x0000800000000000,
     0x0001000000000000, 0x0002000000000000, 0x0004000000000000,
     0x0008000000000000, 0x0010000000000000, 0x0020000000000000,
     0x0040000000000000, 0x0080000000000000, 0x0100000000000000,
     0x0200000000000000, 0x0400000000000000, 0x0800000000000000,
     0x1000000000000000, 0x2000000000000000, 0x4000000000000000,
     0x8000000000000000},
    /* 2 */
    {0x0000000000000003, 0x0000000000000006, 0x000000000000000c,
     0x0000000000000018, 0x0000000000000030, 0x0000000000000060,
     0x00000000000000c0, 0x0000000000000180, 0x0000000000000300,
     0x0000000000000600, 0x0000000000000c00, 0x0000000000001800,
     0x0000000000003000, 0x0000000000006000, 0x000000000000c000,
     0x0000000000018000, 0x0000000000030000, 0x0000000000060000,
     0x00000000000c0000, 0x0000000000180000, 0x0000000000300000,
     0x0000000000600000, 0x0000000000c00000, 0x0000000001800000,
     0x0000000003000000, 0x0000000006000000, 0x000000000c000000,
     0x0000000018000000, 0x0000000030000000, 0x0000000060000000,
     0x00000000c0000000, 0x0000000180000000, 0x0000000300000000,
     0x0000000600000000, 0x0000000c00000000, 0x0000001800000000,
     0x0000003000000000, 0x0000006000000000, 0x000000c000000000,
     0x0000018000000000, 0x0000030000000000, 0x0000060000000000,
     0x00000c0000000000, 0x0000180000000000, 0x0000300000000000,
     0x0000600000000000, 0x0000c00000000000, 0x0001800000000000,
     0x0003000000000000, 0x0006000000000000, 0x000c000000000000,
     0x0018000000000000, 0x0030000000000000, 0x0060000000000000,
     0x00c0000000000000, 0x0180000000000000, 0x0300000000000000,
     0x0600000000000000, 0x0c00000000000000, 0x1800000000000000,
     0x3000000000000000, 0x6000000000000000, 0xc000000000000000,
     0xFFFFFFFFFFFFFFFF},
    /* 3 */
    {0x0000000000000007, 0x000000000000000e, 0x000000000000001c,
     0x0000000000000038, 0x0000000000000070, 0x00000000000000e0,
     0x00000000000001c0, 0x0000000000000380, 0x0000000000000700,
     0x0000000000000e00, 0x0000000000001c00, 0x0000000000003800,
     0x0000000000007000, 0x000000000000e000, 0x000000000001c000,
     0x0000000000038000, 0x0000000000070000, 0x00000000000e0000,
     0x00000000001c0000, 0x0000000000380000, 0x0000000000700000,
     0x0000000000e00000, 0x0000000001c00000, 0x0000000003800000,
     0x0000000007000000, 0x000000000e000000, 0x000000001c000000,
     0x0000000038000000, 0x0000000070000000, 0x00000000e0000000,
     0x00000001c0000000, 0x0000000380000000, 0x0000000700000000,
     0x0000000e00000000, 0x0000001c00000000, 0x0000003800000000,
     0x0000007000000000, 0x000000e000000000, 0x000001c000000000,
     0x0000038000000000, 0x0000070000000000, 0x00000e0000000000,
     0x00001c0000000000, 0x0000380000000000, 0x0000700000000000,
     0x0000e00000000000, 0x0001c00000000000, 0x0003800000000000,
     0x0007000000000000, 0x000e000000000000, 0x001c000000000000,
     0x0038000000000000, 0x0070000000000000, 0x00e0000000000000,
     0x01c0000000000000, 0x0380000000000000, 0x0700000000000000,
     0x0e00000000000000, 0x1c00000000000000, 0x3800000000000000,
     0x7000000000000000, 0xe000000000000000, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF},
    /* 4 */
    {0x000000000000000f, 0x000000000000001e, 0x000000000000003c,
     0x0000000000000078, 0x00000000000000f0, 0x00000000000001e0,
     0x00000000000003c0, 0x0000000000000780, 0x0000000000000f00,
     0x0000000000001e00, 0x0000000000003c00, 0x0000000000007800,
     0x000000000000f000, 0x000000000001e000, 0x000000000003c000,
     0x0000000000078000, 0x00000000000f0000, 0x00000000001e0000,
     0x00000000003c0000, 0x0000000000780000, 0x0000000000f00000,
     0x0000000001e00000, 0x0000000003c00000, 0x0000000007800000,
     0x000000000f000000, 0x000000001e000000, 0x000000003c000000,
     0x0000000078000000, 0x00000000f0000000, 0x00000001e0000000,
     0x00000003c0000000, 0x0000000780000000, 0x0000000f00000000,
     0x0000001e00000000, 0x0000003c00000000, 0x0000007800000000,
     0x000000f000000000, 0x000001e000000000, 0x000003c000000000,
     0x0000078000000000, 0x00000f0000000000, 0x00001e0000000000,
     0x00003c0000000000, 0x0000780000000000, 0x0000f00000000000,
     0x0001e00000000000, 0x0003c00000000000, 0x0007800000000000,
     0x000f000000000000, 0x001e000000000000, 0x003c000000000000,
     0x0078000000000000, 0x00f0000000000000, 0x01e0000000000000,
     0x03c0000000000000, 0x0780000000000000, 0x0f00000000000000,
     0x1e00000000000000, 0x3c00000000000000, 0x7800000000000000,
     0xf000000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF},
    /* 5 */
    {0x000000000000001f, 0x000000000000003e, 0x000000000000007c,
     0x00000000000000f8, 0x00000000000001f0, 0x00000000000003e0,
     0x00000000000007c0, 0x0000000000000f80, 0x0000000000001f00,
     0x0000000000003e00, 0x0000000000007c00, 0x000000000000f800,
     0x000000000001f000, 0x000000000003e000, 0x000000000007c000,
     0x00000000000f8000, 0x00000000001f0000, 0x00000000003e0000,
     0x00000000007c0000, 0x0000000000f80000, 0x0000000001f00000,
     0x0000000003e00000, 0x0000000007c00000, 0x000000000f800000,
     0x000000001f000000, 0x000000003e000000, 0x000000007c000000,
     0x00000000f8000000, 0x00000001f0000000, 0x00000003e0000000,
     0x00000007c0000000, 0x0000000f80000000, 0x0000001f00000000,
     0x0000003e00000000, 0x0000007c00000000, 0x000000f800000000,
     0x000001f000000000, 0x000003e000000000, 0x000007c000000000,
     0x00000f8000000000, 0x00001f0000000000, 0x00003e0000000000,
     0x00007c0000000000, 0x0000f80000000000, 0x0001f00000000000,
     0x0003e00000000000, 0x0007c00000000000, 0x000f800000000000,
     0x001f000000000000, 0x003e000000000000, 0x007c000000000000,
     0x00f8000000000000, 0x01f0000000000000, 0x03e0000000000000,
     0x07c0000000000000, 0x0f80000000000000, 0x1f00000000000000,
     0x3e00000000000000, 0x7c00000000000000, 0xf800000000000000,
     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF},
    /* 6 */
    {0x000000000000003f, 0x000000000000007e, 0x00000000000000fc,
     0x00000000000001f8, 0x00000000000003f0, 0x00000000000007e0,
     0x0000000000000fc0, 0x0000000000001f80, 0x0000000000003f00,
     0x0000000000007e00, 0x000000000000fc00, 0x000000000001f800,
     0x000000000003f000, 0x000000000007e000, 0x00000000000fc000,
     0x00000000001f8000, 0x00000000003f0000, 0x00000000007e0000,
     0x0000000000fc0000, 0x0000000001f80000, 0x0000000003f00000,
     0x0000000007e00000, 0x000000000fc00000, 0x000000001f800000,
     0x000000003f000000, 0x000000007e000000, 0x00000000fc000000,
     0x00000001f8000000, 0x00000003f0000000, 0x00000007e0000000,
     0x0000000fc0000000, 0x0000001f80000000, 0x0000003f00000000,
     0x0000007e00000000, 0x000000fc00000000, 0x000001f800000000,
     0x000003f000000000, 0x000007e000000000, 0x00000fc000000000,
     0x00001f8000000000, 0x00003f0000000000, 0x00007e0000000000,
     0x0000fc0000000000, 0x0001f80000000000, 0x0003f00000000000,
     0x0007e00000000000, 0x000fc00000000000, 0x001f800000000000,
     0x003f000000000000, 0x007e000000000000, 0x00fc000000000000,
     0x01f8000000000000, 0x03f0000000000000, 0x07e0000000000000,
     0x0fc0000000000000, 0x1f80000000000000, 0x3f00000000000000,
     0x7e00000000000000, 0xfc00000000000000, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF},
    /* 7 */
    {0x000000000000007f, 0x00000000000000fe, 0x00000000000001fc,
     0x00000000000003f8, 0x00000000000007f0, 0x0000000000000fe0,
     0x0000000000001fc0, 0x0000000000003f80, 0x0000000000007f00,
     0x000000000000fe00, 0x000000000001fc00, 0x000000000003f800,
     0x000000000007f000, 0x00000000000fe000, 0x00000000001fc000,
     0x00000000003f8000, 0x00000000007f0000, 0x0000000000fe0000,
     0x0000000001fc0000, 0x0000000003f80000, 0x0000000007f00000,
     0x000000000fe00000, 0x000000001fc00000, 0x000000003f800000,
     0x000000007f000000, 0x00000000fe000000, 0x00000001fc000000,
     0x00000003f8000000, 0x00000007f0000000, 0x0000000fe0000000,
     0x0000001fc0000000, 0x0000003f80000000, 0x0000007f00000000,
     0x000000fe00000000, 0x000001fc00000000, 0x000003f800000000,
     0x000007f000000000, 0x00000fe000000000, 0x00001fc000000000,
     0x00003f8000000000, 0x00007f0000000000, 0x0000fe0000000000,
     0x0001fc0000000000, 0x0003f80000000000, 0x0007f00000000000,
     0x000fe00000000000, 0x001fc00000000000, 0x003f800000000000,
     0x007f000000000000, 0x00fe000000000000, 0x01fc000000000000,
     0x03f8000000000000, 0x07f0000000000000, 0x0fe0000000000000,
     0x1fc0000000000000, 0x3f80000000000000, 0x7f00000000000000,
     0xfe00000000000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF},
    /* 8 */
    {0x00000000000000ff, 0x00000000000001fe, 0x00000000000003fc,
     0x00000000000007f8, 0x0000000000000ff0, 0x0000000000001fe0,
     0x0000000000003fc0, 0x0000000000007f80, 0x000000000000ff00,
     0x000000000001fe00, 0x000000000003fc00, 0x000000000007f800,
     0x00000000000ff000, 0x00000000001fe000, 0x00000000003fc000,
     0x00000000007f8000, 0x0000000000ff0000, 0x0000000001fe0000,
     0x0000000003fc0000, 0x0000000007f80000, 0x000000000ff00000,
     0x000000001fe00000, 0x000000003fc00000, 0x000000007f800000,
     0x00000000ff000000, 0x00000001fe000000, 0x00000003fc000000,
     0x00000007f8000000, 0x0000000ff0000000, 0x0000001fe0000000,
     0x0000003fc0000000, 0x0000007f80000000, 0x000000ff00000000,
     0x000001fe00000000, 0x000003fc00000000, 0x000007f800000000,
     0x00000ff000000000, 0x00001fe000000000, 0x00003fc000000000,
     0x00007f8000000000, 0x0000ff0000000000, 0x0001fe0000000000,
     0x0003fc0000000000, 0x0007f80000000000, 0x000ff00000000000,
     0x001fe00000000000, 0x003fc00000000000, 0x007f800000000000,
     0x00ff000000000000, 0x01fe000000000000, 0x03fc000000000000,
     0x07f8000000000000, 0x0ff0000000000000, 0x1fe0000000000000,
     0x3fc0000000000000, 0x7f80000000000000, 0xff00000000000000,
     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
     0xFFFFFFFFFFFFFFFF}};

u32 bm64_fast_search_consecutive_bits(u64 bm, u32 bits) {
    const u64 *mask = bm64_consecutive_masks[bits - 1];
    u32 i = 0;
    u64 res1, res2, res3, res4;

    bm = ~bm;

    for (i = 0; i < UINT64_BITS; i += 4) {
        res1 = (bm & mask[i]) ^ mask[i];
        res2 = (bm & mask[i + 1]) ^ mask[i + 1];
        res3 = (bm & mask[i + 2]) ^ mask[i + 2];
        res4 = (bm & mask[i + 3]) ^ mask[i + 3];

        if (!res1) {
            return i;
        } else if (!res2) {
            return i + 1;
        } else if (!res3) {
            return i + 2;
        } else if (!res4) {
            return i + 3;
        }
    }

    return UINT64_BITS;
}

u32 bm64_fast_search_consecutive_bits_from(u64 bm, u8 start, u32 bits) {
    const u64 *mask = bm64_consecutive_masks[bits - 1];
    u32 i = 0;
    u64 res1, res2, res3, res4;

    bm = ~bm;
#ifdef DEBUG
    // check start is aligned with `bits`
    if (start % bits) {
        pr_debug("%s ERROR: start %u is not aligned with bits %u\n", __func__,
                 start, bits);
        return UINT64_BITS;
    }
#endif

    for (i = start; i < UINT64_BITS; i += 4) {
        res1 = (bm & mask[i]) ^ mask[i];
        res2 = (bm & mask[i + 1]) ^ mask[i + 1];
        res3 = (bm & mask[i + 2]) ^ mask[i + 2];
        res4 = (bm & mask[i + 3]) ^ mask[i + 3];

        if (!res1) {
            return i;
        } else if (!res2) {
            return i + 1;
        } else if (!res3) {
            return i + 2;
        } else if (!res4) {
            return i + 3;
        }
    }

    return UINT64_BITS;
}

void bm_set(u8 *bm, u32 i) {
    bm[i >> UINT8_SHIFT] |= (1 << (i & UINT8_MASK));
}

void bm_clear(u8 *bm, u32 i) {
    bm[i >> UINT8_SHIFT] &= ~(1 << (i & UINT8_MASK));
}

u8 bm_test(u8 *bm, u32 i) {
    return bm[i >> UINT8_SHIFT] & (1 << (i & UINT8_MASK));
}

u32 bm_weight(u8 *bm, u32 len) {
    return bitmap_weight((unsigned long *)bm, len);
}

// comparator returns: 0 if equal, >0 if a > b, <0 if a < b
int range_insert_node(struct rb_root_cached *tree, struct range_node *new_node,
                      int (*comparator)(unsigned long, unsigned long)) {
    struct range_node *curr;
    struct rb_node **temp, *parent;
    int compVal;
    bool left_most = true;

    temp = &(tree->rb_root.rb_node);
    parent = NULL;

    while (*temp) {
        curr = container_of(*temp, struct range_node, node);
        if (comparator)
            compVal = comparator(curr->low, new_node->low);
        else
            compVal = default_compare(curr->low, new_node->low);
        parent = *temp;

        if (compVal > 0) {
            temp = &((*temp)->rb_left);
        } else if (compVal < 0) {
            temp = &((*temp)->rb_right);
            left_most = false;
        } else {
            pr_debug("%s: node [%lu, %lu) already exists: "
                     "[%lu, %lu)\n",
                     __func__, new_node->low, new_node->high, curr->low,
                     curr->high);
            return -EINVAL;
        }
    }

    rb_link_node(&new_node->node, parent, temp);
    rb_insert_color_cached(&new_node->node, tree, left_most);

    return 0;
}

/* return 1 if found, 0 if not found. Ret node indicates the node that is exact
 * smaller than the blk */
int range_find_node(struct rb_root_cached *tree, unsigned long low,
                    struct range_node **ret_node,
                    int (*comparator)(unsigned long, unsigned long)) {
    struct range_node *curr = NULL;
    struct rb_node *temp;
    int compVal;
    int ret = 0;

    temp = tree->rb_root.rb_node;

    while (temp) {
        curr = container_of(temp, struct range_node, node);
        if (comparator)
            compVal = comparator(curr->low, low);
        else
            compVal = default_compare(curr->low, low);

        if (compVal > 0) {
            temp = temp->rb_left;
        } else if (compVal < 0) {
            temp = temp->rb_right;
        } else {
            ret = 1;
            break;
        }
    }

    *ret_node = curr;

    return ret;
}

static int ___range_find_free_slot(struct rb_root_cached *tree,
                                   unsigned long low, unsigned long high,
                                   struct range_node **prev,
                                   struct range_node **next) {
    struct range_node *ret_node = NULL;
    struct rb_node *tmp;
    int ret;
    u64 ret_node_rng_low;
    u64 ret_node_rng_high;

    ret = range_find_node(tree, low, &ret_node, NULL);
    if (ret) {
        pr_debug("%s ERROR: [%lu, %lu) already in free list\n", __func__, low,
                 high);
        return -EINVAL;
    }

    ret_node_rng_low = ret_node->low;
    ret_node_rng_high = ret_node->high;

    if (!ret_node) {
        *prev = *next = NULL;
    } else if (ret_node_rng_high <= low) {
        *prev = ret_node;
        tmp = rb_next(&ret_node->node);
        if (tmp) {
            *next = container_of(tmp, struct range_node, node);
        } else {
            *next = NULL;
        }
    } else if (ret_node_rng_low > high) {
        *next = ret_node;
        tmp = rb_prev(&ret_node->node);
        if (tmp) {
            *prev = container_of(tmp, struct range_node, node);
        } else {
            *prev = NULL;
        }
    } else {
        pr_debug("%s ERROR: [%lu, %lu) overlaps with existing "
                 "node [%lu, %lu)\n",
                 __func__, low, high, ret_node_rng_low, ret_node_rng_high);
        return -EINVAL;
    }

    return 0;
}

static bool __range_try_insert_range(struct rb_root_cached *tree,
                                     struct range_node *prev,
                                     struct range_node *next, unsigned long low,
                                     unsigned long high) {
    u64 prev_rng_high = prev ? prev->high : 0;
    u64 next_rng_low = next ? next->low : 0;
    u64 next_rng_high = next ? next->high : 0;

    if (prev && next && low == prev_rng_high && high == next_rng_low) {
        /* fits the hole */
        rb_erase_cached(&next->node, tree);
        prev->high = next_rng_high;
        kfree(next);
        return true;
    } else if (prev && low == prev_rng_high) {
        /* Aligns left */
        prev->high = high;
        return true;
    } else if (next && high == next_rng_low) {
        /* Aligns right */
        next->low = low;
        return true;
    }

    return false;
}

int range_insert_range(struct rb_root_cached *tree, unsigned long low,
                       unsigned long high,
                       int (*comparator)(unsigned long, unsigned long)) {
    struct range_node *prev = NULL;
    struct range_node *next = NULL;
    int ret;

    if (RB_EMPTY_ROOT(&tree->rb_root)) {
        struct range_node *new_node =
            kmalloc(sizeof(struct range_node), GFP_ATOMIC);
        if (!new_node) {
            pr_debug("%s ERROR: kmalloc failed\n", __func__);
            return -ENOMEM;
        }
        new_node->low = low;
        new_node->high = high;
        ret = range_insert_node(tree, new_node, comparator);
        if (ret) {
            pr_debug("%s ERROR: insert node failed\n", __func__);
            kfree(new_node);
            return ret;
        }
        return ret;
    }

    ret = ___range_find_free_slot(tree, low, high, &prev, &next);
    if (ret) {
        pr_debug("%s ERROR: find free slot failed\n", __func__);
        return ret;
    }
    if (!__range_try_insert_range(tree, prev, next, low, high)) {
        // fail to insert
        struct range_node *new_node =
            kmalloc(sizeof(struct range_node), GFP_ATOMIC);
        if (!new_node) {
            pr_debug("%s ERROR: kmalloc failed\n", __func__);
            return -ENOMEM;
        }
        new_node->low = low;
        new_node->high = high;
        ret = range_insert_node(tree, new_node, comparator);
        if (ret) {
            pr_debug("%s ERROR: insert node failed\n", __func__);
            kfree(new_node);
            return ret;
        }
    }

    return ret;
}

#define range_traverse_tree(tree, temp, node)           \
    for (temp = rb_first_cached(tree),                  \
        node = rb_entry(temp, struct range_node, node); \
         temp;                                          \
         temp = rb_next(temp), node = rb_entry(temp, struct range_node, node))

int range_remove_range(struct rb_root_cached *tree, unsigned long low,
                       unsigned long high,
                       int (*comparator)(unsigned long, unsigned long)) {
    struct range_node *node;
    struct rb_node *tmp;
    struct list_head affected_nodes;
    INIT_LIST_HEAD(&affected_nodes);
    int ret;

    struct affected_range_node {
        struct list_head list;
        struct range_node *node;
    } * pos, *n;

    range_traverse_tree(tree, tmp, node) {
        if (node->low > high) {
            break;
        } else if (node->high < low) {
            continue;
        } else {
            struct affected_range_node *affected_node =
                kmalloc(sizeof(struct affected_range_node), GFP_ATOMIC);
            if (!affected_node) {
                pr_debug("%s ERROR: kmalloc failed\n", __func__);
                return -ENOMEM;
            }
            affected_node->node = node;
            list_add_tail(&affected_node->list, &affected_nodes);
        }
    }

    list_for_each_entry_safe(pos, n, &affected_nodes, list) {
        struct range_node *node = pos->node;
        if (node->low >= low && node->high <= high) {
            rb_erase_cached(&node->node, tree);
            kfree(node);
        } else if (node->low >= low && node->high > high) {
            node->low = high + 1;
        } else if (node->low < low && node->high <= high) {
            node->high = low - 1;
        } else if (node->low < low && node->high > high) {
            struct range_node *new_node =
                kmalloc(sizeof(struct range_node), GFP_ATOMIC);
            if (!new_node) {
                pr_debug("%s ERROR: kmalloc failed\n", __func__);
                return -ENOMEM;
            }
            new_node->low = high + 1;
            new_node->high = node->high;
            node->high = low - 1;
            ret = range_insert_node(tree, new_node, comparator);
            if (ret) {
                pr_debug("%s ERROR: insert node failed\n", __func__);
                kfree(new_node);
                return ret;
            }
        }
    }

    return 0;
}

static unsigned long __range_try_pop_range(void *key, void *value,
                                           unsigned long req) {
    struct range_node *node = value;

    unsigned long remain = node->high - node->low + 1;
    u64 allocated = 0;

    allocated = remain >= req ? req : remain;
    node->low += allocated;

    return allocated;
}

unsigned long range_try_pop_N_once(struct rb_root_cached *tree,
                                   unsigned long *N) {
    struct range_node *node = NULL;
    struct rb_node *tmp;
    unsigned long allocated = 0;
    unsigned long ret_low = 0;

    range_traverse_tree(tree, tmp, node) {
        allocated = __range_try_pop_range((void *)node->low, node, *N);
        break;
    }

    *N = allocated;

    if (node) {
        ret_low = node->low - allocated;
        if (node->low == node->high) {
            rb_erase_cached(&node->node, tree);
            kfree(node);
        }
    }

    return ret_low;
}

tl_node_t *tl_create_node(void) {
    tl_node_t *node = hk_alloc_tl_node();
    node->blk = 0;
    node->node.rb_left = NULL;
    node->node.rb_right = NULL;
    return node;
}

__always_inline void tl_build_alloc_param(tlalloc_param_t *param, u64 req,
                                          u16 flags) {
    param->flags = flags;
    param->req = req;
    param->_ret_node = NULL;
    param->_ret_allocated = 0;
}

/* num is entrynr(32)|entrynum(32)  */
__always_inline void tl_build_free_param(tlfree_param_t *param, u64 blk,
                                         u64 num, u16 flags) {
    param->flags = flags;
    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        param->blk = blk;
        param->num = num;
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        param->blk = blk;
        param->entrynr = (num >> 32) & 0xFFFFFFFF;
        param->entrynum = num & 0xFFFFFFFF;
    }
}

/* similar to free_param_t */
__always_inline void tl_build_restore_param(tlrestore_param_t *param, u64 blk,
                                            u64 num, u16 flags) {
    param->flags = flags;
    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        param->blk = blk;
        param->num = num;
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        param->blk = blk;
        param->entrynr = (num >> 32) & 0xFFFFFFFF;
        param->entrynum = num & 0xFFFFFFFF;
    }
    INIT_LIST_HEAD(&param->affected_nodes);
}

void tl_free_node(tl_node_t *node) {
    if (node) {
        kfree(node);
    }
}

static inline int tl_node_compare(void *a, void *b) {
    const u64 key_a = (const u64)a;
    const u64 key_b = (const u64)b;
    return key_a - key_b;
}

static int tl_tree_insert_node(struct rb_root_cached *tree,
                               tl_node_t *new_node) {
    tl_node_t *curr;
    struct rb_node **temp, *parent;
    int compVal;
    bool left_most = true;

    temp = &(tree->rb_root.rb_node);
    parent = NULL;

    while (*temp) {
        curr = container_of(*temp, tl_node_t, node);
        compVal = tl_node_compare((void *)curr->blk, (void *)new_node->blk);
        parent = *temp;

        if (compVal > 0) {
            temp = &((*temp)->rb_left);
        } else if (compVal < 0) {
            temp = &((*temp)->rb_right);
            left_most = false;
        } else {
            pr_debug("%s: node %lu - %lu already exists: "
                     "%lu - %lu\n",
                     __func__, new_node->blk,
                     new_node->dnode.num + new_node->blk - 1, curr->blk,
                     curr->blk + curr->dnode.num - 1);
            return -EINVAL;
        }
    }

    rb_link_node(&new_node->node, parent, temp);
    rb_insert_color_cached(&new_node->node, tree, left_most);

    return 0;
}

/* return 1 if found, 0 if not found. Ret node indicates the node that is exact
 * smaller than the blk */
static int tl_tree_find_node(struct rb_root_cached *tree, u64 blk,
                             tl_node_t **ret_node) {
    tl_node_t *curr = NULL;
    struct rb_node *temp;
    int compVal;
    int ret = 0;

    temp = tree->rb_root.rb_node;

    while (temp) {
        curr = container_of(temp, tl_node_t, node);
        compVal = tl_node_compare((void *)curr->blk, (void *)blk);

        if (compVal > 0) {
            temp = temp->rb_left;
        } else if (compVal < 0) {
            temp = temp->rb_right;
        } else {
            ret = 1;
            break;
        }
    }

    *ret_node = curr;

    return ret;
}

/* flags indicate whether find data blocks or meta-block */
static int tl_tree_find_free_slot(struct rb_root_cached *tree, u64 blk, u64 num,
                                  u16 flags, tl_node_t **prev,
                                  tl_node_t **next) {
    tl_node_t *ret_node = NULL;
    struct rb_node *tmp;
    int ret;
    u64 rng_low = blk;
    u64 rng_high = blk + num - 1;
    u64 ret_node_rng_low;
    u64 ret_node_rng_high;

    if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        BUG_ON(num != 1);
    }

    ret = tl_tree_find_node(tree, blk, &ret_node);
    if (ret) {
        pr_debug("%s ERROR: %lu - %lu already in free list\n", __func__, blk,
                 blk + num - 1);
        return -EINVAL;
    }

    ret_node_rng_low = ret_node->blk;
    ret_node_rng_high = TL_ALLOC_TYPE(flags) == TL_BLK
                            ? ret_node->blk + ret_node->dnode.num - 1
                            : ret_node->blk;

    if (!ret_node) {
        *prev = *next = NULL;
    } else if (ret_node_rng_high < rng_low) {
        *prev = ret_node;
        tmp = rb_next(&ret_node->node);
        if (tmp) {
            *next = container_of(tmp, tl_node_t, node);
        } else {
            *next = NULL;
        }
    } else if (ret_node_rng_low > rng_high) {
        *next = ret_node;
        tmp = rb_prev(&ret_node->node);
        if (tmp) {
            *prev = container_of(tmp, tl_node_t, node);
        } else {
            *prev = NULL;
        }
    } else {
        pr_debug("%s ERROR: %lu - %lu overlaps with existing "
                 "node %lu - %lu\n",
                 __func__, rng_low, rng_high, ret_node_rng_low,
                 ret_node_rng_high);
        return -EINVAL;
    }

    return 0;
}

void tl_mgr_init(tl_allocator_t *alloc, u64 blk_size, u64 meta_size) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    typed_meta_mgr_t *tmeta_mgr;
    tl_node_t *node;
    u64 blk = alloc->rng.high - alloc->rng.low + 1, i;

    data_mgr->free_tree = RB_ROOT_CACHED;
    data_mgr->blk_size = blk_size;

    spin_lock_init(&data_mgr->spin);
    node = tl_create_node();
    node->blk = alloc->rng.low;
    node->dnode.num = blk;
    tl_tree_insert_node(&data_mgr->free_tree, node);

    pr_debug("%s: free tree: %lu - %lu for cpu %d\n", __func__, node->blk,
             node->blk + blk - 1, alloc->cpuid);

    meta_mgr->meta_entries_perblk = blk_size / meta_size;
    BUG_ON(meta_mgr->meta_entries_perblk > UINT64_BITS);
    if (meta_mgr->meta_entries_perblk == UINT64_BITS) {
        meta_mgr->meta_entries_mask = (u64)-1;
    } else {
        meta_mgr->meta_entries_mask = (1 << meta_mgr->meta_entries_perblk) - 1;
    }
    meta_mgr->meta_size = meta_size;

    /* typed metadata managers */
    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        tmeta_mgr = &alloc->meta_manager.tmeta_mgrs[i];
        hash_init(tmeta_mgr->used_blks);
        INIT_LIST_HEAD(&tmeta_mgr->free_list);
        INIT_LIST_HEAD(&tmeta_mgr->pend_list);
        spin_lock_init(&tmeta_mgr->spin);
    }
}

int tl_alloc_init(tl_allocator_t *alloc, int cpuid, u64 blk, u64 num,
                  u32 blk_size, u32 meta_size, u8 mode, gc_ops_t *gc_ops) {
    alloc->rng.low = blk;
    alloc->rng.high = blk + num - 1;
    alloc->cpuid = cpuid;
    alloc->mode = mode;
    alloc->meta_manager.gc_ops = gc_ops;

    if (mode == TL_ALLOC_OPU)
        assert(gc_ops != NULL);

    tl_mgr_init(alloc, blk_size, meta_size);
    return 0;
}

static bool __tl_try_find_avail_data_blks(void *key, void *value, void *data) {
    tlalloc_param_t *param = data;
    tl_node_t *node = value;
    u64 allocated = 0;

    allocated = node->dnode.num >= param->req ? param->req : node->dnode.num;
    node->blk = node->blk + allocated;
    node->dnode.num -= allocated;

    param->_ret_node = node;
    param->_ret_rng.low = node->blk - allocated;
    param->_ret_rng.high = node->blk - 1;
    param->_ret_allocated = allocated;

    return true;
}

#define tl_traverse_tree(tree, temp, node)                                     \
    for (temp = rb_first_cached(tree), node = rb_entry(temp, tl_node_t, node); \
         temp; temp = rb_next(temp), node = rb_entry(temp, tl_node_t, node))

#define IF_ALLOC_IPU(alloc) (alloc->mode == TL_ALLOC_IPU)
#define IF_ALLOC_OPU(alloc) (alloc->mode == TL_ALLOC_OPU)

#define tl_alloc_try_lock(plock, flags)                      \
    {                                                        \
        if (!(TL_ALLOC_HINT(flags) & TL_ALLOC_HINT_NO_LOCK)) \
            spin_lock((plock));                              \
    }

#define tl_alloc_try_unlock(plock, flags)                    \
    {                                                        \
        if (!(TL_ALLOC_HINT(flags) & TL_ALLOC_HINT_NO_LOCK)) \
            spin_unlock((plock));                            \
    }

/* alloc as many as possible */
s32 tlalloc(tl_allocator_t *alloc, tlalloc_param_t *param) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    struct list_head *pos;
    tl_node_t *node;
    struct rb_node *temp;
    u16 flags = param->flags;
    s32 entrynr = -1;
    s32 ret = 0;
    u8 i;

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        // spin_lock(&data_mgr->spin);
        tl_alloc_try_lock(&data_mgr->spin, flags);
        tl_traverse_tree(&data_mgr->free_tree, temp, node) {
            if (__tl_try_find_avail_data_blks((void *)node->blk, node, param)) {
                break;
            }
        }
        if (param->_ret_node) {
            if (param->_ret_node->dnode.num == 0) {
                rb_erase_cached(&param->_ret_node->node, &data_mgr->free_tree);
                tl_free_node(param->_ret_node);
            }
            // spin_unlock(&data_mgr->spin);
            tl_alloc_try_unlock(&data_mgr->spin, flags);
        } else {
            ret = -ENOSPC;
            // spin_unlock(&data_mgr->spin);
            tl_alloc_try_unlock(&data_mgr->spin, flags);
            goto out;
        }
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        typed_meta_mgr_t *tmeta_mgr;
        u8 idx = meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags));
        tmeta_mgr = &meta_mgr->tmeta_mgrs[idx];
        // spin_lock(&tmeta_mgr->spin);
        tl_alloc_try_lock(&tmeta_mgr->spin, flags);
    retry:
        list_for_each(pos, &tmeta_mgr->free_list) {
            node = list_entry(pos, tl_node_t, list);

            if (IF_ALLOC_IPU(alloc)) {
                // search from the start
                entrynr = bm64_fast_search_consecutive_bits(node->mnode.bm,
                                                            param->req);
            } else if (IF_ALLOC_OPU(alloc)) {
                // search from the last allocated entry
                entrynr = bm64_fast_search_consecutive_bits_from(
                    node->mnode.bm, node->mnode.tail, param->req);
            }

            assert(entrynr >= 0);

            if (entrynr != UINT64_BITS) {
                param->_ret_node = node;
                param->_ret_rng.low = node->blk;
                param->_ret_rng.high = entrynr;
                for (i = 0; i < param->req; i++) {
                    bm_set((u8 *)&node->mnode.bm, entrynr + i);
                }
                node->mnode.tail = entrynr + param->req;

                /* too full to allocate */
                if (IF_ALLOC_IPU(alloc)) {
                    if ((node->mnode.bm & meta_mgr->meta_entries_mask) ==
                        meta_mgr->meta_entries_mask) {
                        list_del(&node->list);
                    }
                } else if (IF_ALLOC_OPU(alloc)) {
                    if (node->mnode.tail >= meta_mgr->meta_entries_perblk) {
                        list_del(&node->list);
                        // NOTE: do not remove from hash table since `tlfree`
                        // rely on it. Insert to the pend list for caller gc
                        list_add_tail(&node->list, &tmeta_mgr->pend_list);
                    }
                }
                // spin_unlock(&tmeta_mgr->spin);
                tl_alloc_try_unlock(&tmeta_mgr->spin, flags);
                return 0;
            }
        }
        // spin_unlock(&tmeta_mgr->spin);
        tl_alloc_try_unlock(&tmeta_mgr->spin, flags);

        /* alloc a block to hold metadata */
        tlalloc_param_t alloc_blk_param;

        tl_build_alloc_param(&alloc_blk_param, 1,
                             TL_BLK | TL_ALLOC_HINT(flags));
        ret = tlalloc(alloc, &alloc_blk_param);
        if (ret < 0) {
            goto out;
        }
        node = tl_create_node();
        node->blk = alloc_blk_param._ret_rng.low;
        node->mnode.bm = 0;

        param->_ret_allocated = 1;

        // spin_lock(&tmeta_mgr->spin);
        tl_alloc_try_lock(&tmeta_mgr->spin, flags);
        hash_add(tmeta_mgr->used_blks, &node->hnode, node->blk);

        pr_debug("alloc blk %lu for meta type %x (%s)\n", node->blk,
                 TL_ALLOC_MTA_TYPE(flags),
                 meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)));

        /* head insert */
        list_add_tail(&node->list, &tmeta_mgr->free_list);
        goto retry;
    }

out:
    return ret;
}

static bool __tl_try_insert_data_blks(struct rb_root_cached *tree,
                                      tl_node_t *prev, tl_node_t *next,
                                      tlfree_param_t *param) {
    u64 rng_low = param->blk;
    u64 rng_high = param->blk + param->num - 1;
    u64 prev_rng_high = prev ? prev->blk + prev->dnode.num - 1 : 0;
    u64 next_rng_low = next ? next->blk : 0;

    if (prev && next && (rng_low == prev_rng_high + 1) &&
        (rng_high + 1 == next_rng_low)) {
        /* fits the hole */
        rb_erase_cached(&next->node, tree);
        prev->dnode.num += (param->num + next->dnode.num);
        tl_free_node(next);
        param->freed = param->num;
        return true;
    } else if (prev && (rng_low == prev_rng_high + 1)) {
        /* Aligns left */
        prev->dnode.num += param->num;
        param->freed = param->num;
        return true;
    } else if (next && (rng_high + 1 == next_rng_low)) {
        /* Aligns right */
        next->blk = param->blk;
        next->dnode.num += param->num;
        param->freed = param->num;
        return true;
    }

    return false;
}

static bool __list_check_entry_freed(struct list_head *entry) {
    return entry->next == LIST_POISON1 && entry->prev == LIST_POISON2;
}

void tlfree(tl_allocator_t *alloc, tlfree_param_t *param) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *node;
    u16 flags = param->flags;
    param->freed = 0;

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        u64 blk = param->blk;
        u64 num = param->num;
        tl_node_t *prev = NULL;
        tl_node_t *next = NULL;
        int ret;

        pr_debug("free blk %lu, num %lu\n", blk, num);
        if (alloc->rng.low > blk || alloc->rng.high < blk + num - 1) {
            pr_debug("try free blk %lu, num %lu at %d\n", blk, num,
                     alloc->cpuid);
            BUG_ON(1);
        }

        // spin_lock(&data_mgr->spin);
        tl_alloc_try_lock(&data_mgr->spin, flags);
        ret = tl_tree_find_free_slot(&data_mgr->free_tree, blk, num, flags,
                                     &prev, &next);
        if (ret) {
            pr_debug(
                "fail to find free data slot for [%lu, %lu] at layout %d\n",
                blk, blk + num - 1, alloc->cpuid);
            BUG_ON(1);
        }
        __tl_try_insert_data_blks(&data_mgr->free_tree, prev, next, param);
        // spin_unlock(&data_mgr->spin);
        tl_alloc_try_unlock(&data_mgr->spin, flags);

        if (param->freed == 0) {
            node = tl_create_node();
            node->blk = blk;
            node->dnode.num = num;
            // spin_lock(&data_mgr->spin);
            tl_alloc_try_lock(&data_mgr->spin, flags);
            tl_tree_insert_node(&data_mgr->free_tree, node);
            // spin_unlock(&data_mgr->spin);
            tl_alloc_try_unlock(&data_mgr->spin, flags);
        }
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        u64 blk = param->blk;
        u32 entrynr = param->entrynr;
        u32 entrynum = param->entrynum;
        s32 i = 0;
        typed_meta_mgr_t *tmeta_mgr;
        tl_node_t *cur;
        int idx = meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags));

        pr_debug("free meta blk %lu, entrynr %u, entrynum %u, type %x (%s) at "
                 "%d layout.\n",
                 blk, entrynr, entrynum, TL_ALLOC_MTA_TYPE(flags),
                 meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)), alloc->cpuid);

        tmeta_mgr = &meta_mgr->tmeta_mgrs[idx];

        // spin_lock(&tmeta_mgr->spin);
        tl_alloc_try_lock(&tmeta_mgr->spin, flags);
        hash_for_each_possible(tmeta_mgr->used_blks, cur, hnode, blk) {
            if (cur->blk == blk) {
                for (i = 0; i < entrynum; i++) {
                    bm_clear((u8 *)&cur->mnode.bm, entrynr + i);
                }
                param->freed += entrynum;
                /* rls block */
                if (cur->mnode.bm == 0) {
                    hash_del(&cur->hnode);
                    /* The corner case is that one node is held by only
                     * used_blks table, */
                    /* since it is too full to do further allocation, see
                     * `tlalloc()`. */
                    /* Thus, we shall not del node from list again. */
                    if (__list_check_entry_freed(&cur->list) == false) {
                        list_del(&cur->list);
                    }
                    tl_free_node(cur);

                    tlfree_param_t free_blk_param;
                    tl_build_free_param(&free_blk_param, blk, 1,
                                        TL_BLK | TL_ALLOC_HINT(flags));
                    tlfree(alloc, &free_blk_param);

                    param->freed |= TLFREE_BLK;
                } else {
                    if (IF_ALLOC_IPU(alloc)) {
                        if (__list_check_entry_freed(&cur->list)) {
                            // free to be reallocated
                            list_add_tail(&cur->list, &tmeta_mgr->free_list);
                        }
                    } else if (IF_ALLOC_OPU(alloc)) {
                        // Do nothing
                    }
                }
                break;
            }
        }

        if (param->freed == 0) {
            BUG_ON(1);
        }

        // spin_unlock(&tmeta_mgr->spin);
        tl_alloc_try_unlock(&tmeta_mgr->spin, flags);
    }
}

struct affect_node {
    struct list_head list;
    tl_node_t *node;
};

static bool __tl_try_restore_data_blks(void *key, void *value, void *data) {
    tlrestore_param_t *param = data;
    tl_node_t *node = value;
    u64 blk = node->blk;
    u64 num = node->dnode.num;
    struct affect_node *anode;

    if (!(blk + num < param->blk || param->blk + param->num < blk)) {
        anode = kmalloc(sizeof(struct affect_node), GFP_ATOMIC);
        anode->node = node;
        list_add_tail(&anode->list, &param->affected_nodes);
    }

    if (param->blk > blk + num) {
        return true;
    }

    return false;
}

void tlrestore(tl_allocator_t *alloc, tlrestore_param_t *param) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *node;
    struct list_head *pos, *n;
    struct rb_node *temp;
    tlrestore_param_t data_restore_param;
    u16 flags = param->flags;

    if (TL_ALLOC_TYPE(flags) == TL_BLK) {
        u64 blk = param->blk;
        u64 num = param->num;
        struct affect_node *anode;

        // spin_lock(&data_mgr->spin);
        tl_alloc_try_lock(&data_mgr->spin, flags);
        tl_traverse_tree(&data_mgr->free_tree, temp, node) {
            if (__tl_try_restore_data_blks((void *)node->blk, node, param)) {
                break;
            }
        }
        // spin_unlock(&data_mgr->spin);
        tl_alloc_try_unlock(&data_mgr->spin, flags);

        /* traverse affected_nodes */
        list_for_each_safe(pos, n, &param->affected_nodes) {
            anode = list_entry(pos, struct affect_node, list);
            node = anode->node;
            if (blk <= node->blk && blk + num >= node->blk + node->dnode.num) {
                rb_erase_cached(&node->node, &data_mgr->free_tree);
                tl_free_node(node);
            } else if (blk <= node->blk &&
                       blk + num < node->blk + node->dnode.num) {
                node->dnode.num = node->blk + node->dnode.num - blk - num;
                node->blk = blk + num;
            } else if (blk > node->blk &&
                       blk + num >= node->blk + node->dnode.num) {
                node->dnode.num = blk - node->blk;
            } else if (blk > node->blk &&
                       blk + num < node->blk + node->dnode.num) {
                tl_node_t *new_node = tl_create_node();
                new_node->blk = blk + num;
                new_node->dnode.num =
                    node->blk + node->dnode.num - new_node->blk;
                // spin_lock(&data_mgr->spin);
                tl_alloc_try_lock(&data_mgr->spin, flags);
                tl_tree_insert_node(&data_mgr->free_tree, new_node);
                // spin_unlock(&data_mgr->spin);
                tl_alloc_try_unlock(&data_mgr->spin, flags);
                node->dnode.num = blk - node->blk;
            }
            list_del(&anode->list);
            kfree(anode);
        }
        BUG_ON(!list_empty((const struct list_head *)&param->affected_nodes));
    } else if (TL_ALLOC_TYPE(flags) == TL_MTA) {
        u64 blk = param->blk;
        u32 entrynr = param->entrynr;
        u32 entrynum = param->entrynum;
        s32 i = 0;
        typed_meta_mgr_t *tmeta_mgr;
        tl_node_t *cur;

        pr_debug("restore meta blk %lu, entrynr %u, entrynum %u, type %x (%s) "
                 "at %d layout.\n",
                 blk, entrynr, entrynum, TL_ALLOC_MTA_TYPE(flags),
                 meta_type_to_str(TL_ALLOC_MTA_TYPE(flags)), alloc->cpuid);

        tmeta_mgr =
            &meta_mgr->tmeta_mgrs[meta_type_to_idx(TL_ALLOC_MTA_TYPE(flags))];
        // spin_lock(&tmeta_mgr->spin);
        tl_alloc_try_lock(&tmeta_mgr->spin, flags);

        node = NULL;
        hash_for_each_possible(tmeta_mgr->used_blks, cur, hnode, blk) {
            if (cur->blk == blk) {
                node = cur;
                break;
            }
        }

        if (!node) {
            tl_build_restore_param(&data_restore_param, blk, 1, TL_BLK);
            tlrestore(alloc, &data_restore_param);

            /* create new meta node */
            node = tl_create_node();
            node->blk = blk;
            node->mnode.bm = 0;
            hash_add(tmeta_mgr->used_blks, &node->hnode, blk);
            list_add_tail(&node->list, &tmeta_mgr->free_list);
        }

        for (i = 0; i < entrynum; i++) {
            bm_set((u8 *)&node->mnode.bm, entrynr + i);
        }
        node->mnode.tail = entrynr + entrynum;

        /* too full to alloc */
        if (IF_ALLOC_IPU(alloc)) {
            if ((node->mnode.bm & meta_mgr->meta_entries_mask) ==
                meta_mgr->meta_entries_mask) {
                list_del(&node->list);
            }
        } else if (IF_ALLOC_OPU(alloc)) {
            if (node->mnode.tail >= meta_mgr->meta_entries_perblk) {
                list_del(&node->list);
                // NOTE: do not remove from hash table since `tlfree` rely on
                // it. Insert to the pend list for caller gc
                list_add_tail(&node->list, &tmeta_mgr->pend_list);
            }
        }
        // spin_unlock(&tmeta_mgr->spin);
        tl_alloc_try_unlock(&tmeta_mgr->spin, flags);
    }
}

unsigned long tlgc(tl_allocator_t *alloc, unsigned long max) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    typed_meta_mgr_t *tmeta_mgr;
    struct list_head *pend_list, victim_list;
    tl_node_t *node;
    struct rb_node *tmp;
    unsigned long gced = 0;
    int m_alloc_type_idx = 0, ret;
    u64 blks_to_reserve = 0, blks_to_reclaim = 0, blks_remain = 0;

    if (IF_ALLOC_IPU(alloc)) {
        return 0;
    }

    // gc per type
    while (max) {
        tmeta_mgr = &meta_mgr->tmeta_mgrs[m_alloc_type_idx];
        pend_list = &tmeta_mgr->pend_list;

        // frozen alloc
        spin_lock(&data_mgr->spin);
        spin_lock(&tmeta_mgr->spin);

        INIT_LIST_HEAD(&victim_list);

        blks_remain = 0;
        tl_traverse_tree(&data_mgr->free_tree, tmp, node) {
            blks_remain += node->dnode.num;
        }

        // select a number of nodes to migrate, return the number of nodes
        blks_to_reclaim = meta_mgr->gc_ops->victim_selection(
            alloc, pend_list, &victim_list, blks_remain, &blks_to_reserve);
        if (blks_to_reclaim == 0) {
            spin_unlock(&tmeta_mgr->spin);
            spin_unlock(&data_mgr->spin);
            m_alloc_type_idx = m_alloc_type_idx + 1;
            if (m_alloc_type_idx == TL_MTA_TYPE_NUM) {
                break;
            }
            continue;
        }

        assert(blks_to_reserve <= blks_remain);
        assert(blks_to_reclaim >= blks_to_reserve);

        gced += blks_to_reclaim;

        // migrate nodes
        // NOTE: handle lock contention, be careful to
        //       use lock there
        // USE MACRO `TL_ALLOC_HINT_NO_LOCK`
        ret = meta_mgr->gc_ops->migration(alloc, &victim_list, m_alloc_type_idx,
                                          blks_to_reserve);
        assert(!ret);

        ret = meta_mgr->gc_ops->post_clean(alloc, &victim_list);
        assert(!ret);

        // unfrozen alloc
        spin_unlock(&tmeta_mgr->spin);
        spin_unlock(&data_mgr->spin);

        max -= gced;
    }

    return gced;
}

void tl_destory(tl_allocator_t *alloc) {
    data_mgr_t *data_mgr = &alloc->data_manager;
    meta_mgr_t *meta_mgr = &alloc->meta_manager;
    tl_node_t *cur;
    struct rb_node *temp;
    struct list_head *pos, *n;
    struct hlist_node *htemp;
    int bkt, i;

    /* destroy data node */
    temp = rb_first_cached(&data_mgr->free_tree);
    while (temp) {
        cur = container_of(temp, tl_node_t, node);
        temp = rb_next(temp);
        rb_erase_cached(&cur->node, &data_mgr->free_tree);
        tl_free_node(cur);
    }

    /* destroy meta node */
    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        typed_meta_mgr_t *tmeta_mgr;
        tmeta_mgr = &meta_mgr->tmeta_mgrs[i];

        list_for_each_safe(pos, n, &tmeta_mgr->free_list) {
            cur = list_entry(pos, tl_node_t, list);
            list_del(&cur->list);
        }

        hash_for_each_safe(tmeta_mgr->used_blks, bkt, htemp, cur, hnode) {
            hash_del(&cur->hnode);
            tl_free_node(cur);
        }
    }
}

static bool __tl_dump_dnode(void *key, void *value, void *data) {
    tl_node_t *node = value;
    pr_info("[dnode]: start at %llu, end at %llu, len %llu\n", node->blk,
            node->blk + node->dnode.num - 1, node->dnode.num);
    return false;
}

static bool __tl_dump_mnode(void *key, void *value, void *data) {
    tl_node_t *node = value;
    pr_info("[mnode]: block %llu, alloc bitmap: 0x%llx\n", node->blk,
            node->mnode.bm);
    return false;
}

void tl_dump_data_mgr(data_mgr_t *data_mgr) {
    struct rb_node *temp;
    tl_node_t *node;

    spin_lock(&data_mgr->spin);
    tl_traverse_tree(&data_mgr->free_tree, temp, node) {
        __tl_dump_dnode((void *)node->blk, node, NULL);
    }
    spin_unlock(&data_mgr->spin);
}

void tl_dump_meta_mgr(meta_mgr_t *meta_mgr) {
    typed_meta_mgr_t *tmeta_mgr;
    struct list_head *pos;
    tl_node_t *node;
    int i;

    for (i = 0; i < TL_MTA_TYPE_NUM; i++) {
        tmeta_mgr = &meta_mgr->tmeta_mgrs[i];
        spin_lock(&tmeta_mgr->spin);
        list_for_each(pos, &tmeta_mgr->free_list) {
            node = list_entry(pos, tl_node_t, list);
            __tl_dump_mnode((void *)node->blk, node, NULL);
        }
        spin_unlock(&tmeta_mgr->spin);
    }
}