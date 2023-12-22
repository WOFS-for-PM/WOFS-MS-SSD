#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "mm_porting.h"

void *__malloc__(size_t sz) {
    size_t sz1 = SIZE_ALIGNED(sz);

    return malloc(sz1);
}

void __free__(void *p) {
    /* FIXME: don't use this */
    free(p);
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
                                     size_t align, unsigned long flags,
                                     void (*ctor)(void *)) {
    struct kmem_cache *p = __malloc__(sizeof(struct kmem_cache));

    strcpy(p->name, name);
    p->size = size;

    return p;
}

void kmem_cache_destroy(struct kmem_cache *s) {
    if (s)
        __free__(s);
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags) {
    if (!cachep) {
        return NULL;
    }

    return __malloc__(cachep->size);
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp) {
    if (cachep) {
        __free__(objp);
    }
}

void *kmalloc(size_t size, gfp_t flags) {
    return __malloc__(size);
}

void *kzalloc(size_t size, gfp_t flags) {
    void *p = __malloc__(size);
    if (p) {
        memset(p, 0, size);
    }
    return p;
}

void kfree(const void *objp) {
    __free__((void *)objp);
}

void *krealloc(void *p, size_t newsize, gfp_t flags) {
    return realloc(p, newsize);
}

void *kvcalloc(size_t n, size_t size, gfp_t flags) {
    void *p = __malloc__(n * size);
    if (p) {
        memset(p, 0, n * size);
    }
    return p;
}
