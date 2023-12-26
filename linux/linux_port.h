#ifndef __LINUX_PORT_H
#define __LINUX_PORT_H

#ifndef __KERNEL__

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/falloc.h>
#include <linux/magic.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>
#include <stdatomic.h>
#include <signal.h>

#include "kernel.h"

#include "timekeeping32.h"
#include "./bitmap.h"
#include "./hashtable.h"
#include "./list.h"
#include "./llist.h"
#include "./mm_porting.h"
#include "./myrbtree.h"
#include "./radix-tree.h"
#include "./rbtree.h"
#include "./sort.h"

// Basic types
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

#define __aligned(x) __attribute__((aligned(x)))
// Atomic types
typedef struct atomic64 {
    u64 __aligned(8) counter;
} atomic64_t;

#ifdef __x86_64__

#define LOCK_PREFIX_HERE              \
    ".pushsection .smp_locks,\"a\"\n" \
    ".balign 4\n"                     \
    ".long 671f - .\n" /* offset */   \
    ".popsection\n"                   \
    "671:"

#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

/*
 * Non-existent functions to indicate usage errors at link time
 * (or compile-time if the compiler implements __compiletime_error().
 */
extern void __xchg_wrong_size(void)
    __compiletime_error("Bad argument size for xchg");
extern void __cmpxchg_wrong_size(void)
    __compiletime_error("Bad argument size for cmpxchg");
extern void __xadd_wrong_size(void)
    __compiletime_error("Bad argument size for xadd");
extern void __add_wrong_size(void)
    __compiletime_error("Bad argument size for add");

/*
 * Constants for operation sizes. On 32-bit, the 64-bit size it set to
 * -1 because sizeof will never return -1, thereby making those switch
 * case statements guaranteeed dead code which the compiler will
 * eliminate, and allowing the "missing symbol in the default case" to
 * indicate a usage error.
 */
#define __X86_CASE_B 1
#define __X86_CASE_W 2
#define __X86_CASE_L 4
// 64 bits
#define __X86_CASE_Q 8

/*
 * An exchange-type operation, which takes a value and a pointer, and
 * returns the old value.
 */
#define __xchg_op(ptr, arg, op, lock)                    \
    ({                                                   \
        __typeof__(*(ptr)) __ret = (arg);                \
        switch (sizeof(*(ptr))) {                        \
            case __X86_CASE_B:                           \
                asm volatile(lock #op "b %b0, %1\n"      \
                             : "+q"(__ret), "+m"(*(ptr)) \
                             :                           \
                             : "memory", "cc");          \
                break;                                   \
            case __X86_CASE_W:                           \
                asm volatile(lock #op "w %w0, %1\n"      \
                             : "+r"(__ret), "+m"(*(ptr)) \
                             :                           \
                             : "memory", "cc");          \
                break;                                   \
            case __X86_CASE_L:                           \
                asm volatile(lock #op "l %0, %1\n"       \
                             : "+r"(__ret), "+m"(*(ptr)) \
                             :                           \
                             : "memory", "cc");          \
                break;                                   \
            case __X86_CASE_Q:                           \
                asm volatile(lock #op "q %q0, %1\n"      \
                             : "+r"(__ret), "+m"(*(ptr)) \
                             :                           \
                             : "memory", "cc");          \
                break;                                   \
            default:                                     \
                __##op##_wrong_size();                   \
        }                                                \
        __ret;                                           \
    })

#define __xadd(ptr, inc, lock) __xchg_op((ptr), (inc), xadd, lock)
#define xadd(ptr, inc) __xadd((ptr), (inc), LOCK_PREFIX)
/**
 * arch_atomic64_add_return - add and return
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static __always_inline long arch_atomic64_add_return(long i, atomic64_t *v) {
    return i + xadd(&v->counter, i);
}

/**
 * arch_atomic64_set - set atomic64 variable
 * @v: pointer to type atomic64_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.
 */
static inline void arch_atomic64_set(atomic64_t *v, long i) {
    WRITE_ONCE(v->counter, i);
}

/**
 * arch_atomic64_read - read atomic64 variable
 * @v: pointer of type atomic64_t
 *
 * Atomically reads the value of @v.
 * Doesn't imply a read memory barrier.
 */
static inline long arch_atomic64_read(const atomic64_t *v) {
    return READ_ONCE((v)->counter);
}
#else
#error "Unsupported architecture"
#endif

static inline s64 atomic64_add_return(s64 i, atomic64_t *v) {
    return arch_atomic64_add_return(i, v);
}

static inline void atomic64_set(atomic64_t *v, s64 i) {
    arch_atomic64_set(v, i);
}

static inline s64 atomic64_read(const atomic64_t *v) {
    return arch_atomic64_read(v);
}

#define atomic64_read atomic64_read
#define atomic64_set atomic64_set
#define atomic64_add_return atomic64_add_return
#define atomic64_add_return_relaxed atomic64_add_return
#define ATOMIC64_INIT(i) \
    { (i) }

typedef pthread_spinlock_t spinlock_t;
#define spin_lock_init(lock) pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
#define spin_lock(lock) pthread_spin_lock(lock);
#define spin_unlock(lock) pthread_spin_unlock(lock);

struct task_struct {
    struct list_head list;
    atomic64_t should_stop;
    pthread_t t;
};

static LIST_HEAD(tasks);

static inline struct task_struct *kthread_create(int (*threadfn)(void *data),
                                                 void *data,
                                                 const char *namefmt, ...) {
    struct task_struct *task;
    task = malloc(sizeof(struct task_struct));
    pthread_create(&task->t, NULL, (void *(*)(void *))threadfn, data);
    list_add_tail(&task->list, &tasks);
    return task;
}

static inline bool kthread_should_stop(void) {
    pthread_t t = pthread_self();
    struct task_struct *task;
    list_for_each_entry(task, &tasks, list) {
        if (pthread_equal(task->t, t)) {
            return !!atomic64_read(&task->should_stop);
        }
    }
    return false;
}

static inline int kthread_stop(struct task_struct *k) {
    atomic64_set(&k->should_stop, 1);
    pthread_join(k->t, NULL);
    list_del(&k->list);
    free(k);
    return 0;
}

struct super_block {
    void *s_fs_info;
};

#define schedule() sched_yield()

#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)

#endif  // __KERNEL__

#endif  // __LINUX_PORT_H