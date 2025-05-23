/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#ifdef __KERNEL__
#include <linux/compiler_types.h>
#else
#include "compiler_types.h"
#endif

#ifndef __ASSEMBLY__

//#ifdef __KERNEL__

/*
 * Note: DISABLE_BRANCH_PROFILING can be used by special lowlevel code
 * to disable branch tracing on a per file basis.
 */
#if defined(CONFIG_TRACE_BRANCH_PROFILING) && \
    !defined(DISABLE_BRANCH_PROFILING) && !defined(__CHECKER__)
void ftrace_likely_update(struct ftrace_likely_data *f, int val, int expect,
                          int is_constant);

#define likely_notrace(x) __builtin_expect(!!(x), 1)
#define unlikely_notrace(x) __builtin_expect(!!(x), 0)

#define __branch_check__(x, expect, is_constant)                             \
    ({                                                                       \
        int ______r;                                                         \
        static struct ftrace_likely_data __attribute__((__aligned__(4)))     \
            __attribute__((section("_ftrace_annotated_branch"))) ______f = { \
                .data.func = __func__,                                       \
                .data.file = __FILE__,                                       \
                .data.line = __LINE__,                                       \
            };                                                               \
        ______r = __builtin_expect(!!(x), expect);                           \
        ftrace_likely_update(&______f, ______r, expect, is_constant);        \
        ______r;                                                             \
    })

/*
 * Using __builtin_constant_p(x) to ignore cases where the return
 * value is always the same.  This idea is taken from a similar patch
 * written by Daniel Walker.
 */
#ifndef likely
#define likely(x) (__branch_check__(x, 1, __builtin_constant_p(x)))
#endif
#ifndef unlikely
#define unlikely(x) (__branch_check__(x, 0, __builtin_constant_p(x)))
#endif

#ifdef CONFIG_PROFILE_ALL_BRANCHES
/*
 * "Define 'is'", Bill Clinton
 * "Define 'if'", Steven Rostedt
 */
#define if (cond, ...) __trace_if((cond, ##__VA_ARGS__))
#define __trace_if(cond)                                                     \
    if (__builtin_constant_p(!!(cond)) ? !!(cond) : ({                       \
            int ______r;                                                     \
            static struct ftrace_branch_data __attribute__((__aligned__(4))) \
                __attribute__((section("_ftrace_branch"))) ______f = {       \
                    .func = __func__,                                        \
                    .file = __FILE__,                                        \
                    .line = __LINE__,                                        \
                };                                                           \
            ______r = !!(cond);                                              \
            ______f.miss_hit[______r]++;                                     \
            ______r;                                                         \
        }))
#endif /* CONFIG_PROFILE_ALL_BRANCHES */

#else
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Optimization barrier */
#ifndef barrier
#define barrier() __memory_barrier()
#endif

#ifndef barrier_data
#define barrier_data(ptr) barrier()
#endif

/* Unreachable code */
#ifdef CONFIG_STACK_VALIDATION
#define annotate_reachable()                      \
    ({                                            \
        asm("%c0:\n\t"                            \
            ".pushsection .discard.reachable\n\t" \
            ".long %c0b - .\n\t"                  \
            ".popsection\n\t"                     \
            :                                     \
            : "i"(__COUNTER__));                  \
    })
#define annotate_unreachable()                      \
    ({                                              \
        asm("%c0:\n\t"                              \
            ".pushsection .discard.unreachable\n\t" \
            ".long %c0b - .\n\t"                    \
            ".popsection\n\t"                       \
            :                                       \
            : "i"(__COUNTER__));                    \
    })
#define ASM_UNREACHABLE                     \
    "999:\n\t"                              \
    ".pushsection .discard.unreachable\n\t" \
    ".long 999b - .\n\t"                    \
    ".popsection\n\t"
#else
#define annotate_reachable()
#define annotate_unreachable()
#endif

#ifndef ASM_UNREACHABLE
#define ASM_UNREACHABLE
#endif
#ifndef unreachable
#define unreachable()         \
    do {                      \
        annotate_reachable(); \
        do {                  \
        } while (1);          \
    } while (0)
#endif

/*
 * KENTRY - kernel entry point
 * This can be used to annotate symbols (functions or data) that are used
 * without their linker symbol being referenced explicitly. For example,
 * interrupt vector handlers, or functions in the kernel image that are found
 * programatically.
 *
 * Not required for symbols exported with EXPORT_SYMBOL, or initcalls. Those
 * are handled in their own way (with KEEP() in linker scripts).
 *
 * KENTRY can be avoided if the symbols in question are marked as KEEP() in the
 * linker script. For example an architecture could KEEP() its entire
 * boot/exception vector code rather than annotate each function and data.
 */
#ifndef KENTRY
#define KENTRY(sym)                                  \
    extern typeof(sym) sym;                          \
    static const unsigned long __kentry_##sym __used \
        __attribute__((section("___kentry"           \
                               "+" #sym),            \
                       used)) = (unsigned long)&sym;
#endif

#ifndef RELOC_HIDE
#define RELOC_HIDE(ptr, off)          \
    ({                                \
        unsigned long __ptr;          \
        __ptr = (unsigned long)(ptr); \
        (typeof(ptr))(__ptr + (off)); \
    })
#endif

#ifndef OPTIMIZER_HIDE_VAR
#define OPTIMIZER_HIDE_VAR(var) barrier()
#endif

/* Not-quite-unique ID. */
#ifndef __UNIQUE_ID
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __LINE__)
#endif

#ifdef __KERNEL__
#include <uapi/linux/types.h>
#endif

#define __READ_ONCE_SIZE                                              \
    ({                                                                \
        switch (size) {                                               \
            case 1:                                                   \
                *(__u8 *)res = *(volatile __u8 *)p;                   \
                break;                                                \
            case 2:                                                   \
                *(__u16 *)res = *(volatile __u16 *)p;                 \
                break;                                                \
            case 4:                                                   \
                *(__u32 *)res = *(volatile __u32 *)p;                 \
                break;                                                \
            case 8:                                                   \
                *(__u64 *)res = *(volatile __u64 *)p;                 \
                break;                                                \
            default:                                                  \
                barrier();                                            \
                __builtin_memcpy((void *)res, (const void *)p, size); \
                barrier();                                            \
        }                                                             \
    })

static __always_inline void __read_once_size(const volatile void *p, void *res,
                                             int size) {
    __READ_ONCE_SIZE;
}

#ifdef CONFIG_KASAN
/*
 * This function is not 'inline' because __no_sanitize_address confilcts
 * with inlining. Attempt to inline it may cause a build failure.
 * 	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
 * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
 */
static __no_sanitize_address __maybe_unused void __read_once_size_nocheck(
    const volatile void *p, void *res, int size) {
    __READ_ONCE_SIZE;
}
#else
static __always_inline void __read_once_size_nocheck(const volatile void *p,
                                                     void *res, int size) {
    __READ_ONCE_SIZE;
}
#endif

static __always_inline void __write_once_size(volatile void *p, void *res,
                                              int size) {
    switch (size) {
        case 1:
            *(volatile __u8 *)p = *(__u8 *)res;
            break;
        case 2:
            *(volatile __u16 *)p = *(__u16 *)res;
            break;
        case 4:
            *(volatile __u32 *)p = *(__u32 *)res;
            break;
        case 8:
            *(volatile __u64 *)p = *(__u64 *)res;
            break;
        default:
            barrier();
            __builtin_memcpy((void *)p, (const void *)res, size);
            barrier();
    }
}

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 *
 * In contrast to ACCESS_ONCE these two macros will also work on aggregate
 * data types like structs or unions. If the size of the accessed data
 * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)
 * READ_ONCE() and WRITE_ONCE() will fall back to memcpy(). There's at
 * least two memcpy()s: one for the __builtin_memcpy() and then one for
 * the macro doing the copy of variable - '__u' allocated on the stack.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 */
#ifdef __KERNEL__
#include <asm/barrier.h>
#else
#define smp_read_barrier_depends()
#endif

#define __READ_ONCE(x, check)                                                \
    ({                                                                       \
        union {                                                              \
            typeof(x) __val;                                                 \
            char __c[1];                                                     \
        } __u;                                                               \
        if (check)                                                           \
            __read_once_size(&(x), __u.__c, sizeof(x));                      \
        else                                                                 \
            __read_once_size_nocheck(&(x), __u.__c, sizeof(x));              \
        smp_read_barrier_depends(); /* Enforce dependency ordering from x */ \
        __u.__val;                                                           \
    })
#define READ_ONCE(x) __READ_ONCE(x, 1)

/*
 * Use READ_ONCE_NOCHECK() instead of READ_ONCE() if you need
 * to hide memory access from KASAN.
 */
#define READ_ONCE_NOCHECK(x) __READ_ONCE(x, 0)

#define WRITE_ONCE(x, val)                           \
    ({                                               \
        union {                                      \
            typeof(x) __val;                         \
            char __c[1];                             \
        } __u = {.__val = (__force typeof(x))(val)}; \
        __write_once_size(&(x), __u.__c, sizeof(x)); \
        __u.__val;                                   \
    })

//#endif /* __KERNEL__ */

#endif /* __ASSEMBLY__ */

#ifndef __optimize
#define __optimize(level)
#endif

/* Compile time object size, -1 for unknown */
#ifndef __compiletime_object_size
#define __compiletime_object_size(obj) -1
#endif
#ifndef __compiletime_warning
#define __compiletime_warning(message)
#endif
#ifndef __compiletime_error
#define __compiletime_error(message)
/*
 * Sparse complains of variable sized arrays due to the temporary variable in
 * __compiletime_assert. Unfortunately we can't just expand it out to make
 * sparse see a constant array size without breaking compiletime_assert on old
 * versions of GCC (e.g. 4.2.4), so hide the array from sparse altogether.
 */
#ifndef __CHECKER__
#define __compiletime_error_fallback(condition)  \
    do {                                         \
        ((void)sizeof(char[1 - 2 * condition])); \
    } while (0)
#endif
#endif
#ifndef __compiletime_error_fallback
#define __compiletime_error_fallback(condition) \
    do {                                        \
    } while (0)
#endif

#ifdef __OPTIMIZE__
#define __compiletime_assert(condition, msg, prefix, suffix)       \
    do {                                                           \
        bool __cond = !(condition);                                \
        extern void prefix##suffix(void) __compiletime_error(msg); \
        if (__cond)                                                \
            prefix##suffix();                                      \
        __compiletime_error_fallback(__cond);                      \
    } while (0)
#else
#define __compiletime_assert(condition, msg, prefix, suffix) \
    do {                                                     \
    } while (0)
#endif

#define _compiletime_assert(condition, msg, prefix, suffix) \
    __compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
    _compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

#define compiletime_assert_atomic_type(t) \
    compiletime_assert(__native_word(t),  \
                       "Need native word sized stores/loads for atomicity.")

/*
 * Prevent the compiler from merging or refetching accesses.  The compiler
 * is also forbidden from reordering successive instances of ACCESS_ONCE(),
 * but only when the compiler is aware of some particular ordering.  One way
 * to make the compiler aware of ordering is to put the two invocations of
 * ACCESS_ONCE() in different C statements.
 *
 * ACCESS_ONCE will only work on scalar types. For union types, ACCESS_ONCE
 * on a union member will work as long as the size of the member matches the
 * size of the union and the size is smaller than word size.
 *
 * The major use cases of ACCESS_ONCE used to be (1) Mediating communication
 * between process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 *
 * If possible use READ_ONCE()/WRITE_ONCE() instead.
 */
#define __ACCESS_ONCE(x)                                       \
    ({                                                         \
        __maybe_unused typeof(x) __var = (__force typeof(x))0; \
        (volatile typeof(x) *)&(x);                            \
    })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))

/**
 * lockless_dereference() - safely load a pointer for later dereference
 * @p: The pointer to load
 *
 * Similar to rcu_dereference(), but for situations where the pointed-to
 * object's lifetime is managed by something other than RCU.  That
 * "something other" might be reference counting or simple immortality.
 *
 * The seemingly unused variable ___typecheck_p validates that @p is
 * indeed a pointer type by using a pointer to typeof(*p) as the type.
 * Taking a pointer to typeof(*p) again is needed in case p is void *.
 */
#define lockless_dereference(p)                                         \
    ({                                                                  \
        typeof(p) _________p1 = READ_ONCE(p);                           \
        typeof(*(p)) *___typecheck_p __maybe_unused;                    \
        smp_read_barrier_depends(); /* Dependency order vs. p above. */ \
        (_________p1);                                                  \
    })

#endif /* __LINUX_COMPILER_H */
