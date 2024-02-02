#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include "../backend/common.h"

#define IO_DEPTH 128
#define IO_UNIT 4096
#define DEV_PATH "/dev/nvme0n1p1"
#define LOOP (128 * 1024)

#define BENCH_START(name)                      \
    {                                          \
        const char *_name = name;              \
        printf("\n[BENCH START]: %s\n", name); \
        d_addr = d_start;                      \
        m_addr = m_start;                      \
        struct timespec start, end;            \
        clock_gettime(CLOCK_MONOTONIC, &start);

#define BENCH_END(op, size)                                                   \
    clock_gettime(CLOCK_MONOTONIC, &end);                                     \
    double _time = (end.tv_sec - start.tv_sec) +                              \
                   (end.tv_nsec - start.tv_nsec) / 1000000000.0;              \
    double bandwidth = (double)(size) / 1024 / 1024 / 1024 / _time;           \
    double lat = _time * 1000 * 1000 / (op);                                  \
    printf(                                                                   \
        "[BENCH END]: %s time: %lf s, bandwidth: %lf GB/s, lat: %lf us/op\n", \
        _name, _time, bandwidth, lat);                                        \
    }                                                                         \
    io_drain(td);                                                             \
    io_fence(td);

#define DECLARE_BENCH_ENV()                 \
    char buf[32 * 1024];                    \
    char meta[256];                         \
    int loop = LOOP;                        \
    int max_meta_times = 10;                \
    unsigned long long d_start = 0, d_addr, \
                       m_start = d_start + loop * IO_UNIT, m_addr;

static inline void sfence(void) {
    asm volatile("sfence\n" : :);
}

static inline void mem_fence(void) {
    sfence();
}

static u64 inline __require_flush(u64 addr, u32 entry_size) {
    return ((addr + entry_size) & (IO_UNIT - 1)) == 0;
}

static void inline try_evict(struct thread_data *td, u64 addr, u32 size) {
    if (__require_flush(addr, size)) {
        pr_debug("flush [%llx, %llx)\n", round_down(addr, IO_UNIT),
                 round_down(addr, IO_UNIT) + IO_UNIT);
        io_flush(td, round_down(addr, IO_UNIT), IO_UNIT);
    }
}

struct thread_data *init_io_engine(int sq_poll_cpu) {
    struct thread_data *td =
        (struct thread_data *)malloc(sizeof(struct thread_data));
    int ret;
    io_register(false);
    thread_data_init(td, IO_DEPTH, IO_UNIT, DEV_PATH, &sq_poll_cpu);
    ret = io_open(td, "uring");
    assert(!ret);

    return td;
}

void destroy_io_engine(struct thread_data *td) {
    assert(td);
    io_close(td);
    thread_data_cleanup(td);
    free(td);
}

#endif