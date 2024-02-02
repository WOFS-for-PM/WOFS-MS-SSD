#include "common.h"

int main() {
    struct thread_data *td = init_io_engine(-1);
    DECLARE_BENCH_ENV();
    // WAR
    for (int j = 0; j < max_meta_times; j++) {
        char name[64];
        snprintf(name, 64, "WOFS pipeline w/ read-modify-write, meta times: %d",
                 j);

        BENCH_START(name);
        // test pipeline
        for (int i = 0; i < loop; i++) {
            io_write(td, d_addr, buf, IO_UNIT, O_IO_DROP);
            mem_fence();
            for (int n = 0; n < j; n++) {
                io_read(td, m_addr, meta, 64, O_IO_DROP);
                meta[0] = (char)n;
                io_write(td, m_addr, meta, 64, O_IO_CACHED);
                try_evict(td, m_addr, 256);
                mem_fence();
                m_addr += 256;
            }
            d_addr += 4096;
        }
        BENCH_END(loop, loop * 4096);
    }

    // WAW_INPLACE
    for (int j = 0; j < max_meta_times; j++) {
        char name[64];
        snprintf(name, 64, "WOFS pipeline w/ mem fence, inplace meta times: %d",
                 j);
        BENCH_START(name);
        // test pipeline
        for (int i = 0; i < loop; i++) {
            io_write(td, d_addr, buf, IO_UNIT, O_IO_DROP);
            mem_fence();
            for (int n = 0; n < j; n++) {
                io_write(td, m_addr, meta, 64, O_IO_CACHED);
                mem_fence();
            }
            d_addr += 4096;
        }
        BENCH_END(loop, loop * 4096);
    }

    // WAD
    for (int j = 0; j < max_meta_times; j++) {
        char name[64];
        snprintf(name, 64, "WOFS pipeline w/ mem fence, meta times: %d", j);
        BENCH_START(name);
        // test pipeline
        for (int i = 0; i < loop; i++) {
            io_write(td, d_addr, buf, IO_UNIT, O_IO_DROP);
            mem_fence();
            for (int n = 0; n < j; n++) {
                io_write(td, m_addr, meta, 64, O_IO_CACHED);
                try_evict(td, m_addr, 256);
                mem_fence();
                m_addr += 256;
            }
            d_addr += 4096;
        }
        BENCH_END(loop, loop * 4096);
    }

    // RAW
    for (int j = 0; j < max_meta_times; j++) {
        char name[64];
        snprintf(name, 64, "WOFS pipeline w/ io fence, meta times: %d", j);
        BENCH_START(name);
        // test pipeline
        for (int i = 0; i < loop; i++) {
            io_write(td, d_addr, buf, IO_UNIT, O_IO_DROP);
            mem_fence();
            for (int n = 0; n < j; n++) {
                // write meta, and reread for verification
                io_write(td, m_addr, meta, 64, O_IO_CACHED);
                mem_fence();
                io_read(td, m_addr, meta, 64, O_IO_DROP);
                try_evict(td, m_addr, 256);
                m_addr += 256;
            }
            d_addr += 4096;
        }
        BENCH_END(loop, loop * 4096);
    }
    destroy_io_engine(td);
}