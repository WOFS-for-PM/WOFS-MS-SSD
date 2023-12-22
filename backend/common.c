#include <fcntl.h>
#include <stdlib.h>

#include "common.h"

#define PREDEFINED_PAGE_SIZE 4096
#define PREDEFINED_CACHE_LINE_SIZE 64
#define CACHE_LINE_FILE \
    "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void) {
    char size[32];
    int fd, ret;

    fd = open(CACHE_LINE_FILE, O_RDONLY);
    if (fd < 0)
        return -1;

    ret = read(fd, size, sizeof(size));

    close(fd);

    if (ret <= 0)
        return -1;
    else
        return atoi(size);
}

static inline int os_cache_line_size(void) {
    static int size = 0;

    size = arch_cache_line_size();
    if (size <= 0)
        size = PREDEFINED_CACHE_LINE_SIZE;

    return size;
}

static inline int os_page_size(void) {
    static int size = 0;

    size = getpagesize();
    if (size <= 0)
        size = PREDEFINED_PAGE_SIZE;

    return size;
}

int thread_data_init(struct thread_data *td, int iodepth, int bs,
                     char *dev_path) {
    size_t buf_size;
    int ret;

    buf_size = (unsigned long long)iodepth * (unsigned long long)bs;

    ret = posix_memalign(&td->buf, os_page_size(), buf_size);
    if (ret) {
        perror("posix_memalign");
        BUG_ON(1);
        return ret;
    }

    td->iodepth = iodepth;
    td->bs = bs;
    td->dev_path = dev_path;

    return 0;
}

int thread_data_cleanup(struct thread_data *td) {
    free(td->buf);
    return 0;
}