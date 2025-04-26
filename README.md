# WOFS for MS-SSD

This repository contains the code base for Wolves atop an emulated MS-SSD. Wolves for MS-SSD inherits many existing codes from the original [Wolves](https://github.com/WOFS-for-PM/WOFS) code base, but with a cleaner structure that eliminates HUNTER file system's burden. The artifact evaluation steps can be obtained from [our AE repository](https://github.com/WOFS-for-PM/tests). We now introduce the code base.

## Code Organization

Wolves for MS-SSD is deployed as a user-space file system to facilitate `io_uring` ability for fast I/O. The primary code difference compared to the original Wolves code base is listed below:

- `backend/`: `io_uring` driver code inspired from FIO. The initialized buffer should be protected by UPS.

- `glibc/`: `glibc`-related File operations implementation. 

- `linux/`: The [Kernel Porting](https://github.com/oun111/kernel_porting) project, which enables us to use the same kernel API
  in user space. 

- `utils/`: Utility codes for the user-space file system.

- `wrapper.c` and `usyscall.c`: The main entry of the user-space file system. It builds up a simple VFS wrapper, initializes the `io_uring`, and mounts the file system.

- `io_dispatch.c`: The helper file to dispatch the I/O requests to the `io_uring` driver, in a memory-like manner. 

- Others: we have changed all direct PM access to use `io_dispatch` functions.

## Future Work

The `io_dispather` is now in a very simple and fragile state. Maybe we can use a more elegant way (e.g., implementing a virtual memory view, backed by `io_uring` buffer) to transparently handle all the I/O requests for better emulation.

