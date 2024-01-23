# KILLER for NVMe


## TODO List

- [ ] Refactor the I/O backend
    - [ ] io_rmw to avoid double-copy
    
    - [ ] remove CUR_DEV_HANDLER_PTR, determine the `td` core by I/O address
    
    - I/O Interface Design
        - handle = read(addr, buf, size)
            - [ ] Uncached. Read will drop `io_u` if `io_u` is not cached.  
            - [ ] Cached. Read from a cached `io_u` will not drop `io_u`.
        
        - handle = write(addr, buf, size)
            - [ ] Uncached. Write an aligned `io_u` will drop `io_u`.
            - [ ] Uncached. Write an unaligned `io_u` will perform a read-modify-write and cache the `io_u` till the last byte is written. If `hint=NO_RMW` will force not read-modify-write but only cached write, should be carefully used.
            - [ ] Cached. Write to a cached `io_u` will not drop `io_u` unless the last byte is written.
            - [ ] Cached. Write to a cached `io_u` will change `io_u` to a write unit.

        - ptr = rmw(addr, size)
            - [ ] Read a `io_u` and cached it, return the pointer to the cached `io_u` buffer.
        
        - handle = flush(addr, size)
            - [ ] Flush will drop all the cached `io_u` within the given range [addr, addr + size).
        
        - drain(handle)
            - [ ] Flush all the cached `io_u` in current `handle` are written and dropped.
        
        - winvd(addr, size)
            - [ ] Only drop the cached `io_u` within the given range [addr, addr + size) but not write them.

        - clwb(addr, size)
            - [ ] Only write the cached `io_u` within the given range [addr, addr + size) but not drop them.

        - handle = fence(handle)
            - [ ] Wait till all the cached `io_u` in current `handle` are written.


