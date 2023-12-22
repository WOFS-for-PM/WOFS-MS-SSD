set environment LD_PRELOAD /home/deadpool/WOFS/killer-nvme/build/libkiller.so
set breakpoint pending on
b killer_init
run