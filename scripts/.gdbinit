set environment LD_PRELOAD build/libkiller.so
set breakpoint pending on
b killer_init
run