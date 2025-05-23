ABS_PATH=$(shell pwd)
CFLAGS=-fPIC -mclwb -mclflushopt -Wall -pthread -mavx512f -I. -DBITS_PER_LONG=64 -DKBUILD_MODNAME=\"KILLER\" -lkp -L$(ABS_PATH)/linux -Wl,-rpath=$(ABS_PATH)/linux
CC=gcc

.PHONY: default
default: libkiller.so;

OPTS := -O3

BUILD_DIR := $(shell pwd)/build
LIB_DIR := $(shell pwd)

LIB_FILES := $(shell find $(LIB_DIR) -maxdepth 1 -name "*.c" )
LIB_FILES += $(shell find $(LIB_DIR)/backend -name "*.c")
LIB_FILES += $(shell find $(LIB_DIR)/utils -name "*.c")

LIB_OBJS := $(patsubst $(LIB_DIR)/%.c,$(BUILD_DIR)/%.o,$(LIB_FILES))

K_FILES := $(shell find $(LIB_DIR) -maxdepth 1 -name "*.c")
K_OBJS := $(patsubst $(LIB_DIR)/%.c,%.o,$(K_FILES))

# Filters out the user-space files
K_OBJS := $(filter-out port_test.o, $(K_OBJS))
K_OBJS := $(filter-out wrapper.o, $(K_OBJS))
K_OBJS := $(filter-out syscall.o, $(K_OBJS))

obj-m += killer.o
killer-y := $(K_OBJS)

DEV_PATH := /dev/nvme0n1p1

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g -DDEBUG
	OPTS := -O0
endif

MODE ?= 1
ifeq ($(MODE), 1)
	CFLAGS += -DMODE_STRICT
else ifeq ($(MODE), 0)
	CFLAGS += -DMODE_ASYNC
endif

CFLAGS += $(OPTS)

all: libkiller.so

libkiller.so: libkp.so killer.a wrapper.c ffile.o
	$(CC) -shared $(CFLAGS) -o build/libkiller.so wrapper.c build/killer.a build/ffile.o -ldl -lkp

killer.a: $(LIB_OBJS)
	ar cru build/killer.a $(LIB_OBJS)

ffile.o:
	cd glibc && $(MAKE)

$(BUILD_DIR)/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

libkp.so:
	cd linux && $(MAKE)

ci-test: libkiller.so
	cd tests && $(MAKE) clean && $(MAKE)

	@echo "\033[35m\033[1m===== Basic Tests =====\033[0m"
	sudo bash scripts/run_killer.sh tests/test
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

	@echo "\033[35m\033[1m===== FIO Tests: WRITE =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4K -size=128k -name=write -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

	@echo "\033[35m\033[1m===== FIO Tests: RAND-WRITE =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=randwrite -ioengine=sync -bs=4K -size=128k -name=randwrite -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

	@echo "\033[35m\033[1m===== FIO Tests: READ =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=read -ioengine=sync -bs=4K -size=128k -name=read -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

perf-test: libkiller.so
	make clean && make -j$(nproc)

	@echo "\033[35m\033[1m===== FIO Perf Tests: WRITE =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4K -size=4G -name=write -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

	@echo "\033[35m\033[1m===== FIO Perf Tests: RAND-WRITE =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=randwrite -ioengine=sync -bs=4K -size=4G -name=randwrite -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

	@echo "\033[35m\033[1m===== FIO Perf Tests: READ =====\033[0m"
	sudo bash scripts/run_killer.sh fio -filename=\a -fallocate=none -direct=0 -iodepth 1 -rw=read -ioengine=sync -bs=4K -size=4G -name=read -thread
	@echo "\033[32m\033[1m===== Done =====\n\033[0m"

fio-strace:
	mkdir -p trace
	sudo rm -f ./trace/output-golden ./trace/output-killer ./trace/test-golden ./trace/test-killer
	sudo bash scripts/run_naive_trace.sh fio -filename=./trace/test-golden -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4K -size=128k -name=write -thread
	sudo bash scripts/run_killer_trace.sh fio -filename=./trace/test-killer -fallocate=none -direct=0 -iodepth 1 -rw=write -ioengine=sync -bs=4K -size=128k -name=write -thread

kmod:
	# $(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd`
	@echo "Building kernel module..."
	@echo $(K_OBJS)

kmod-clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=`pwd` clean

CODES := $(shell find $(LIB_DIR) -maxdepth 1 -name "*.c" )
CODES += $(shell find $(LIB_DIR)/backend -name "*.c")
CODES += $(shell find $(LIB_DIR) -maxdepth 1 -name "*.h" )
CODES += $(shell find $(LIB_DIR)/backend -name "*.h")
CODES += $(LIB_DIR)/linux/linux_port.h

LOC:
	@find $(CODES) -type f -print | xargs wc -l

ugdb:
	sudo gdb -x scripts/.gdbinit $(shell pwd)/tests/test

clean:
	rm -r build/*
	cd linux && $(MAKE) clean