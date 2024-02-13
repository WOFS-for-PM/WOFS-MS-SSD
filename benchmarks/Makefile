ABS_PATH=$(shell pwd)
CFLAGS=-fPIC -mclwb -mclflushopt -mavx512f -Wall -pthread -I. -DBITS_PER_LONG=64 -lkp -L$(ABS_PATH)/../linux -Wl,-rpath=$(ABS_PATH)/../linux 
CC=gcc

.PHONY: default

OPTS := -O3
BUILD_DIR := $(shell pwd)/build

BACKEND_FILES := $(shell find $(ABS_PATH)/../backend -name "*.c")
BACKEND_OBJS := $(patsubst $(ABS_PATH)/../backend/%.c,$(BUILD_DIR)/%.o,$(BACKEND_FILES))

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g
	OPTS := -O0
endif

all: stalls urfs

stalls: libbackend.a libkp.so
	$(CC) $(CFLAGS) $(OPTS) -o build/stalls $(ABS_PATH)/stalls.c build/libbackend.a -lkp

urfs: libbackend.a libkp.so
	$(CC) $(CFLAGS) $(OPTS) -o build/urfs $(ABS_PATH)/urfs.c build/libbackend.a -lkp

libbackend.a: $(BACKEND_OBJS)
	ar cru build/libbackend.a $(BACKEND_OBJS)

libkp.so:
	cd ../linux && $(MAKE)

$(BUILD_DIR)/%.o: $(ABS_PATH)/../backend/%.c
	@echo "Building $@ using $<"
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(OPTS) -c $< -o $@

test-stalls: stalls
	./build/stalls

test-urfs: urfs
	./build/urfs

clean:
	rm -rf $(BUILD_DIR)/*
