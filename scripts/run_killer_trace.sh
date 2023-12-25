#!/usr/bin/env bash

ABS_PATH=$(cd `dirname $0` && pwd)
TRACE_PATH=$ABS_PATH/../trace/trace-killer
export LD_PRELOAD="$ABS_PATH"/../build/libkiller.so
strace -o "$TRACE_PATH" -f $@

