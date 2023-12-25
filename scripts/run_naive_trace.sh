#!/usr/bin/env bash

ABS_PATH=$(cd `dirname $0` && pwd)
TRACE_PATH=$ABS_PATH/../trace/trace-golden
strace -o "$TRACE_PATH" -f $@

