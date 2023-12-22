#!/usr/bin/env bash

ABS_PATH=$(cd `dirname $0` && pwd)
LD_PRELOAD=$ABS_PATH/../build/libkiller.so $@

