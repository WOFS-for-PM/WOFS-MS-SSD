#!/usr/bin/env bash

ABS_PATH=$(cd `dirname $0` && pwd)

export TARGET_TEST_PROG="tests/test"
LD_PRELOAD=$ABS_PATH/../build/libkiller.so $@

