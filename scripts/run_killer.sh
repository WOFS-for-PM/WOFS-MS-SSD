#!/usr/bin/env bash

ABS_PATH=$(cd $(dirname $0) && pwd)

# TODO: correct path to your test program
export TARGET_TEST_PROG="fio"
export KILLER_PARAMS="init"
LD_PRELOAD=$ABS_PATH/../build/libkiller.so $@
