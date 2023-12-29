#!/usr/bin/env bash
ps=$(ps -ef | grep make | grep deadpool | grep ci-test)
if [ -n "$ps" ]; then
    echo "kill deadpool ci-test"
    ps -ef | grep make | grep deadpool | grep ci-test | awk '{print $2}' | xargs kill -9
fi
