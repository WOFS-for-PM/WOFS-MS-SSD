#!/usr/bin/env bash

function where_is_script() {
    local script=$1
    cd "$(dirname "$script")" && pwd
}

ABS_PATH=$(where_is_script "$0")

WAR="WOFS pipeline w/ read-modify-write, meta times: "         # write after read
WAW_INPLACE="WOFS pipeline w/ mem fence, inplace meta times: " # write after write inplace
WAD="WOFS pipeline w/ mem fence, meta times: "                 # write append
RAW="WOFS pipeline w/ io fence, meta times: "                  # read after write

TABLE_NAME="$ABS_PATH/performance-comparison-table"
TMP_PATH="$ABS_PATH/tmp"

function table_create() {
    local TABLE_NAME
    local COLUMNS
    TABLE_NAME=$1
    COLUMNS=$2
    echo "$COLUMNS" >"$TABLE_NAME"
}

function table_add_row() {
    local TABLE_NAME
    local ROW
    TABLE_NAME=$1
    ROW=$2
    echo "$ROW" >>"$TABLE_NAME"
}

table_create "$TABLE_NAME" "pattern meta_times bandwidth(GiB/s)"

loop=1
if [ "$1" ]; then
    loop=$1
fi

TARGETS=("$WAR" "$WAW_INPLACE" "$WAD" "$RAW")
TARGETS_NAME=("WAR" "WAW_INPLACE" "WAD" "RAW")

for ((i = 1; i <= loop; i++)); do
    ../build/stalls >"$TMP_PATH"
    TARGET_INDEX=0
    for target in "${TARGETS[@]}"; do
        for ((meta_times = 0; meta_times <= 9; meta_times++)); do
            MATCH="\[BENCH END\]: "$target$meta_times"\s"
            bw=$(cat "$TMP_PATH" | grep "$MATCH" | awk '{print $(NF-4)}')
            target_name=${TARGETS_NAME[$TARGET_INDEX]}
            table_add_row "$TABLE_NAME" "$target_name $meta_times $bw"
        done
        TARGET_INDEX=$((TARGET_INDEX + 1))
    done
done
