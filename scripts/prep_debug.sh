#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$script_dir"/.. || exit

make clean
make DEBUG=1 -j"$(nproc)"

cd - || exit
