#!/bin/bash

export NUM_PROC="$(nproc)"

make clean
make

echo

./build/packet-storm
