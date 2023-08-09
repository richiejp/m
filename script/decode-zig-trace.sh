#!/bin/sh -eu

exe=$1

while read line; do
        llvm-addr2line --color --functions --pretty-print --relativenames --obj=$exe \
                       $(grep -E -o '0x\w+')
done
