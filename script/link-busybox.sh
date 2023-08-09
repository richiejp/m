#!/bin/sh -eu

rootdir=$(realpath $1)
path_or_name=$2
path=

if [ -f $path_or_name ]; then
        path=$(realpath $path_or_name)
else
        path=$(whereis -b $path_or_name | awk '{ print $2 }')
fi

for cmd in $(busybox --list); do
        ln -svf $path $rootdir/bin/$cmd
done
