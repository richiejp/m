#!/bin/sh -eu

rootdir=$(realpath $1)

if [ -z $rootdir ]; then
        echo "Expected directory as first positional parameter"
        exit 1
fi

if [ ! -x $rootdir/init ]; then
        echo "Expected init executable in $rootdir"
        exit 1
fi

bname=$(basename $rootdir)
pdir=$(pwd)
cd $rootdir
find . | cpio -R 0:0 -v -H newc -o | gzip -n > ../$bname.cpio.gz
cd $pdir
