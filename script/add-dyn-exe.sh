#!/bin/sh -eu

help="$0 [-i] <initrd-root> <exe>"

while getopts ':ih' opt; do
        case $opt in
                i)
                        is_init=true
                        ;;
                h)
                        echo $help >&2
                        exit 0
                        ;;
                \?)
                        echo "-$OPTARG unknown" >&2
                        echo $help >&2
                        exit 1
                        ;;
        esac
done

shift $((OPTIND - 1))

if [ $# -lt 2 ]; then
        echo "Expected 2 arguments got $#" >&2
        echo $help >&2
        exit 1
fi

rootdir=$(realpath $1)
path_or_name=$2
path=

if [ -f $path_or_name ]; then
        path=$(realpath $path_or_name)
else
        path=$(whereis -b $path_or_name | awk '{ print $2 }')
fi

if [ ! -f $path ]; then
        echo "Could not resolve $path_or_name to a file (got $path)"
        exit 1;
fi

libs=$(ldd $path | awk 'NF > 3 { print $3 }')

mkdir -p $rootdir$(dirname $path)
rsync --progress $path $rootdir$path
ln -fvs $rootdir$path $rootdir/bin/$(basename $path)

interp=$(readelf -p .interp $path | grep -o '/.*')
rsync --progress $interp $rootdir$interp

if [ $is_init ]; then
        ln -fvs $rootdir$path $rootdir/init
fi

for lib in $libs; do
        mkdir -p $rootdir$(dirname $lib)
        rsync --progress $lib $rootdir/$lib
done