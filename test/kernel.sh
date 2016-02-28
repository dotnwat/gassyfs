#!/bin/bash
set -e
set -x

DIR=linux-4.4.3
curl -O https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.4.3.tar.xz
tar xf linux-4.4.3.tar.xz
pushd $DIR

make allmodconfig
make -j20
make distclean

make allyesconfig
make -j20
make distclean

popd
rm -rf $DIR
rm linux-4.4.3.tar.xz
