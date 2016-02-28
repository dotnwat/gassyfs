#!/bin/bash
set -e
set -x

DIR=ceph
git clone --branch=v10.0.3 --recursive \
  https://github.com/ceph/ceph.git $DIR
pushd $DIR

./install-deps.sh
./autogen.sh
./configure --with-debug --with-librocksdb-static
make -j10

popd
rm -rf $DIR
