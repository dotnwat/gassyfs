#!/bin/env bash

set -e
set -x

#
#
#
git clone http://github.com/facebook/rocksdb.git
pushd rocksdb
make -j5
######
# TMPD over-ride doesn't seem to work, so it will take
# some effort to get the working directory for check to
# be in our fuse mount.
####### make check
popd
rm -rf rocksdb

#
#
#
git clone https://github.com/torvalds/linux.git
pushd linux
make allmodconfig
make -j20
make distclean
make allyesconfig
make -j20
make distclean
popd
rm -rf linux

#
#
#
git clone --recursive https://github.com/ceph/ceph.git
pushd ceph
./install-deps.sh
./autogen.sh
./configure --with-debug
make -j10
popd
rm -rf ceph

#
#
#
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
echo $DIR
prove -r ${DIR}/pjd-fstest-20090130-RC/tests
