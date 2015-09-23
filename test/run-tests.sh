#!/bin/env bash

set -e
set -x

#
#
#
mkdir rocksdb_test
TESTDIR=$PWD/rocksdb_test
git clone http://github.com/facebook/rocksdb.git
pushd rocksdb
git checkout rocksdb-3.12.1
make -j10 all
TEST_TMPDIR=$TESTDIR make check
popd
rm -rf rocksdb
rm -rf rocksdb_test

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
