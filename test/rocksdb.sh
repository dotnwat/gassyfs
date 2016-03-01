#!/bin/bash
#
# make sure to have libgflags-dev installed
#
set -e
set -x

DIR=rocksdb
git clone --branch=v4.2 \
  http://github.com/facebook/rocksdb.git $DIR
pushd $DIR

make -j10 all

TESTDIR=../testtmpdir
mkdir $TESTDIR
pushd $TESTDIR
TESTDIR=`pwd`
popd

TEST_TMPDIR=$TESTDIR make check

popd
rm -rf $DIR
rm -rf $TESTDIR
