#!/bin/bash
set -e
set -x

pushd `dirname $0` > /dev/null
TEST_DIR=`pwd`
popd > /dev/null

FSTEST_DIR=$TEST_DIR/pjd-fstest-20090130-RC
pushd $FSTEST_DIR
make
popd

mkdir fstest
pushd fstest
sudo prove -r $FSTEST_DIR/tests/
popd
sudo rm -rf fstest
