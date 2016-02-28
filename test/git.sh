#!/bin/bash
set -e
set -x

DIR=git
git clone --branch=v2.7.1 git://github.com/git/git.git $DIR
pushd $DIR

make -j5
NO_UNIX_SOCKETS=1 make test

popd
rm -rf $DIR
