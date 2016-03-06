#!/bin/bash
set -e
set -x

CACHE_DIR=/tmp/gassyfs-cache/git
mkdir -p `dirname $CACHE_DIR`

if [ ! -d "$CACHE_DIR" ]; then
  git clone --branch=v2.7.1 git://github.com/git/git.git $CACHE_DIR
fi

DIR=git
cp -a $CACHE_DIR $DIR
pushd $DIR

make -j5
NO_UNIX_SOCKETS=1 make test

popd
rm -rf $DIR
