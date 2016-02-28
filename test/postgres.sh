#!/bin/bash
set -e
set -x

DIR=postgresql-9.5.1
curl -O https://ftp.postgresql.org/pub/source/v9.5.1/postgresql-9.5.1.tar.gz
tar xzf postgresql-9.5.1.tar.gz
pushd $DIR

./configure
make -j10
make check

popd
rm -rf $DIR
rm postgresql-9.5.1.tar.gz
