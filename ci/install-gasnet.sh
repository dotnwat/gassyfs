#!/bin/bash

set -x
set -e

pushd /tmp

curl -O https://gasnet.lbl.gov/GASNet-1.26.0.tar.gz
tar xzvf GASNet-1.26.0.tar.gz
pushd GASNet-1.26.0
./configure --enable-udp --disable-mpi --prefix=/usr/local --enable-par --enable-segment-fast --disable-aligned-segments
make -j2
sudo make install
popd

popd
