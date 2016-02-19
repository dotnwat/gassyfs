#!/bin/bash

set -x
set -e

pushd /tmp

curl -O https://gasnet.lbl.gov/GASNet-1.26.0.tar.gz
tar xzvf GASNet-1.26.0.tar.gz
pushd GASNet-1.26.0

CONF_FLAGS="--enable-udp --disable-mpi --prefix=/usr/local \
  --enable-par --disable-aligned-segments"
if [ "$USE_GASNET_EVERYTHING" = "1" ]; then
  CONF_FLAGS="$CONF_FLAGS --enable-segment-everything"
else
  CONF_FLAGS="$CONF_FLAGS --enable-segment-large"
fi
./configure $CONF_FLAGS

make -j2
sudo make install
popd

popd
