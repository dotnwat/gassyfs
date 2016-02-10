#!/bin/bash

git clone git://github.com/git/git.git
pushd git
make -j5
NO_UNIX_SOCKETS=1 make test
popd
