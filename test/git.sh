#!/bin/bash

git clone --branch=v2.7.1 git://github.com/git/git.git
pushd git
make -j5
NO_UNIX_SOCKETS=1 make test
popd
