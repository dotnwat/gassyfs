#!/bin/bash

set -x
set -e


if [ -d "/usr/include/lua5.2" ]; then
  LUA_CPPFLAGS=/usr/include/lua5.2 GASNET=/usr/local make
else
  GASNET=/usr/local make
fi
