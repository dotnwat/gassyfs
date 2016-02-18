#!/bin/bash

set -x
set -e


if [ -d "/usr/include/lua5.2" ]; then
  cp policies/atime.lua /tmp/atime.lua
  LUA_CPPFLAGS=/usr/include/lua5.2 GASNET=/usr/local make
else
  GASNET=/usr/local make
fi
