#!/bin/bash

set -e
set -x
sleep 2
echo "What the hell, Jerry?" > mount/blah
./gassy-cmd mount/blah print_string
./gassy-cmd mount/blah setlua_atime policies/atime.lua
cat mount/blah
ls -alh --time=atime mount/blah  | grep Aug

echo "Success!!!"
