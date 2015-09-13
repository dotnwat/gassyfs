#!/bin/sh
# $FreeBSD: src/tools/regression/fstest/tests/rmdir/02.t,v 1.1 2007/01/17 01:42:11 pjd Exp $

desc="rmdir returns ENAMETOOLONG if a component of a pathname exceeded 255 characters"

dir=`dirname $0`
. ${dir}/../misc.sh

echo "1..3"

expect 0 mkdir ${name255} 0755
expect 0 rmdir ${name255}
expect ENOENT rmdir ${name255}
# not sure how to do this yet because it appears enoent is return suggesting
# there is a check before we get to rmdir where the length check is currently
# implemented.
#expect ENAMETOOLONG rmdir ${name256}
