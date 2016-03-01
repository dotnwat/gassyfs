gassyfs - distributed in-memory file system over RDMA
=======

[![Build Status](https://travis-ci.org/noahdesu/gassyfs.svg?branch=master)](https://travis-ci.org/noahdesu/gassyfs) [![license](https://img.shields.io/badge/license-LGPLv2.1-blue.svg)](https://raw.githubusercontent.com/noahdesu/gassyfs/master/LICENSE)

GassyFS is a [FUSE](http://fuse.sourceforge.net/)-based file system that
stores data in distributed remote memory. Remote memory is managed and
accessed using [GASNet](http://gasnet.lbl.gov/), which supports
[RDMA](http://en.wikipedia.org/wiki/Remote_direct_memory_access) over a wide
variety of high-performance network interconnects, as well as supporting
slower network access methods such as UDP that are useful for development. The
Gassy file system is intended to be used in a manner analagous to
[tmpfs](http://en.wikipedia.org/wiki/Tmpfs), but when the amount of RAM needed
exceeds that of a single node.

# Testing

The file system is regularly tested with a variety of workloads. The following
workloads are tested for each travis-ci.org build:

* Run the Tuxera POSIX test suite (test/posix.sh)
* Build Git and run unit tests (test/git.sh)
* samtools

An additional set of larger workloads (in addition to those listed above) are
run prior to each release:

* Build the Linux kernel (test/kernel.sh)
* Build the Ceph storage system (test/ceph.sh)
* Multiple configurations of iozone (test/iozone.sh)
* Build PostgreSQL and run tests (test/postgres.sh)
* Build RocksDB and run tests (test/rocksdb.sh)
