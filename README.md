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

The file system is regularly tested with the following workloads.

```bash
git clone http://github.com/facebook/rocksdb.git
cd rocksdb
make -j5
make check
```

```bash
git clone https://github.com/torvalds/linux.git
cd linux
make allmodconfig
make -j20
make distclean
make allyesconfig
make -j20
make distclean
```

```bash
iozone -a
```

```bash
git clone --recursive https://github.com/ceph/ceph.git
cd ceph
./autogen.sh
./configure --with-debug
make -j10
```
