gassyfs - distributed in-memory file system over RDMA
=======

[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/noahdesu/gassyfs/master/LICENSE)

GassyFS is a [FUSE](http://fuse.sourceforge.net/)-based file system that stores data in distributed remote memory. Remote memory is managed and accessed using [GASNet](http://gasnet.lbl.gov/), which supports [RDMA](http://en.wikipedia.org/wiki/Remote_direct_memory_access) over a wide variety of high-performance network interconnects, as well as supporting slower network access methods such as UDP that are useful for development. The Gassy file system is intended to be used in a manner analagous to [tmpfs](http://en.wikipedia.org/wiki/Tmpfs), when the amount of RAM needed exceeds that of a single node.

# Testing

```bash
git clone http://github.com/facebook/rocksdb.git
cd rocksdb
make -j5
make check
```
