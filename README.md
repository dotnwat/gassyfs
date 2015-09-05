gassyfs - scale-out in-memory file system
=======

GassyFS is a non-persistent [FUSE](http://fuse.sourceforge.net/)-based filesystem that stores all data in distributed memory. Remote memory is managed and accessed using [GASNet](http://gasnet.lbl.gov/), which supports [RDMA](http://en.wikipedia.org/wiki/Remote_direct_memory_access) over a wide variety of high-performance network interconnects. The Gassy file system is intended to be used in a manner analagous to [tmpfs](http://en.wikipedia.org/wiki/Tmpfs).
