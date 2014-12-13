gassyfs - distributed memory filesystem
=======

GassyFS is a FUSE-based filesystem that stores all file data in distributed memory. Remote memory is managed and accessed using GASNet which supports RDMA over a wide variety of high-performance network interconnects. The Gassy filesystem is entirely in-memory; it is intended to be used in a similar manner to that of tmpfs.
