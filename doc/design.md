# I/O Parallelism

We assume that FUSE will _not_ serialize I/O each file, but we do not optimize
for this case because at the time this is being written it appears that FUSE
does serialize I/O to each file. Instead, we add our own file-level I/O
serialization and log a message if we notice any attempt to perform parallel
I/O. There seems to be interest in supporting parallel I/O by the FUSE
developers:

  https://github.com/libfuse/libfuse/wiki/TODO-List

Given the restriction in GASNet that non-blocking I/O be initiated and
synchronized by the same thread (see below), we select to instead perform
blocking I/O, and allow I/O parallelism across files. If non-blocking I/O
becomes an important feature, we would want to look at having dedicated I/O
threads or some how have control over threads driving the FUSE request loop.

## GASNet I/O Notes

The GASNet API provides blocking and non-blocking I/O, and can support
parallel I/O when compiled with support.

The blocking API allows multiple threads to run concurrently, and there are
versions for aligned and unaligned requests.

The non-blocking API requires that the same thread that initiates I/O also
synchronizes on the completion.

The non-blocking API can re-order and coalesce operations with respect to o
ther blocking or non-blocking operations, or operations initiated by other
threads. It is unclear if it is safe to have non-blocking operations that do
not overlap.

Overlapping I/O for blocking and non-blocking I/O is undefined.

# Locking

todo: move allocations outside locking
todo: move string length checks outside locking

BlockAllocator
- internal locking

GassyFs::mutex
- file system state
- inode structure (except block list)
- held during put_inode, which will release blocks

The top-level mutex will protect all metadata except inode block lists and
file i/o, which will be done holding only a per-inode lock.

Open--truncate
Truncate, Write, WRiteBuf, Read
SetAttr--truncate
