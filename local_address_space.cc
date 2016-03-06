#include "address_space.h"
#include <cassert>
#include <sys/mman.h>
#include <gasnet.h>
#include <iostream>
#include "common.h"

class LocalNodeImpl : public Node {
 public:
  LocalNodeImpl(int id, void *base, uintptr_t size) :
    id_(id), base_((char*)base), size_(size)
  {
#if 0
    std::cout << "local mem: base=" << base
      << " size=" << size << std::endl;
#endif
  }

  int id() {
    return id_;
  }

  size_t size() {
    return size_;
  }

  void read(void *dst, void *src, size_t len) {
    char *abs_src = base_ + (uintptr_t)src;
    assert((abs_src + len - 1) < (base_ + size_));
    memcpy(dst, abs_src, len);
  }

  void write(void *dst, void *src, size_t len) {
    char *abs_dst = base_ + (uintptr_t)dst;
    assert((abs_dst + len - 1) < (base_ + size_));
    memcpy(abs_dst, src, len);
  }

  void aio_read(group_io_handle_t handle, void *dst, void *src, size_t len) {
    return read(dst, src, len);
  }

  void aio_write(group_io_handle_t handle, void *dst, void *src, size_t len) {
    return write(dst, src, len);
  }

 private:
  int id_;
  char *base_;
  uintptr_t size_;
};

int LocalAddressSpace::init(struct gassyfs_opts *opts)
{
  const size_t size = opts->heap_size << 20;

  for (int i = 0; i < opts->local_parts; i++) {
    void *data = mmap(NULL, size, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (data == MAP_FAILED)
      return -ENOMEM;

    LocalNodeImpl *node = new LocalNodeImpl(i, data, size);
    nodes_.push_back(node);
  }

  opts->rank0_alloc = 1;

  return 0;
}

/*
 * local mode aio becomes synchronous (i.e. memcpy)
 */
Node::group_io_handle_t LocalAddressSpace::group_io_start()
{
  return NULL;
}

void LocalAddressSpace::group_io_wait(Node::group_io_handle_t handle)
{
}
