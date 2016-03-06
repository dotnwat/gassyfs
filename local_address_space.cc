#include "address_space.h"
#include <cassert>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
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

  void checkpoint(const std::string& checkpoint_id);

 private:
  int id_;
  char *base_;
  uintptr_t size_;
};

void LocalNodeImpl::checkpoint(const std::string& checkpoint_id)
{
  /*
   * ensure a directory exists to store the checkpoint. each node uses a
   * directory with the path /checkpoint/path/node-{id}/.
   *
   * TODO:
   *  - configurable paths
   *  - directory creation is buggy/racy
   */
  char nodedir[PATH_MAX];
  sprintf(nodedir, "/home/nwatkins/gassyfs-checkpoint/node-%d", id());

  int ret = mkdir(nodedir, 0775);
  if (ret && errno != EEXIST) {
    perror("mkdir");
    assert(0);
  }

  /*
   * create file to store checkpoint
   */
  char cp_bin_path[PATH_MAX];
  sprintf(cp_bin_path, "%s/%s.bin", nodedir, checkpoint_id.c_str());

  int fd = open(cp_bin_path, O_RDWR | O_CREAT | O_EXCL, 0660);
  if (fd < 0) {
    perror("open");
    assert(0);
  }

#if 0
  fallocate(fd, 0, 0, size());
  lseek(fd, 0, SEEK_SET);

  char *cur = base_;
  size_t left = size();

  while (left) {
    size_t done = std::min(left, 1ULL<<30);
    ssize_t ret = write(fd, cur, done);
    if (ret < 0) {
      perror("write");
      assert(0);
    }
    left -= ret;
    cur += ret;
  }
#else
  ret = ftruncate(fd, (off_t)size());
  if (ret) {
    perror("ftruncate");
    assert(0);
  }

  void *bin_map = mmap(0, size(), PROT_WRITE, MAP_SHARED, fd, 0);
  assert(bin_map != MAP_FAILED);

  memcpy(bin_map, base_, size());

  ret = msync(bin_map, size(), MS_SYNC);
  if (ret) {
    perror("msync");
    assert(0);
  }

  munmap(bin_map, size());

  fsync(fd);
  close(fd);
#endif
}

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
