#ifndef GASSYFS_ADDRESS_SPACE_H_
#define GASSYFS_ADDRESS_SPACE_H_
#include <cstddef>
#include <string>
#include <vector>

struct gassyfs_opts;

/*
 * A node is a single linearly addressable region that supports random read /
 * write operations (e.g. a GASNet node). The address space exposed by a node
 * is physically located on a single host.
 */
class Node {
 public:
  typedef void* group_io_handle_t;

  virtual int id() = 0;

  // valid address space: [0, size)
  virtual size_t size() = 0;

  // synchronous
  virtual void read(void *dst, void *src, size_t len) = 0;
  virtual void write(void *dst, void *src, size_t len) = 0;

  virtual void aio_read(group_io_handle_t handle, void *dst,
      void *src, size_t len) = 0;
  virtual void aio_write(group_io_handle_t handle, void *dst,
      void *src, size_t len) = 0;

  // durability
  virtual void checkpoint(const std::string& checkpoint_id) = 0;
  virtual void restore(const std::string& checkpoint_id, int *prev_id) = 0;
};

/*
 * An address space is a set of nodes.
 */
class AddressSpace {
 public:
  virtual std::vector<Node*>& nodes() = 0;

  // aio
  virtual Node::group_io_handle_t group_io_start() = 0;
  virtual void group_io_wait(Node::group_io_handle_t handle) = 0;
};

class LocalAddressSpace : public AddressSpace {
 public:
  int init(struct gassyfs_opts *opts);

  std::vector<Node*>& nodes() {
    return nodes_;
  }

  Node::group_io_handle_t group_io_start();
  void group_io_wait(Node::group_io_handle_t handle);

 private:
  std::vector<Node*> nodes_;
};

class GASNetAddressSpace : public AddressSpace {
 public:
  int init(int *argc, char ***argv, struct gassyfs_opts *opts);

  std::vector<Node*>& nodes() {
    return nodes_;
  }

  Node::group_io_handle_t group_io_start();
  void group_io_wait(Node::group_io_handle_t handle);

 private:
  std::vector<Node*> nodes_;
};

#endif
