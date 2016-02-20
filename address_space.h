#ifndef GASSYFS_ADDRESS_SPACE_H_
#define GASSYFS_ADDRESS_SPACE_H_
#include <cstddef>
#include <vector>
#include "common.h"

/*
 * A node is a single linearly addressable region that supports random read /
 * write operations (e.g. a GASNet node). The address space exposed by a node
 * is physically located on a single host.
 */
class Node {
 public:
  virtual size_t size() = 0;
  virtual void read(void *dst, void *src, size_t len) = 0;
  virtual void write(void *dst, void *src, size_t len) = 0;
};

/*
 * An address space is a set of nodes.
 */
class AddressSpace {
 public:
  virtual std::vector<Node*>& nodes() = 0;
};

class LocalAddressSpace : public AddressSpace {
 public:
  int init(struct gassyfs_opts *opts);

  std::vector<Node*>& nodes() {
    return nodes_;
  }

 private:
  std::vector<Node*> nodes_;
};

class GASNetAddressSpace : public AddressSpace {
 public:
  int init(int *argc, char ***argv, struct gassyfs_opts *opts);

  std::vector<Node*>& nodes() {
    return nodes_;
  }

 private:
  std::vector<Node*> nodes_;
};

#endif
