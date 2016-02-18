#ifndef GASSYFS_ADDRESS_SPACE_H_
#define GASSYFS_ADDRESS_SPACE_H_
#include <cstddef>
#include <vector>

class AddressSpace {
 public:
  struct Segment {
    size_t addr;
    size_t len;
  };

  struct Node {
    Segment segment;
    int node;
  };

  virtual int init(int *argc, char ***argv) = 0;
  virtual void write(int node, void *dst, void *src, size_t len) = 0;
  virtual void read(void *dest, int node, void *src, size_t len) = 0;

  std::vector<Node> nodes;
};

class GasnetAddressSpace : public AddressSpace {
 public:
  virtual int init(int *argc, char ***argv);
  virtual void write(int node, void *dst, void *src, size_t len);
  virtual void read(void *dest, int node, void *src, size_t len);
};

class LocalAddressSpace : public AddressSpace {
 public:
  virtual int init(int *argc, char ***argv);
  virtual void write(int node, void *dst, void *src, size_t len);
  virtual void read(void *dest, int node, void *src, size_t len);
};

#endif
