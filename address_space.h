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

  int init(int *argc, char ***argv);

  void write(int node, void *dst, void *src, size_t len);
  void read(void *dest, int node, void *src, size_t len);

  std::vector<Node> nodes;
};

#endif
