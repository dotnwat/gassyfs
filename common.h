#ifndef COMMON_H
#define COMMON_H
#include <gasnet.h>
#include "address_space.h"
#include "alloc.h"

#define GASNET_SAFE(fncall) do {                                     \
    int _retval;                                                     \
    if ((_retval = fncall) != GASNET_OK) {                           \
      fprintf(stderr, "ERROR calling: %s\n"                          \
                      " at: %s:%i\n"                                 \
                      " error: %s (%s)\n",                           \
              #fncall, __FILE__, __LINE__,                           \
              gasnet_ErrorName(_retval), gasnet_ErrorDesc(_retval)); \
      fflush(stderr);                                                \
      gasnet_exit(_retval);                                          \
      exit(_retval);                                                 \
    }                                                                \
  } while(0)

struct gassyfs_opts {
  int rank0_alloc;
  int local_mode;
  size_t heap_size;
  int local_parts;
};

struct NodeAlloc {
  NodeAlloc(Node *n) :
    node(n), alloc(new Allocator(n->size()))
  {}

  Node *node;
  Allocator *alloc;
};

struct Extent {
  // logical
  size_t length;

  // physical
  NodeAlloc *node;
  size_t addr;
  size_t size;
};

#endif
