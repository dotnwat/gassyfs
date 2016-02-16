#ifndef GASSYFS_BLOCK_ALLOCATOR_H_
#define GASSYFS_BLOCK_ALLOCATOR_H_
#include <deque>
#include <mutex>
#include <vector>
#include <gasnet.h>
#include "common.h"
#include "address_space.h"

/*
 * Block Allocation
 *
 * The entire GASNet address space is divided into fixed size blocks. New
 * blocks are allocated from a free list, otherwise new blocks are assigned in
 * round-robin across all GASNet segments.
 */
class BlockAllocator {
 public:
  BlockAllocator(AddressSpace *storage);

  int GetBlock(Block *bp);

  void ReturnBlock(Block b);

  uint64_t total_bytes();

  uint64_t avail_bytes();

 private:
  struct Node {
    size_t addr;
    size_t size;
    size_t curr;
    int node;
  };

  std::deque<Block> free_blks_;
  unsigned curr_node, num_nodes;
  std::vector<Node> nodes_;

  uint64_t total_bytes_;
  uint64_t avail_bytes_;

  std::mutex mutex_;
};

#endif
