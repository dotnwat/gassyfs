#include "block_allocator.h"

BlockAllocator::BlockAllocator(gasnet_seginfo_t *segments, unsigned nsegments)
{
  total_bytes_ = 0;
  // FIXME: we don't really fill up the global address space at this point,
  // but it we need to be making sure that everything is aligned when we
  // approach the end of a segment.
  for (unsigned i = 0; i < nsegments; i++) {
    Node n;
    n.addr = (size_t)segments[i].addr;
    n.size = segments[i].size;
    n.curr = n.addr;
    nodes_.push_back(n);
    total_bytes_ += n.size;
  }
  curr_node = 0;
  num_nodes = nsegments;
  avail_bytes_ = total_bytes_;
}

int BlockAllocator::GetBlock(Block *bp)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (!free_blks_.empty()) {
    Block b = free_blks_.front();
    free_blks_.pop_front();
    *bp = b;
    avail_bytes_ -= BLOCK_SIZE;
    return 0;
  }

  // node we are allocating from
  Node& n = nodes_[curr_node];

  Block bb;
  bb.node = curr_node;
  bb.addr = n.curr;
  bb.size = BLOCK_SIZE;

  n.curr += BLOCK_SIZE;
  if (n.curr >= (n.addr + n.size))
    return -ENOSPC;

  // next node to allocate from
  curr_node = (curr_node + 1) % num_nodes;

  *bp = bb;
  avail_bytes_ -= BLOCK_SIZE;
  return 0;
}

void BlockAllocator::ReturnBlock(Block b)
{
  std::lock_guard<std::mutex> l(mutex_);
  free_blks_.push_back(b);
  avail_bytes_ += BLOCK_SIZE;
}

uint64_t BlockAllocator::total_bytes()
{
  std::lock_guard<std::mutex> l(mutex_);
  return total_bytes_;
}

uint64_t BlockAllocator::avail_bytes()
{
  std::lock_guard<std::mutex> l(mutex_);
  return avail_bytes_;
}
