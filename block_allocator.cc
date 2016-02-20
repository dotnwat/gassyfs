#include "block_allocator.h"

BlockAllocator::BlockAllocator(AddressSpace *storage)
{
  total_bytes_ = 0;

  for (Node *node : storage->nodes()) {
    NodeAlloc node_alloc;
    node_alloc.node = node;
    node_alloc.curr = 0;
    total_bytes_ += node->size();
    nodes_.push_back(node_alloc);
  }

  curr_node = 0;
  num_nodes = nodes_.size();
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
  NodeAlloc& n = nodes_[curr_node];

  Block bb;
  bb.node = n.node;
  bb.addr = n.curr;
  bb.size = BLOCK_SIZE;

  n.curr += BLOCK_SIZE;
  if (n.curr >= n.node->size())
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
