#include "inode.h"
#include <cassert>
#include <fuse.h>
#include "block_allocator.h"
#include "common.h"

Inode::Inode(fuse_ino_t ino, BlockAllocator *ba) :
    ino_(ino), lookup_count_(0), ba_(ba)
{
  memset(&i_st, 0, sizeof(i_st));
}

Inode::~Inode()
{
  free_blocks(ba_);
}

bool Inode::lookup_get()
{
  assert(lookup_count_ >= 0);
  lookup_count_++;
  return lookup_count_ == 1;
}

bool Inode::lookup_put(long int dec)
{
  assert(lookup_count_);
  lookup_count_ -= dec;
  assert(lookup_count_ >= 0);
  return lookup_count_ == 0;
}

int Inode::set_capacity(off_t size, BlockAllocator *ba)
{
  while ((blks_.size()*BLOCK_SIZE) < (unsigned long)size) {
    Block b;
    int ret = ba->GetBlock(&b);
    if (ret)
      return ret;
    blks_.push_back(b);
  }
  return 0;
}

void Inode::free_blocks(BlockAllocator *ba)
{
  for (auto &blk : blks_)
    ba->ReturnBlock(blk);
  blks_.clear();
}

fuse_ino_t Inode::ino() const
{
  return ino_;
}

std::vector<Block>& Inode::blocks()
{
  return blks_;
}

bool Inode::is_directory() const
{
  return i_st.st_mode & S_IFDIR;
}

bool Inode::is_symlink() const
{
  return i_st.st_mode & S_IFLNK;
}
