#include "inode.h"
#include <cassert>
#include <fuse.h>
#include "block_allocator.h"
#include "common.h"

Inode::Inode(fuse_ino_t ino) :
    ino_(ino), ref_(1)
{
  memset(&i_st, 0, sizeof(i_st));
}

void Inode::get()
{
  assert(ref_);
  ref_++;
}

bool Inode::put(long int dec)
{
  assert(ref_);
  ref_ -= dec;
  assert(ref_ >= 0);
  if (ref_ == 0)
    return false;
  return true;
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
