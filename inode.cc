#include "inode.h"
#include <cassert>
#include <fuse.h>
#include "block_allocator.h"
#include "common.h"

Inode::Inode(time_t time, uid_t uid, gid_t gid,
    blksize_t blksize, BlockAllocator *ba) :
    ino_set_(false), lookup_count_(0), ba_(ba)
{
  memset(&i_st, 0, sizeof(i_st));

  i_st.st_atime = time;
  i_st.st_mtime = time;
  i_st.st_ctime = time;

  i_st.st_uid = uid;
  i_st.st_gid = gid;

  i_st.st_blksize = blksize;

  // DirInode will set this to 2
  i_st.st_nlink = 1;
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

void Inode::set_ino(fuse_ino_t ino)
{
  assert(ino_set_ == false);
  ino_ = ino;
  i_st.st_ino = ino;
  ino_set_ = true;
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
  assert(ino_set_);
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
