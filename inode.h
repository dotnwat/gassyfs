#include <map>
#include <mutex>
#include <vector>

#include <fuse.h>
#include <fuse_lowlevel.h>

#include "common.h"

class BlockAllocator;

class Inode {
 public:
  explicit Inode(fuse_ino_t ino);

  void get();

  bool put(long int dec = 1);

  int set_capacity(off_t size, BlockAllocator *ba);

  void free_blocks(BlockAllocator *ba);

  fuse_ino_t ino() const;

  std::vector<Block>& blocks();

  struct stat i_st;
  off_t size;

  bool is_directory() const;
  bool is_symlink() const;

  void lock() {
    mutex_.lock();
  }

  bool try_lock() {
    return mutex_.try_lock();
  }

  void unlock() {
    mutex_.unlock();
  }

 private:
  fuse_ino_t ino_;
  long int ref_;
  std::vector<Block> blks_;
  std::mutex mutex_;
};

class DirInode : public Inode {
 public:
  typedef std::map<std::string, Inode*> dir_t;
  explicit DirInode(fuse_ino_t ino) : Inode(ino) {}
  dir_t dentries;
};

class SymlinkInode : public Inode {
 public:
  explicit SymlinkInode(fuse_ino_t ino) : Inode(ino) {}
  std::string link;
};
