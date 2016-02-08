#include <map>
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

  typedef std::map<std::string, Inode*> dir_t;
  dir_t dentries;

  std::string link;

 private:
  fuse_ino_t ino_;
  long int ref_;
  std::vector<Block> blks_;
};
