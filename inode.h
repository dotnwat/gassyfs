#ifndef GASSYFS_INODE_H_
#define GASSYFS_INODE_H_
#include <map>
#include <memory>
#include <vector>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include "common.h"

class BlockAllocator;

class Inode {
 public:
  typedef std::shared_ptr<Inode> Ptr;

  explicit Inode(fuse_ino_t ino);

  void get();

  bool put(long int dec = 1);

  int set_capacity(off_t size, BlockAllocator *ba);

  void free_blocks(BlockAllocator *ba);

  fuse_ino_t ino() const;

  std::vector<Block>& blocks();

  struct stat i_st;

  bool is_directory() const;
  bool is_symlink() const;

 private:
  fuse_ino_t ino_;
  long int ref_;
  std::vector<Block> blks_;
};

class DirInode : public Inode {
 public:
  typedef std::shared_ptr<DirInode> Ptr;
  typedef std::map<std::string, Inode::Ptr> dir_t;
  explicit DirInode(fuse_ino_t ino) : Inode(ino) {}
  dir_t dentries;
};

class SymlinkInode : public Inode {
 public:
  typedef std::shared_ptr<SymlinkInode> Ptr;
  explicit SymlinkInode(fuse_ino_t ino) : Inode(ino) {}
  std::string link;
};

#endif
