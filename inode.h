#ifndef GASSYFS_INODE_H_
#define GASSYFS_INODE_H_
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include "common.h"

class BlockAllocator;

class Inode {
 public:
  typedef std::shared_ptr<Inode> Ptr;

  Inode(time_t time, BlockAllocator *ba);
  virtual ~Inode();

  int set_capacity(off_t size, BlockAllocator *ba);

  void set_ino(fuse_ino_t ino);
  fuse_ino_t ino() const;

  std::vector<Block>& blocks();

  struct stat i_st;

  bool is_directory() const;
  bool is_symlink() const;

  bool lookup_get();
  bool lookup_put(long int dec);

 private:
  void free_blocks(BlockAllocator *ba);

  bool ino_set_;
  fuse_ino_t ino_;
  long int lookup_count_;
  BlockAllocator *ba_;
  std::vector<Block> blks_;
};

class DirInode : public Inode {
 public:
  typedef std::shared_ptr<DirInode> Ptr;
  typedef std::map<std::string, Inode::Ptr> dir_t;
  DirInode(time_t time, BlockAllocator *ba) : Inode(time, ba) {}
  dir_t dentries;
};

class SymlinkInode : public Inode {
 public:
  typedef std::shared_ptr<SymlinkInode> Ptr;
  SymlinkInode(time_t time, BlockAllocator *ba) : Inode(time, ba) {}
  std::string link;
};

#endif
