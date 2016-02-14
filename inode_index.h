#ifndef GASSYFS_INODE_INDEX_H_
#define GASSYFS_INODE_INDEX_H_
#include <cassert>
#include <unordered_map>
#include <fuse.h>
#include "inode.h"

class InodeIndex {
 public:
  void add(Inode::Ptr inode);
  void get(Inode::Ptr inode);
  void put(fuse_ino_t ino, long int dec);
  Inode::Ptr inode(fuse_ino_t ino);
  DirInode::Ptr dir_inode(fuse_ino_t ino);
  SymlinkInode::Ptr symlink_inode(fuse_ino_t ino);
  uint64_t nfiles();

 private:
  std::unordered_map<fuse_ino_t, Inode::Ptr> refs_;
};

#endif
