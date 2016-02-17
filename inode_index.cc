#include "inode_index.h"
#include <cassert>

void InodeIndex::add(Inode::Ptr inode)
{
  assert(refs_.find(inode->ino()) == refs_.end());
  refs_[inode->ino()] = std::make_pair(1, inode);
}

void InodeIndex::get(Inode::Ptr inode)
{
  auto it = refs_.find(inode->ino());
  if (it == refs_.end())
    refs_[inode->ino()] = std::make_pair(1, inode);
  else {
    assert(it->second.first > 0);
    it->second.first++;
  }
}

void InodeIndex::put(fuse_ino_t ino, long int dec)
{
  auto it = refs_.find(ino);
  assert(it != refs_.end());
  assert(it->second.first > 0);
  it->second.first -= dec;
  assert(it->second.first >= 0);
  if (it->second.first == 0)
    refs_.erase(it);
}

Inode::Ptr InodeIndex::inode(fuse_ino_t ino)
{
  return refs_.at(ino).second;
}

DirInode::Ptr InodeIndex::dir_inode(fuse_ino_t ino)
{
  auto in = inode(ino);
  assert(in->is_directory());
  return std::static_pointer_cast<DirInode>(in);
}

SymlinkInode::Ptr InodeIndex::symlink_inode(fuse_ino_t ino)
{
  auto in = inode(ino);
  assert(in->is_symlink());
  return std::static_pointer_cast<SymlinkInode>(in);
}

uint64_t InodeIndex::nfiles()
{
  uint64_t ret = 0;
  for (auto it = refs_.begin(); it != refs_.end(); it++)
    if (it->second.second->i_st.st_mode & S_IFREG)
      ret++;
  return ret;
}
