#include "inode_index.h"

void InodeIndex::add(Inode::Ptr inode)
{
  assert(refs_.find(inode->ino()) == refs_.end());
  assert(inode->lookup_get());
  refs_[inode->ino()] = inode;
}

void InodeIndex::get(Inode::Ptr inode)
{
  auto it = refs_.find(inode->ino());
  if (inode->lookup_get()) {
    assert(it == refs_.end());
    refs_[inode->ino()] = inode;
  } else
    assert(it != refs_.end());
}

void InodeIndex::put(fuse_ino_t ino, long int dec)
{
  auto it = refs_.find(ino);
  assert(it != refs_.end());
  if (it->second->lookup_put(dec))
    refs_.erase(it);
}

Inode::Ptr InodeIndex::inode(fuse_ino_t ino)
{
  return refs_.at(ino);
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
    if (it->second->i_st.st_mode & S_IFREG)
      ret++;
  return ret;
}
