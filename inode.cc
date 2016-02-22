#include "inode.h"
#include <cassert>
#include <fuse.h>
#include "gassy_fs.h"
#include "common.h"

Inode::Inode(time_t time, uid_t uid, gid_t gid, blksize_t blksize,
    mode_t mode, GassyFs *fs) :
  alloc_node(0), ino_set_(false), fs_(fs)
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
  // Dir/Sym will set reset this
  i_st.st_mode = mode;
}

/*
 * FIXME: space should be freed here, but also when it is deleted, if there
 * are no other open file handles. Otherwise, space is only freed after the
 * file is deleted and the kernel releases its references.
 */
Inode::~Inode()
{
  for (auto it = extents_.begin(); it != extents_.end(); it++)
    fs_->free_space(&it->second);
  extents_.clear();
}

void Inode::set_ino(fuse_ino_t ino)
{
  assert(ino_set_ == false);
  ino_ = ino;
  i_st.st_ino = ino;
  ino_set_ = true;
}

fuse_ino_t Inode::ino() const
{
  assert(ino_set_);
  return ino_;
}

bool Inode::is_directory() const
{
  return i_st.st_mode & S_IFDIR;
}

bool Inode::is_symlink() const
{
  return i_st.st_mode & S_IFLNK;
}
