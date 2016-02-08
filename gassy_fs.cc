#include "gassy_fs.h"
#include <cassert>
#include <cstring>
#include <string>
#include <iostream>
#include <time.h>
#include "inode.h"
#include "block_allocator.h"

/*
 *
 */
static inline std::time_t time_now(void)
{
  struct timespec ts;
  int ret = clock_gettime(CLOCK_REALTIME, &ts);
  assert(ret == 0);
  return ts.tv_sec;
}

GassyFs::GassyFs(BlockAllocator *ba) :
  next_ino_(FUSE_ROOT_ID + 1), ba_(ba)
{
  // setup root inode
  Inode *root = new Inode(FUSE_ROOT_ID);
  root->i_st.st_mode = S_IFDIR | 0755;
  root->i_st.st_nlink = 2;
  std::time_t now = time_now();
  root->i_st.st_atime = now;
  root->i_st.st_mtime = now;
  root->i_st.st_ctime = now;
  ino_to_inode_[root->ino()] = root;

  memset(&stat, 0, sizeof(stat));
  stat.f_fsid = 983983;
  stat.f_namemax = PATH_MAX;
  stat.f_bsize = 4096;
  stat.f_frsize = 4096;
  stat.f_blocks = ba_->total_bytes() / 4096;

  stat.f_files = 0;

  stat.f_bfree = stat.f_blocks;
  stat.f_bavail = stat.f_blocks;
}

int GassyFs::Create(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
    int flags, struct stat *st, FileHandle **fhp, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  /*
   * One reference for the name and one for the kernel inode cache. This
   * call also opens a file handle to the new file. However, it appears that
   * open does not take a reference on the in-kernel inode, so we shouldn't
   * need one here. The scenario that is of interest is removing a file that
   * is open.
   */
  Inode *in = new Inode(next_ino_++);
  in->get();

  children[name] = in;
  ino_to_inode_[in->ino()] = in;

  in->i_st.st_ino = in->ino();
  in->i_st.st_mode = S_IFREG | mode;
  in->i_st.st_nlink = 1;
  in->i_st.st_blksize = 4096;
  in->i_st.st_uid = uid;
  in->i_st.st_gid = gid;
  std::time_t now = time_now();
  in->i_st.st_atime = now;
  in->i_st.st_mtime = now;
  in->i_st.st_ctime = now;

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;

  FileHandle *fh = new FileHandle(in);
  *fhp = fh;

  return 0;
}

int GassyFs::GetAttr(fuse_ino_t ino, struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);
  *st = in->i_st;

  return 0;
}

int GassyFs::Unlink(fuse_ino_t parent_ino, const std::string& name, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t::const_iterator it = parent_in->dentries.find(name);
  if (it == parent_in->dentries.end())
    return -ENOENT;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  Inode *in = it->second;
  assert(in);
  assert(!(in->i_st.st_mode & S_IFDIR));

  if (parent_in->i_st.st_mode & S_ISVTX) {
    if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid)
      return -EPERM;
  }

  std::time_t now = time_now();
  in->i_st.st_ctime = now;

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  in->i_st.st_nlink--;

  parent_in->dentries.erase(it);

  put_inode(in->ino());

  return 0;
}

int GassyFs::Lookup(fuse_ino_t parent_ino, const std::string& name, struct stat *st)
{
  std::lock_guard<std::mutex> l(mutex_);

  // FIXME: should this be -ENOTDIR or -ENOENT in some cases?
  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);
  assert(parent_in->i_st.st_mode & S_IFDIR);

  Inode::dir_t::const_iterator it = parent_in->dentries.find(name);
  if (it == parent_in->dentries.end())
    return -ENOENT;

  Inode *in = it->second;
  assert(in);
  in->get();

  *st = in->i_st;

  return 0;
}

int GassyFs::Open(fuse_ino_t ino, int flags, FileHandle **fhp, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);

  int mode = 0;
  if ((flags & O_ACCMODE) == O_RDONLY)
    mode = R_OK;
  else if ((flags & O_ACCMODE) == O_WRONLY)
    mode = W_OK;
  else if ((flags & O_ACCMODE) == O_RDWR)
    mode = R_OK | W_OK;

  if (!(mode & W_OK) && (flags & O_TRUNC))
    return -EACCES;

  int ret = Access(in, mode, uid, gid);
  if (ret)
    return ret;

  if (flags & O_TRUNC) {
    ret = Truncate(in, 0, uid, gid);
    if (ret)
      return ret;
    std::time_t now = time_now();
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;
  }

  FileHandle *fh = new FileHandle(in);
  *fhp = fh;

  return 0;
}

void GassyFs::Release(fuse_ino_t ino) {}

void GassyFs::Forget(fuse_ino_t ino, long unsigned nlookup)
{
  std::lock_guard<std::mutex> l(mutex_);
  put_inode(ino, nlookup);
}

ssize_t GassyFs::Write(FileHandle *fh, off_t offset, size_t size, const char *buf)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = fh->in;
  ssize_t ret = Write(in, offset, size, buf);
  if (ret > 0)
    fh->pos += ret;

  return ret;
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
/*
 *
 */
ssize_t GassyFs::WriteBuf(FileHandle *fh, struct fuse_bufvec *bufv, off_t off)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = fh->in;

  size_t written = 0;

  for (size_t i = bufv->idx; i < bufv->count; i++) {
    struct fuse_buf *buf = bufv->buf + i;

    assert(!(buf->flags & FUSE_BUF_IS_FD));
    assert(!(buf->flags & FUSE_BUF_FD_RETRY));
    assert(!(buf->flags & FUSE_BUF_FD_SEEK));

    ssize_t ret;
    if (i == bufv->idx) {
      ret = Write(in, off, buf->size - bufv->off, (char*)buf->mem + bufv->off);
      if (ret < 0)
        return ret;
      assert(buf->size > bufv->off);
      if (ret < (ssize_t)(buf->size - bufv->off))
        return written;
    } else {
      ret = Write(in, off, buf->size, (char*)buf->mem);
      if (ret < 0)
        return ret;
      if (ret < (ssize_t)buf->size)
        return written;
    }
    off += ret;
    written += ret;
  }

  return written;
}
#endif

ssize_t GassyFs::Read(FileHandle *fh, off_t offset,
    size_t size, char *buf)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = fh->in;

  std::time_t now = time_now();
  in->i_st.st_atime = now;

  // reading past eof returns nothing
  if (offset >= in->i_st.st_size || size == 0)
    return 0;

  // read up until eof
  size_t left;
  if ((off_t)(offset + size) > in->i_st.st_size)
    left = in->i_st.st_size - offset;
  else
    left = size;

  const size_t new_n = left;

  char *dest = buf;
  while (left != 0) {
    size_t blkid = offset / BLOCK_SIZE;
    size_t blkoff = offset % BLOCK_SIZE;
    size_t done = std::min(left, BLOCK_SIZE-blkoff);

    const std::vector<Block>& blks = in->blocks();
    assert(blkid < blks.size());
    const Block& b = blks[blkid];
    gasnet_get_bulk(dest, b.node, (void*)(b.addr + blkoff), done);

    dest += done;
    offset += done;
    left -= done;
  }

  fh->pos += new_n;

  return new_n;
}

int GassyFs::Mkdir(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
    struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);
  
  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  Inode *in = new Inode(next_ino_++);
  in->get();

  in->i_st.st_uid = uid;
  in->i_st.st_gid = gid;
  in->i_st.st_ino = in->ino();
  in->i_st.st_mode = S_IFDIR | mode;
  in->i_st.st_nlink = 2;
  in->i_st.st_blksize = 4096;
  in->i_st.st_blocks = 1;
  std::time_t now = time_now();
  in->i_st.st_atime = now;
  in->i_st.st_mtime = now;
  in->i_st.st_ctime = now;

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;
  parent_in->i_st.st_nlink++;

  *st = in->i_st;

  children[name] = in;
  ino_to_inode_[in->ino()] = in;

  return 0;
}

int GassyFs::Rmdir(fuse_ino_t parent_ino, const std::string& name,
    uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = parent_in->dentries;
  Inode::dir_t::const_iterator it = children.find(name);
  if (it == children.end())
    return -ENOENT;

  Inode *in = it->second;
  if (!(in->i_st.st_mode & S_IFDIR))
    return -ENOTDIR;

  if (in->dentries.size())
    return -ENOTEMPTY;

  if (parent_in->i_st.st_mode & S_ISVTX) {
    if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid)
      return -EPERM;
  }

  children.erase(it);

  std::time_t now = time_now();
  parent_in->i_st.st_mtime = now;
  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_nlink--;

  put_inode(in->ino());

  return 0;
}

int GassyFs::Rename(fuse_ino_t parent_ino, const std::string& name,
    fuse_ino_t newparent_ino, const std::string& newname,
    uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (name.length() > NAME_MAX || newname.length() > NAME_MAX)
    return -ENAMETOOLONG;

  // old
  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& parent_children = parent_in->dentries;
  Inode::dir_t::const_iterator old_it = parent_children.find(name);
  if (old_it == parent_children.end())
    return -ENOENT;

  Inode *old_in = old_it->second;
  assert(old_in);

  // new
  Inode *newparent_in = inode_get(newparent_ino);
  assert(newparent_in);

  assert(newparent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& newparent_children = newparent_in->dentries;
  Inode::dir_t::const_iterator new_it = newparent_children.find(newname);

  Inode *new_in = NULL;
  if (new_it != newparent_children.end()) {
    new_in = new_it->second;
    assert(new_in);
  }

  /*
   * EACCES Write permission is denied for the directory containing oldpath or
   * newpath,
   *
   * (TODO) or search permission is denied for one of the directories in the
   * path prefix  of  old‐ path or newpath,
   *
   * or oldpath is a directory and does not allow write permission (needed
   * to update the ..  entry).  (See also path_resolution(7).) TODO: this is
   * implemented but what is the affect on ".." update?
   */
  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  ret = Access(newparent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  if (old_in->i_st.st_mode & S_IFDIR) {
    ret = Access(old_in, W_OK, uid, gid);
    if (ret)
      return ret;
  }

  /*
   * EPERM or EACCES The  directory  containing  oldpath  has the sticky bit
   * (S_ISVTX) set and the process's effective user ID is neither the user ID
   * of the file to be deleted nor that of the directory containing it, and
   * the process is not privileged (Linux: does not have the CAP_FOWNER
   * capability);
   *
   * or newpath is an existing file and the directory containing it has the
   * sticky bit set and the process's effective user ID is neither the user
   * ID of the  file to  be  replaced  nor that of the directory containing
   * it, and the process is not privileged (Linux: does not have the
   * CAP_FOWNER capability);
   *
   * or the filesystem containing pathname does not support renaming of the
   * type requested.
   */
  if (parent_in->i_st.st_mode & S_ISVTX) {
    if (uid && uid != old_in->i_st.st_uid && uid != parent_in->i_st.st_uid)
      return -EPERM;
  }

  if (new_in &&
      newparent_in->i_st.st_mode & S_ISVTX &&
      uid && uid != new_in->i_st.st_uid &&
      uid != newparent_in->i_st.st_uid) {
    return -EPERM;
  }


  if (new_in) {
    if (old_in->i_st.st_mode & S_IFDIR) {
      if (new_in->i_st.st_mode & S_IFDIR) {
        Inode::dir_t& new_children = new_in->dentries;
        if (new_children.size())
          return -ENOTEMPTY;
      } else
        return -ENOTDIR;
    } else {
      if (new_in->i_st.st_mode & S_IFDIR)
        return -EISDIR;
    }

    newparent_children.erase(new_it);

    put_inode(new_in->ino());
  }

  std::time_t now = time_now();
  old_in->i_st.st_ctime = now;

  newparent_children[newname] = old_it->second;
  parent_children.erase(old_it);

  return 0;
}

int GassyFs::SetAttr(fuse_ino_t ino, struct stat *attr, int to_set,
    uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);
  mode_t clear_mode = 0;

  Inode *in = inode_get(ino);
  assert(in);

  std::time_t now = time_now();

  if (to_set & FUSE_SET_ATTR_MODE) {
    if (uid && in->i_st.st_uid != uid)
      return -EPERM;

    if (uid && in->i_st.st_gid != gid)
      clear_mode |= S_ISGID;

    in->i_st.st_mode = attr->st_mode;
  }

  if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
    /*
     * Only  a  privileged  process  (Linux: one with the CAP_CHOWN capability)
     * may change the owner of a file.  The owner of a file may change the
     * group of the file to any group of which that owner is a member.  A
     * privileged process (Linux: with CAP_CHOWN) may change the group
     * arbitrarily.
     *
     * TODO: group membership for owner is not enforced.
     */
    if (uid && (to_set & FUSE_SET_ATTR_UID) &&
        (in->i_st.st_uid != attr->st_uid))
      return -EPERM;

    if (uid && (to_set & FUSE_SET_ATTR_GID) &&
        (uid != in->i_st.st_uid))
      return -EPERM;

    if (to_set & FUSE_SET_ATTR_UID)
      in->i_st.st_uid = attr->st_uid;

    if (to_set & FUSE_SET_ATTR_GID)
      in->i_st.st_gid = attr->st_gid;
  }

  if (to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_ATIME)) {
    if (uid && in->i_st.st_uid != uid)
      return -EPERM;

    if (to_set & FUSE_SET_ATTR_MTIME)
      in->i_st.st_mtime = attr->st_mtime;

    if (to_set & FUSE_SET_ATTR_ATIME)
      in->i_st.st_atime = attr->st_atime;
  }

  if (to_set & FUSE_SET_ATTR_SIZE) {
    if (uid) {
      int ret = Access(in, W_OK, uid, gid);
      if (ret)
        return ret;
    }

    // impose maximum size of 2TB
    if (attr->st_size > 2199023255552)
      return -EFBIG;

    int ret = Truncate(in, attr->st_size, uid, gid);
    if (ret < 0)
      return ret;

    in->i_st.st_mtime = now;
  }

  in->i_st.st_ctime = now;

  if (to_set & FUSE_SET_ATTR_MODE)
    in->i_st.st_mode &= ~clear_mode;

  *attr = in->i_st;

  return 0;
}

int GassyFs::Symlink(const std::string& link, fuse_ino_t parent_ino,
    const std::string& name, struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  // TODO: check length of link path components
  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  Inode *in = new Inode(next_ino_++);
  in->get();

  children[name] = in;
  ino_to_inode_[in->ino()] = in;

  in->link = link;

  in->i_st.st_ino = in->ino();
  in->i_st.st_mode = S_IFLNK;
  in->i_st.st_nlink = 1;
  in->i_st.st_blksize = 4096;
  in->i_st.st_uid = uid;
  in->i_st.st_gid = gid;
  std::time_t now = time_now();
  in->i_st.st_atime = now;
  in->i_st.st_mtime = now;
  in->i_st.st_ctime = now;
  in->i_st.st_size = link.length();

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;

  return 0;
}

ssize_t GassyFs::Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);
  assert(in->i_st.st_mode & S_IFLNK);

  size_t link_len = in->link.size();

  if (link_len > maxlen)
    return -ENAMETOOLONG;

  in->link.copy(path, link_len, 0);

  return link_len;
}

int GassyFs::Statfs(fuse_ino_t ino, struct statvfs *stbuf)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);

  uint64_t nfiles = 0;
  for (inode_table_t::const_iterator it = ino_to_inode_.begin();
      it != ino_to_inode_.end(); it++) {
    if (it->second->i_st.st_mode & S_IFREG)
      nfiles++;
  }

  stat.f_files = nfiles;
  stat.f_bfree = ba_->avail_bytes() / 4096;
  stat.f_bavail = ba_->avail_bytes() / 4096;

  *stbuf = stat;

  return 0;
}

int GassyFs::Link(fuse_ino_t ino, fuse_ino_t newparent_ino, const std::string& newname,
    struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (newname.length() > NAME_MAX)
    return -ENAMETOOLONG;


  Inode *newparent_in = inode_get(newparent_ino);
  assert(newparent_in);

  assert(newparent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = newparent_in->dentries;
  if (children.find(newname) != children.end())
    return -EEXIST;

  Inode *in = inode_get(ino);
  assert(in);

  if (in->i_st.st_mode & S_IFDIR)
    return -EPERM;

  int ret = Access(newparent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  in->get(); // for newname
  in->get(); // for kernel inode cache

  in->i_st.st_nlink++;

  std::time_t now = time_now();
  in->i_st.st_ctime = now;
  newparent_in->i_st.st_ctime = now;
  newparent_in->i_st.st_mtime = now;

  children[newname] = in;

  *st = in->i_st;

  return 0;
}

int GassyFs::Access(Inode *in, int mask, uid_t uid, gid_t gid)
{
  if (mask == F_OK)
    return 0;

  assert(mask & (R_OK | W_OK | X_OK));

  if (in->i_st.st_uid == uid) {
    if (mask & R_OK) {
      if (!(in->i_st.st_mode & S_IRUSR))
        return -EACCES;
    }
    if (mask & W_OK) {
      if (!(in->i_st.st_mode & S_IWUSR))
        return -EACCES;
    }
    if (mask & X_OK) {
      if (!(in->i_st.st_mode & S_IXUSR))
        return -EACCES;
    }
    return 0;
  } else if (in->i_st.st_gid == gid) {
    if (mask & R_OK) {
      if (!(in->i_st.st_mode & S_IRGRP))
        return -EACCES;
    }
    if (mask & W_OK) {
      if (!(in->i_st.st_mode & S_IWGRP))
        return -EACCES;
    }
    if (mask & X_OK) {
      if (!(in->i_st.st_mode & S_IXGRP))
        return -EACCES;
    }
    return 0;
  } else if (uid == 0) {
    if (mask & X_OK) {
      if (!(in->i_st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
        return -EACCES;
    }
    return 0;
  } else {
    if (mask & R_OK) {
      if (!(in->i_st.st_mode & S_IROTH))
        return -EACCES;
    }
    if (mask & W_OK) {
      if (!(in->i_st.st_mode & S_IWOTH))
        return -EACCES;
    }
    if (mask & X_OK) {
      if (!(in->i_st.st_mode & S_IXOTH))
        return -EACCES;
    }
    return 0;
  }

  assert(0);
}


int GassyFs::Access(fuse_ino_t ino, int mask, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);

  return Access(in, mask, uid, gid);
}

/*
 * Allow mknod to create special files, but enforce that these files are
 * never used in anything other than metadata operations.
 *
 * TODO: add checks that enforce non-use of special files. Note that this
 * routine can also create regular files.
 */
int GassyFs::Mknod(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
    dev_t rdev, struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  Inode *parent_in = inode_get(parent_ino);
  assert(parent_in);

  assert(parent_in->i_st.st_mode & S_IFDIR);
  Inode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  Inode *in = new Inode(next_ino_++);
  in->get();

  children[name] = in;
  ino_to_inode_[in->ino()] = in;

  in->i_st.st_ino = in->ino();
  in->i_st.st_mode = mode;
  in->i_st.st_nlink = 1;
  in->i_st.st_blksize = 4096;
  in->i_st.st_uid = uid;
  in->i_st.st_gid = gid;
  std::time_t now = time_now();
  in->i_st.st_atime = now;
  in->i_st.st_mtime = now;
  in->i_st.st_ctime = now;

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;

  return 0;
}

int GassyFs::OpenDir(fuse_ino_t ino, int flags, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode *in = inode_get(ino);
  assert(in);

  if ((flags & O_ACCMODE) == O_RDONLY) {
    int ret = Access(in, R_OK, uid, gid);
    if (ret)
      return ret;
  }

  return 0;
}

/*
 * This is a work-in-progress. It currently is functioning, but I think that
 * the it is not robust against concurrent modifications. The common
 * approach it seems is to encode a cookie in the offset parameter. Current
 * we just do an in-order traversal of the directory and return the Nth
 * item.
 */
ssize_t GassyFs::ReadDir(fuse_req_t req, fuse_ino_t ino, char *buf,
    size_t bufsize, off_t off)
{
  std::lock_guard<std::mutex> l(mutex_);

  struct stat st;
  memset(&st, 0, sizeof(st));

  size_t pos = 0;

  /*
   * FIXME: the ".." directory correctly shows up at the parent directory
   * inode, but "." shows a inode number as "?" with ls -lia.
   */
  if (off == 0) {
    size_t remaining = bufsize - pos;
    memset(&st, 0, sizeof(st));
    st.st_ino = 1;
    size_t used = fuse_add_direntry(req, buf + pos, remaining, ".", &st, 1);
    if (used > remaining)
      return pos;
    pos += used;
    off = 1;
  }

  if (off == 1) {
    size_t remaining = bufsize - pos;
    memset(&st, 0, sizeof(st));
    st.st_ino = 1;
    size_t used = fuse_add_direntry(req, buf + pos, remaining, "..", &st, 2);
    if (used > remaining)
      return pos;
    pos += used;
    off = 2;
  }

  assert(off >= 2);

  Inode *dir_in = inode_get(ino);
  assert(dir_in);
  assert(dir_in->i_st.st_mode & S_IFDIR);
  const Inode::dir_t& children = dir_in->dentries;

  size_t count = 0;
  size_t target = off - 2;

  for (Inode::dir_t::const_iterator it = children.begin();
      it != children.end(); it++) {
    if (count >= target) {
      Inode *in = it->second;
      assert(in);
      memset(&st, 0, sizeof(st));
      st.st_ino = in->i_st.st_ino;
      size_t remaining = bufsize - pos;
      size_t used = fuse_add_direntry(req, buf + pos, remaining, it->first.c_str(), &st, off + 1);
      if (used > remaining)
        return pos;
      pos += used;
      off++;
    }
    count++;
  }

  return pos;
}

/*
 *
 */
void GassyFs::ReleaseDir(fuse_ino_t ino) {}

/*
 * must hold mutex_
 */
int GassyFs::Truncate(Inode *in, off_t newsize, uid_t uid, gid_t gid)
{
  std::cout << in->ino() << " " << newsize << std::endl;
  int ret = Access(in, W_OK, uid, gid);
  if (ret)
    return ret;
  if (in->i_st.st_size == newsize) {
    return 0;
  } else if (in->i_st.st_size > newsize) {
    std::vector<Block>& blks = in->blocks();
    size_t blkid = newsize / BLOCK_SIZE;
    assert(blkid < blks.size());
    for (size_t i = blks.size() - 1; i > blkid; --i) {
      Block blk = blks.back();
      ba_->ReturnBlock(blk);
      blks.pop_back();
    }
    assert(blkid == (blks.size() - 1));
    in->i_st.st_size = newsize;
  } else {
    char zeros[4096];
    memset(zeros, 0, sizeof(zeros));
    while (in->i_st.st_size < newsize) {
      ssize_t ret = Write(in, in->i_st.st_size,
          sizeof(zeros), zeros);
      assert(ret > 0);
    }
    if (in->i_st.st_size > newsize)
      return Truncate(in, newsize, uid, gid);
    else
      assert(in->i_st.st_size == newsize);
  }

  return 0;
}

/*
 * must hold mutex_
 */
ssize_t GassyFs::Write(Inode *in, off_t offset, size_t size, const char *buf)
{
  int ret = in->set_capacity(offset + size, ba_);
  if (ret)
    return ret;

  std::time_t now = time_now();
  in->i_st.st_ctime = now;
  in->i_st.st_mtime = now;

  const off_t orig_offset = offset;
  const char *src = buf;

  size_t left = size;
  while (left != 0) {
    size_t blkid = offset / BLOCK_SIZE;
    size_t blkoff = offset % BLOCK_SIZE;
    size_t done = std::min(left, BLOCK_SIZE-blkoff);

    const std::vector<Block>& blks = in->blocks();
    assert(blkid < blks.size());
    const Block& b = blks[blkid];
    gasnet_put_bulk(b.node, (void*)(b.addr + blkoff), (void*)src, done);

    left -= done;
    src += done;
    offset += done;
  }

  in->i_st.st_size = std::max(in->i_st.st_size, orig_offset + (off_t)size);

  return size;
}

Inode *GassyFs::inode_get(fuse_ino_t ino) const
{
  inode_table_t::const_iterator it = ino_to_inode_.find(ino);
  if (it == ino_to_inode_.end())
    return NULL;
  return it->second;
}

/*
 *
 */
void GassyFs::put_inode(fuse_ino_t ino, long unsigned dec)
{
  inode_table_t::iterator it = ino_to_inode_.find(ino);
  assert(it != ino_to_inode_.end());
  Inode *in = it->second;
  if (!in->put(dec)) {
    ino_to_inode_.erase(ino);
    in->free_blocks(ba_);
    delete in;
  }
}
