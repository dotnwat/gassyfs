#include "gassy_fs.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <time.h>
#include "inode.h"

#ifdef HAVE_LUA
#include <lua.hpp>
#endif

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#define LUA_ATIME "/tmp/atime.lua"

#ifdef __MACH__
static inline std::time_t time_now(void)
{
  clock_serv_t cclock;
  mach_timespec_t mts;
  host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
  clock_get_time(cclock, &mts);
  mach_port_deallocate(mach_task_self(), cclock);
  return mts.tv_sec;
}
#else
static inline std::time_t time_now(void)
{
  struct timespec ts;
  int ret = clock_gettime(CLOCK_REALTIME, &ts);
  assert(ret == 0);
  return ts.tv_sec;
}
#endif

#ifdef HAVE_LUA
int lua_policy(const char *fname)
{
  lua_State *L = NULL;
  L = luaL_newstate();
  luaL_openlibs(L);
  lua_newtable(L);
  if (!L) {
    std::cerr << "===> ERROR creating Lua state\n";
    std::cerr.flush();
    return -ENOSYS;
  }

  if (luaL_dofile(L, fname) > 0) {
    std::cerr << "===> ERROR: " << lua_tostring(L, lua_gettop(L)) << "\n"; 
    std::cerr.flush();
    return -ENOENT;
  }

  int ret = lua_tonumber(L, lua_gettop(L));
  lua_close(L);
  return ret;
}
#else
int lua_policy(const char *fname)
{
   return -ENOSYS;
}
#endif

GassyFs::GassyFs(AddressSpace *storage) :
  next_ino_(FUSE_ROOT_ID + 1), storage_(storage)
{
  std::time_t now = time_now();

  auto root = std::make_shared<DirInode>(now,
      getuid(), getgid(), 4096, 0755, this);

  root->set_ino(FUSE_ROOT_ID);

  // bump kernel inode cache reference count
  ino_refs_.add(root);

  total_bytes_ = 0;
  for (Node *node : storage_->nodes()) {
    NodeAlloc na(node);
    node_alloc_.push_back(na);
    total_bytes_ += node->size();
  }
  avail_bytes_ = total_bytes_;
  node_alloc_count_ = node_alloc_.size();

  memset(&stat, 0, sizeof(stat));
  stat.f_fsid = 983983;
  stat.f_namemax = PATH_MAX;
  stat.f_bsize = 4096;
  stat.f_frsize = 4096;
  stat.f_blocks = total_bytes_ / 4096;
  stat.f_files = 0;
  stat.f_bfree = stat.f_blocks;
  stat.f_bavail = stat.f_blocks;
}

int GassyFs::Create(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
    int flags, struct stat *st, FileHandle **fhp, uid_t uid, gid_t gid)
{
  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::time_t now = time_now();

  auto in = std::make_shared<Inode>(now, uid, gid, 4096, S_IFREG | mode, this);
  auto fh = std::unique_ptr<FileHandle>(new FileHandle(in, flags));

  std::lock_guard<std::mutex> l(mutex_);

  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  in->set_ino(next_ino_++);

  children[name] = in;
  ino_refs_.add(in);

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;
  *fhp = fh.release();

  return 0;
}

int GassyFs::GetAttr(fuse_ino_t ino, struct stat *st, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  auto in = ino_refs_.inode(ino);

  *st = in->i_st;

  return 0;
}

int GassyFs::Unlink(fuse_ino_t parent_ino, const std::string& name, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t::const_iterator it = parent_in->dentries.find(name);
  if (it == parent_in->dentries.end())
    return -ENOENT;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  auto in = it->second;

  // see unlink(2): EISDIR may be another case
  if (in->is_directory())
    return -EPERM;

  if (parent_in->i_st.st_mode & S_ISVTX) {
    if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid)
      return -EPERM;
  }

  std::time_t now = time_now();

  in->i_st.st_ctime = now;
  in->i_st.st_nlink--;

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;
  parent_in->dentries.erase(it);

  return 0;
}

int GassyFs::Lookup(fuse_ino_t parent_ino, const std::string& name, struct stat *st)
{
  std::lock_guard<std::mutex> l(mutex_);

  // FIXME: should this be -ENOTDIR or -ENOENT in some cases?
  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t::const_iterator it = parent_in->dentries.find(name);
  if (it == parent_in->dentries.end())
    return -ENOENT;

  auto in = it->second;

  // bump kernel inode cache reference count
  ino_refs_.get(in);

  *st = in->i_st;

  return 0;
}

int GassyFs::Open(fuse_ino_t ino, int flags, FileHandle **fhp, uid_t uid, gid_t gid)
{
  int mode = 0;
  if ((flags & O_ACCMODE) == O_RDONLY)
    mode = R_OK;
  else if ((flags & O_ACCMODE) == O_WRONLY)
    mode = W_OK;
  else if ((flags & O_ACCMODE) == O_RDWR)
    mode = R_OK | W_OK;

  if (!(mode & W_OK) && (flags & O_TRUNC))
    return -EACCES;

  std::lock_guard<std::mutex> l(mutex_);

  auto in = ino_refs_.inode(ino);
  auto fh = std::unique_ptr<FileHandle>(new FileHandle(in, flags));

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

  *fhp = fh.release();

  return 0;
}

void GassyFs::Release(fuse_ino_t ino, FileHandle *fh)
{
  assert(fh);
  delete fh;
}

void GassyFs::Forget(fuse_ino_t ino, long unsigned nlookup)
{
  std::lock_guard<std::mutex> l(mutex_);

  // decrease kernel inode cache reference count
  ino_refs_.put(ino, nlookup);
}

ssize_t GassyFs::Write(FileHandle *fh, off_t offset, size_t size, const char *buf)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode::Ptr in = fh->in;
  ssize_t ret = Write(in, offset, size, buf);
  if (ret > 0)
    fh->pos += ret;

  return ret;
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
ssize_t GassyFs::WriteBuf(FileHandle *fh, struct fuse_bufvec *bufv, off_t off)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode::Ptr in = fh->in;

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

  Inode::Ptr in = fh->in;

  int ret = lua_policy(LUA_ATIME);
  if (ret < 0) 
    in->i_st.st_atime = time_now();
  else
    in->i_st.st_atime = ret;

  // reads that start past eof return nothing
  if (offset >= in->i_st.st_size || size == 0)
    return 0;

  // clip the read so that it doesn't pass eof
  size_t left;
  if ((off_t)(offset + size) > in->i_st.st_size)
    left = in->i_st.st_size - offset;
  else
    left = size;

  const size_t new_size = left;
  char *dst = buf;

  /*
   * find first segment that might intersect the read
   *
   * upper_bound(offset) will return a pointer to the first segment whose
   * offset is greater (>) than the target offset. Thus, the immediately
   * preceeding segment is the first that has an offset less than or equal to
   * (<=) the offset which is what we are interested in.
   *
   * 1) it == begin(): can't move backward
   * 2) it == end() / other: <= case described above
   */
  auto it = in->extents_.upper_bound(offset);
  if (it != in->extents_.begin()) { // not empty
    assert(!in->extents_.empty());
    --it;
  } else if (it == in->extents_.end()) { // empty
    assert(in->extents_.empty());
    memset(dst, 0, new_size);
    fh->pos += new_size;
    return new_size;
  }

  assert(it != in->extents_.end());
  off_t seg_offset = it->first;

  while (left) {
    // size of movement this round
    size_t done = 0;

    // read starts before the current segment. return zeros up until the
    // beginning of the segment or until we've completed the read.
    if (offset < seg_offset) {
      done = std::min(left, (size_t)(seg_offset - offset));
      memset(dst, 0, done);
    } else {
      const auto& extent = it->second;
      off_t seg_end_offset = seg_offset + extent.length;

      // fixme: there may be a case here where the end of file lands inside an
      // allocated extent, but logically it shoudl be returning zeros

      // read starts within the current segment. return valid data up until
      // the end of the segment or until we've completed the read.
      if (offset < seg_end_offset) {
        done = std::min(left, (size_t)(seg_end_offset - offset));

        size_t blkoff = offset - seg_offset;
        extent.node->node->read(dst, (void*)(extent.addr + blkoff), done);

      } else if (++it == in->extents_.end()) {
        seg_offset = offset + left;
        assert(offset < seg_offset);
        // assert that we'll be done
        continue;
      } else {
        seg_offset = it->first;
        continue;
      }
    }
    dst += done;
    offset += done;
    left -= done;
  }

  fh->pos += new_size;

  return new_size;
}

int GassyFs::Mkdir(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
    struct stat *st, uid_t uid, gid_t gid)
{
  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::time_t now = time_now();

  auto in = std::make_shared<DirInode>(now, uid, gid, 4096, mode, this);

  std::lock_guard<std::mutex> l(mutex_);

  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  in->set_ino(next_ino_++);

  children[name] = in;
  ino_refs_.add(in);

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;
  parent_in->i_st.st_nlink++;

  *st = in->i_st;

  return 0;
}

int GassyFs::Rmdir(fuse_ino_t parent_ino, const std::string& name,
    uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& children = parent_in->dentries;
  DirInode::dir_t::const_iterator it = children.find(name);
  if (it == children.end())
    return -ENOENT;

  if (!it->second->is_directory())
    return -ENOTDIR;

  auto in = std::static_pointer_cast<DirInode>(it->second);

  if (in->dentries.size())
    return -ENOTEMPTY;

  if (parent_in->i_st.st_mode & S_ISVTX) {
    if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid)
      return -EPERM;
  }

  std::time_t now = time_now();

  parent_in->i_st.st_mtime = now;
  parent_in->i_st.st_ctime = now;
  parent_in->dentries.erase(it);
  parent_in->i_st.st_nlink--;

  return 0;
}

int GassyFs::Rename(fuse_ino_t parent_ino, const std::string& name,
    fuse_ino_t newparent_ino, const std::string& newname,
    uid_t uid, gid_t gid)
{
  if (name.length() > NAME_MAX || newname.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::lock_guard<std::mutex> l(mutex_);

  // old
  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& parent_children = parent_in->dentries;
  DirInode::dir_t::const_iterator old_it = parent_children.find(name);
  if (old_it == parent_children.end())
    return -ENOENT;

  Inode::Ptr old_in = old_it->second;
  assert(old_in);

  // new
  auto newparent_in = ino_refs_.dir_inode(newparent_ino);
  DirInode::dir_t& newparent_children = newparent_in->dentries;
  DirInode::dir_t::const_iterator new_it = newparent_children.find(newname);

  Inode::Ptr new_in = NULL;
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
        DirInode::dir_t& new_children =
          std::static_pointer_cast<DirInode>(new_in)->dentries;
        if (new_children.size())
          return -ENOTEMPTY;
      } else
        return -ENOTDIR;
    } else {
      if (new_in->i_st.st_mode & S_IFDIR)
        return -EISDIR;
    }

    newparent_children.erase(new_it);
  }

  std::time_t now = time_now();
  old_in->i_st.st_ctime = now;

  newparent_children[newname] = old_it->second;
  parent_children.erase(old_it);

  return 0;
}

int GassyFs::SetAttr(fuse_ino_t ino, FileHandle *fh, struct stat *attr,
    int to_set, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);
  mode_t clear_mode = 0;

  Inode::Ptr in = ino_refs_.inode(ino);

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

#ifdef FUSE_SET_ATTR_MTIME_NOW
    if (to_set & FUSE_SET_ATTR_MTIME_NOW)
      in->i_st.st_mtime = time_now();
    else
#endif
    if (to_set & FUSE_SET_ATTR_MTIME)
      in->i_st.st_mtime = attr->st_mtime;

#ifdef FUSE_SET_ATTR_ATIME_NOW
    if (to_set & FUSE_SET_ATTR_ATIME_NOW)
      in->i_st.st_atime = time_now();
    else
#endif
    if (to_set & FUSE_SET_ATTR_ATIME)
      in->i_st.st_atime = attr->st_atime;
  }

#ifdef FUSE_SET_ATTR_CTIME
  if (to_set & FUSE_SET_ATTR_CTIME) {
    if (uid && in->i_st.st_uid != uid)
      return -EPERM;
    in->i_st.st_ctime = attr->st_ctime;
  }
#endif

  if (to_set & FUSE_SET_ATTR_SIZE) {

    if (uid) {   // not root
      if (!fh) { // not open file descriptor
        int ret = Access(in, W_OK, uid, gid);
        if (ret)
          return ret;
      } else if (((fh->flags & O_ACCMODE) != O_WRONLY) &&
                 ((fh->flags & O_ACCMODE) != O_RDWR)) {
        return -EACCES;
      }
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
  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::time_t now = time_now();

  auto in = std::make_shared<SymlinkInode>(now, uid, gid, 4096, link, this);

  std::lock_guard<std::mutex> l(mutex_);

  auto parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  in->set_ino(next_ino_++);

  children[name] = in;
  ino_refs_.add(in);

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;

  return 0;
}

ssize_t GassyFs::Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  SymlinkInode::Ptr in = ino_refs_.symlink_inode(ino);

  size_t link_len = in->link.size();

  if (link_len > maxlen)
    return -ENAMETOOLONG;

  in->link.copy(path, link_len, 0);

  return link_len;
}

int GassyFs::Statfs(fuse_ino_t ino, struct statvfs *stbuf)
{
  std::lock_guard<std::mutex> l(mutex_);

  // assert we are in this file system
  Inode::Ptr in = ino_refs_.inode(ino);
  (void)in;

  stat.f_files = ino_refs_.nfiles();
  stat.f_bfree = avail_bytes_ / 4096;
  stat.f_bavail = avail_bytes_ / 4096;

  *stbuf = stat;

  return 0;
}

int GassyFs::Link(fuse_ino_t ino, fuse_ino_t newparent_ino, const std::string& newname,
    struct stat *st, uid_t uid, gid_t gid)
{
  if (newname.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::lock_guard<std::mutex> l(mutex_);

  DirInode::Ptr newparent_in = ino_refs_.dir_inode(newparent_ino);
  if (newparent_in->dentries.find(newname) != newparent_in->dentries.end())
    return -EEXIST;

  Inode::Ptr in = ino_refs_.inode(ino);

  if (in->i_st.st_mode & S_IFDIR)
    return -EPERM;

  int ret = Access(newparent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  std::time_t now = time_now();

  // bump in kernel inode cache reference count
  ino_refs_.get(in);

  in->i_st.st_ctime = now;
  in->i_st.st_nlink++;

  newparent_in->i_st.st_ctime = now;
  newparent_in->i_st.st_mtime = now;
  newparent_in->dentries[newname] = in;

  *st = in->i_st;

  return 0;
}

int GassyFs::Access(Inode::Ptr in, int mask, uid_t uid, gid_t gid)
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

  Inode::Ptr in = ino_refs_.inode(ino);

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
  if (name.length() > NAME_MAX)
    return -ENAMETOOLONG;

  std::time_t now = time_now();

  auto in = std::make_shared<Inode>(now, uid, gid, 4096, mode, this);

  // directories start with nlink = 2, but according to mknod(2), "Under
  // Linux, mknod() cannot be used to create directories.  One should make
  // directories with mkdir(2).".
  assert(!in->is_directory());

  std::lock_guard<std::mutex> l(mutex_);

  DirInode::Ptr parent_in = ino_refs_.dir_inode(parent_ino);
  DirInode::dir_t& children = parent_in->dentries;
  if (children.find(name) != children.end())
    return -EEXIST;

  int ret = Access(parent_in, W_OK, uid, gid);
  if (ret)
    return ret;

  in->set_ino(next_ino_++);

  children[name] = in;
  ino_refs_.add(in);

  parent_in->i_st.st_ctime = now;
  parent_in->i_st.st_mtime = now;

  *st = in->i_st;

  return 0;
}

int GassyFs::OpenDir(fuse_ino_t ino, int flags, uid_t uid, gid_t gid)
{
  std::lock_guard<std::mutex> l(mutex_);

  Inode::Ptr in = ino_refs_.inode(ino);

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

  DirInode::Ptr dir_in = ino_refs_.dir_inode(ino);
  const DirInode::dir_t& children = dir_in->dentries;

  size_t count = 0;
  size_t target = off - 2;

  for (DirInode::dir_t::const_iterator it = children.begin();
      it != children.end(); it++) {
    if (count >= target) {
      Inode::Ptr in = it->second;
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

void GassyFs::ReleaseDir(fuse_ino_t ino) {}

void GassyFs::free_space(Extent *extent)
{
  extent->node->alloc->free(extent->addr, extent->size);
  avail_bytes_ += extent->size;
}

int GassyFs::Truncate(Inode::Ptr in, off_t newsize, uid_t uid, gid_t gid)
{
  // easy: nothing to do
  if (in->i_st.st_size == newsize) {
    return 0;

  // easy: free all extents
  } else if (newsize == 0) {
    for (auto& it : in->extents_) {
      free_space(&it.second);
    }
    in->extents_.clear();
    in->i_st.st_size = 0;

  // shrink file
  } else if (in->i_st.st_size > newsize) {

    // find extent that could intersect newsize
    auto it = in->extents_.upper_bound(newsize);
    if (it != in->extents_.begin()) {
      assert(!in->extents_.empty());
      --it;
    } else if (it == in->extents_.end()) {
      // empty: could happen if truncate big then small without causing any
      // space to actually be allocated (i.e. performing no writes).
      in->i_st.st_size = newsize;
      return 0;
    }

    assert(it != in->extents_.end());
    off_t extent_offset = it->first;

    if (newsize < extent_offset) {
      for (auto it2 = it; it2 != in->extents_.end(); it2++) {
        free_space(&it2->second);
      }
      in->extents_.erase(it, in->extents_.end());
      in->i_st.st_size = newsize;
      return 0;
    }

    const auto& extent = it->second;
    off_t extent_end = extent_offset + extent.length;

    if (newsize <= extent_end)
      it++;

    for (auto it2 = it; it2 != in->extents_.end(); it2++) {
      free_space(&it2->second);
    }

    in->extents_.erase(it, in->extents_.end());
    in->i_st.st_size = newsize;

    return 0;

  // expand file with zeros
  } else {
    assert(in->i_st.st_size < newsize);

    // find extent that could intersect newsize
    auto it = in->extents_.upper_bound(in->i_st.st_size);
    if (it != in->extents_.begin()) {
      assert(!in->extents_.empty());
      assert(it == in->extents_.end());
      --it;
    } else if (it == in->extents_.end()) {
      // empty: could happen with small truncate then large truncate having
      // not yet allocated any space (i.e. no writes).
      in->i_st.st_size = newsize;
      return 0;
    }

    assert(it != in->extents_.end());
    off_t extent_offset = it->first;

    assert(in->i_st.st_size >= extent_offset);

    const auto& extent = it->second;
    off_t extent_end = extent_offset + extent.length;

    if (in->i_st.st_size > extent_end) {
      in->i_st.st_size = newsize;
      return 0;
    }

    size_t left = std::min(extent_end - in->i_st.st_size,
        newsize - in->i_st.st_size);
    assert(left);

    char zeros[4096];
    memset(zeros, 0, sizeof(zeros));

    while (left) {
      size_t done = std::min(left, sizeof(zeros));
      ssize_t ret = Write(in, in->i_st.st_size, done, zeros);
      assert(ret > 0);
      left -= ret;
    }

    in->i_st.st_size = newsize;
  }

  return 0;
}

/*
 * Allocate storage space for a file. The space should be available at file
 * offset @offset, and be no larger than @size bytes.
 */
int GassyFs::allocate_space(Inode::Ptr in, off_t offset, size_t size, bool upper_bound)
{
#if 0
  std::cout << "alloc: offset=" << offset << " size=" << size << " upper_bound="
    << upper_bound << std::endl;
#endif

  // select a target node from which to allocate space
  NodeAlloc *na = &node_alloc_[in->alloc_node];
  in->alloc_node = ++in->alloc_node % node_alloc_count_;

  // allocate some space in the target node
  off_t alloc_offset = na->alloc->alloc(4096);
  if (alloc_offset == -ENOMEM)
    return -ENOSPC;
  assert(alloc_offset >= 0);

  avail_bytes_ -= 4096;

  // construct extent
  Extent extent;
  if (upper_bound)
    extent.length = std::min(size, (size_t)4096);
  else
    extent.length = 4096;
  extent.node = na;
  extent.addr = alloc_offset;
  extent.size = 4096;

#if 0
  std::cout << "   alloc extent: length=" << extent.length <<
    " addr=" << extent.addr <<
    " size=" << extent.size <<
    std::endl;
#endif

  // insert extent into inode allocation table
  assert(in->extents_.find(offset) == in->extents_.end());
  in->extents_[offset] = extent;

  return 0;
}

ssize_t GassyFs::Write(Inode::Ptr in, off_t offset, size_t size, const char *buf)
{
#if 0
  std::cout << "write: offset=" << offset << " size=" << size << std::endl;
#endif

  std::time_t now = time_now();
  in->i_st.st_ctime = now;
  in->i_st.st_mtime = now;

  // find the first extent that could intersect the write
  auto it = in->extents_.upper_bound(offset);
  if (it != in->extents_.begin()) {
    assert(!in->extents_.empty());
    --it;
  } else if (it == in->extents_.end()) {
    assert(in->extents_.empty());
    int ret = allocate_space(in, offset, size, false);
    if (ret)
      return ret;
    assert(!in->extents_.empty());
    it = in->extents_.begin();
    assert(it->first == offset);
  }

  assert(it != in->extents_.end());
  off_t seg_offset = it->first;

  size_t left = size;

  while (left) {
    // case 1. the offset is contained in a non-allocated region before the
    // extent. allocate some space starting at the target offset that doesn't
    // extend past the beginning of the extent.
    if (offset < seg_offset) {
#if 0
      std::cout << "write:case1: offset=" << offset <<
        " size=" << (seg_offset - offset) <<
        " upper_bound=true"
        << std::endl;
#endif
      int ret = allocate_space(in, offset, seg_offset - offset, true);
      if (ret)
        return ret;

      it = in->extents_.find(offset);
      assert(it != in->extents_.end());
      seg_offset = it->first;

      continue;
    }

    const auto& extent = it->second;
    off_t seg_end_offset = seg_offset + extent.length;

    // case 2. the offset falls within the current extent: write data
    if (offset < seg_end_offset) {
      size_t done = std::min(left, (size_t)(seg_end_offset - offset));
      size_t blkoff = offset - seg_offset;

#if 0
      std::cout << "write:case2: " <<
        " offset=" << offset <<
        " seg_offset=" << seg_offset <<
        " blkoff=" << blkoff <<
        " done=" << done <<
        " dst=" << (extent.addr + blkoff) <<
        std::endl;
#endif

      extent.node->node->write(
          (void*)(extent.addr + blkoff), (void*)buf, done);

      buf += done;
      offset += done;
      left -= done;

      in->i_st.st_size = std::max(in->i_st.st_size, offset);

      continue;
    }

    // case 3. the offset falls past the extent, and there are no more
    // extents. in this case we extend the file allocation.
    if (++it == in->extents_.end()) {
      int ret = allocate_space(in, offset, left, false);
      if (ret)
        return ret;

      it = in->extents_.find(offset);
      assert(it != in->extents_.end());
      seg_offset = it->first;

      continue;
    }

    // case 4. try the next extent
    seg_offset = it->first;
  }

  return size;
}
