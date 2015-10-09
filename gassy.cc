/*
 *
 */
#define FUSE_USE_VERSION 30

#include <map>
#include <unordered_map>
#include <string>
#include <deque>
#include <vector>
#include <iostream>
#include <mutex>
#include <cstring>
#include <cassert>
#include <cstddef>
#include <atomic>

#include <linux/limits.h>
#include <time.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#ifdef STORE_GASNET
#include <gasnet.h>
#endif

#include "common.h"

static std::time_t time_now()
{
  struct timespec ts;
  int ret = clock_gettime(CLOCK_REALTIME, &ts);
  assert(ret == 0);
  return ts.tv_sec;
}

/*
 * Block Allocation
 *
 * The entire GASNet address space is divided into fixed size blocks. New
 * blocks are allocated from a free list, otherwise new blocks are assigned in
 * round-robin across all GASNet segments.
 */
#define BLOCK_SIZE 4096
class BlockAllocator {
 public:
  struct Block {
    unsigned node;
    size_t addr;
    size_t size;
    char *data;
  };

#ifdef STORE_GASNET
  BlockAllocator(gasnet_seginfo_t *segments, unsigned nsegments) :
    local_(false)
  {
    total_bytes_ = 0;
    // FIXME: we don't really fill up the global address space at this point,
    // but it we need to be making sure that everything is aligned when we
    // approach the end of a segment.
    for (unsigned i = 0; i < nsegments; i++) {
      Node n;
      n.addr = (size_t)segments[i].addr;
      n.size = segments[i].size;
      n.curr = n.addr;
      nodes_.push_back(n);
      total_bytes_ += n.size;
    }
    curr_node = 0;
    num_nodes = nsegments;
    avail_bytes_ = total_bytes_;
  }
#elif defined(STORE_LOCAL)
  explicit BlockAllocator(size_t size) :
    local_(true)
  {
    Node n;
    n.addr = 0;
    n.size = size;
    n.curr = n.addr;
    nodes_.push_back(n);
    total_bytes_ = n.size;
    curr_node = 0;
    num_nodes = 1;
    avail_bytes_ = total_bytes_;
  }
#else
#error
#endif

  int GetBlock(Block *bp) {
    std::lock_guard<std::mutex> l(mutex_);

    if (!free_blks_.empty()) {
      Block b = free_blks_.front();
      free_blks_.pop_front();
      *bp = b;
      avail_bytes_ -= BLOCK_SIZE;
      return 0;
    }

    // node we are allocating from
    Node& n = nodes_[curr_node];

    Block bb;
    bb.node = curr_node;
    bb.addr = n.curr;
    bb.size = BLOCK_SIZE;
    bb.data = NULL;

    n.curr += BLOCK_SIZE;
    if (n.curr >= (n.addr + n.size))
      return -ENOSPC;

    // next node to allocate from
    curr_node = (curr_node + 1) % num_nodes;

    if (local_)
      bb.data = new char[BLOCK_SIZE];

    *bp = bb;
    avail_bytes_ -= BLOCK_SIZE;
    return 0;
  }

  void ReturnBlock(Block b) {
    std::lock_guard<std::mutex> l(mutex_);
    free_blks_.push_back(b);
    avail_bytes_ += BLOCK_SIZE;
  }

  uint64_t total_bytes() {
    std::lock_guard<std::mutex> l(mutex_);
    return total_bytes_;
  }

  uint64_t avail_bytes() {
    std::lock_guard<std::mutex> l(mutex_);
    return avail_bytes_;
  }

 private:
  struct Node {
    size_t addr;
    size_t size;
    size_t curr;
  };

  std::deque<Block> free_blks_;
  unsigned curr_node, num_nodes;
  std::vector<Node> nodes_;

  uint64_t total_bytes_;
  uint64_t avail_bytes_;

  bool local_;

  std::mutex mutex_;
};

/*
 *
 */
class Inode {
 public:
  Inode() : ino_(0), ref_(1) {}

  explicit Inode(fuse_ino_t ino) :
    ino_(ino), ref_(1)
  {
    memset(&i_st, 0, sizeof(i_st));
  }

  void get() {
    assert(ref_);
    ref_++;
  }

  bool put(long int dec = 1) {
    assert(ref_);
    ref_ -= dec;
    assert(ref_ >= 0);
    if (ref_ == 0)
      return false;
    return true;
  }

  int set_capacity(off_t size, BlockAllocator *ba) {
    while ((blks_.size()*BLOCK_SIZE) < (unsigned long)size) {
      BlockAllocator::Block b;
      int ret = ba->GetBlock(&b);
      if (ret)
        return ret;
      blks_.push_back(b);
    }
    return 0;
  }

  void free_blocks(BlockAllocator *ba) {
    for (auto &blk : blks_)
      ba->ReturnBlock(blk);
    blks_.clear();
  }

  fuse_ino_t ino() const {
    return ino_;
  }

  void set_ino(fuse_ino_t ino) {
    ino_ = ino;
  }

  std::vector<BlockAllocator::Block>& blocks() {
    return blks_;
  }

  struct stat i_st;


 private:
  fuse_ino_t ino_;
  long int ref_;
  std::vector<BlockAllocator::Block> blks_;
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

/*
 * FIXME: where are FileHandle instances freed?
 */
struct FileHandle {
  Inode *in;
  off_t pos;

  FileHandle() : in(NULL), pos(0)
  {}

  FileHandle(Inode *in) :
    in(in), pos(0)
  {}
};

/*
 *
 */
class Gassy {
 public:
  Gassy(BlockAllocator *ba) :
    next_ino_(FUSE_ROOT_ID + 1), ba_(ba)
  {
    // setup root inode
    DirInode *root = new DirInode(FUSE_ROOT_ID);
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

  /*
   *
   */
  int Create(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      int flags, struct stat *st, FileHandle **fhp, uid_t uid, gid_t gid) {

    if (name.length() > NAME_MAX)
      return -ENAMETOOLONG;

    /*
     * One reference for the name and one for the kernel inode cache. This
     * call also opens a file handle to the new file. However, it appears that
     * open does not take a reference on the in-kernel inode, so we shouldn't
     * need one here. The scenario that is of interest is removing a file that
     * is open.
     */
    Inode *in = new Inode;
    in->get();

    in->i_st.st_mode = S_IFREG | mode;
    in->i_st.st_nlink = 1;
    in->i_st.st_blksize = 4096;
    in->i_st.st_uid = uid;
    in->i_st.st_gid = gid;
    std::time_t now = time_now();
    in->i_st.st_atime = now;
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;

    FileHandle *fh = new FileHandle(in);

    DirInode *parent_in;
    get_inode_locked(parent_ino, &parent_in);
    assert(parent_in);

    DirInode::dir_t& children = parent_in->dentries;
    if (children.find(name) != children.end()) {
      parent_in->unlock();
      delete in; // FIXME: use shared_ptr
      delete fh;
      return -EEXIST;
    }

    int ret = Access(parent_in, W_OK, uid, gid);
    if (ret) {
      parent_in->unlock();
      delete in;
      delete fh;
      return ret;
    }

    in->set_ino(next_ino_++);
    in->i_st.st_ino = in->ino();

    parent_in->i_st.st_ctime = now;
    parent_in->i_st.st_mtime = now;

    children[name] = in;

    add_inode(in);

    *st = in->i_st;
    *fhp = fh;

    parent_in->unlock();

    return 0;
  }

  /*
   *
   */
  int GetAttr(fuse_ino_t ino, struct stat *st, uid_t uid, gid_t gid) {
    Inode *in;
    get_inode_locked(ino, &in);
    assert(in);
    *st = in->i_st;
    in->unlock();
    return 0;
  }

  /*
   *
   */
  int Unlink(fuse_ino_t parent_ino, const std::string& name, uid_t uid, gid_t gid) {

    DirInode *parent_in;
    get_inode_locked(parent_ino, &parent_in);
    assert(parent_in);

    DirInode::dir_t::const_iterator it = parent_in->dentries.find(name);
    if (it == parent_in->dentries.end()) {
      parent_in->unlock();
      return -ENOENT;
    }

    int ret = Access(parent_in, W_OK, uid, gid);
    if (ret) {
      parent_in->unlock();
      return ret;
    }

    Inode *in = it->second;
    in->lock();

    // rmdir is used for directories
    assert(!(in->i_st.st_mode & S_IFDIR));

    if (parent_in->i_st.st_mode & S_ISVTX) {
      if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid) {
        in->unlock();
        parent_in->unlock();
        return -EPERM;
      }
    }

    std::time_t now = time_now();
    in->i_st.st_ctime = now;

    parent_in->i_st.st_ctime = now;
    parent_in->i_st.st_mtime = now;

    in->i_st.st_nlink--;

    parent_in->dentries.erase(it);

    put_inode(in->ino());

    in->unlock();
    parent_in->unlock();

    return 0;
  }

  /*
   *
   */
  int Lookup(fuse_ino_t parent_ino, const std::string& name, struct stat *st) {

    DirInode *parent_in;
    get_inode_locked(parent_ino, &parent_in);
    assert(parent_in);

    // FIXME: should this be -ENOTDIR or -ENOENT in some cases?
    DirInode::dir_t::const_iterator it = parent_in->dentries.find(name);
    if (it == parent_in->dentries.end()) {
      parent_in->unlock();
      return -ENOENT;
    }

    Inode *in = it->second;
    in->lock();

    in->get();

    *st = in->i_st;

    in->unlock();
    parent_in->unlock();

    return 0;
  }

  /*
   *
   */
  int Open(fuse_ino_t ino, int flags, FileHandle **fhp, uid_t uid, gid_t gid) {

    FileHandle *fh = new FileHandle;

    Inode *in;
    get_inode_locked(ino, &in);
    assert(in);

    fh->in = in;

    int mode = 0;
    if ((flags & O_ACCMODE) == O_RDONLY)
      mode = R_OK;
    else if ((flags & O_ACCMODE) == O_WRONLY)
      mode = W_OK;
    else if ((flags & O_ACCMODE) == O_RDWR)
      mode = R_OK | W_OK;

    if (!(mode & W_OK) && (flags & O_TRUNC)) {
      in->unlock();
      delete fh;
      return -EACCES;
    }

    int ret = Access(in, mode, uid, gid);
    if (ret) {
      in->unlock();
      delete fh;
      return ret;
    }

    if (flags & O_TRUNC) {
      ret = Truncate(in, 0, uid, gid);
      if (ret) {
        in->unlock();
        delete fh;
        return ret;
      }
      std::time_t now = time_now();
      in->i_st.st_mtime = now;
      in->i_st.st_ctime = now;
    }

    *fhp = fh;

    in->unlock();

    return 0;
  }

  /*
   *
   */
  void Release(fuse_ino_t ino) {}

  /*
   *
   */
  void Forget(fuse_ino_t ino, long unsigned nlookup) {
    fixme
    std::lock_guard<std::mutex> l(mutex_);
    put_inode(ino, nlookup);
  }

  /*
   *
   */
  ssize_t Write(FileHandle *fh, off_t offset, size_t size, const char *buf) {
    fixme
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
  ssize_t WriteBuf(FileHandle *fh, struct fuse_bufvec *bufv, off_t off) {
    fixme
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

  /*
   *
   */
  ssize_t Read(FileHandle *fh, off_t offset,
    fixme
      size_t size, char *buf) {
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

      const std::vector<BlockAllocator::Block>& blks = in->blocks();
      assert(blkid < blks.size());
      const BlockAllocator::Block& b = blks[blkid];
#ifdef STORE_LOCAL
        memcpy(dest, b.data + blkoff, done);
#elif defined(STORE_GASNET)
        gasnet_get_bulk(dest, b.node, (void*)(b.addr + blkoff), done);
#else
#error
#endif

      dest += done;
      offset += done;
      left -= done;
    }

    fh->pos += new_n;

    return new_n;
  }

  /*
   *
   */
  int Mkdir(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      struct stat *st, uid_t uid, gid_t gid) {

    if (name.length() > NAME_MAX)
      return -ENAMETOOLONG;

    DirInode *in = new DirInode;
    in->get();

    in->i_st.st_uid = uid;
    in->i_st.st_gid = gid;
    in->i_st.st_mode = S_IFDIR | mode;
    in->i_st.st_nlink = 2;
    in->i_st.st_blksize = 4096;
    in->i_st.st_blocks = 1;
    std::time_t now = time_now();
    in->i_st.st_atime = now;
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;

    DirInode *parent_in;
    get_inode_locked(parent_ino, &parent_in);
    assert(parent_in);

    DirInode::dir_t& children = parent_in->dentries;
    if (children.find(name) != children.end()) {
      parent_in->unlock();
      delete in;
      return -EEXIST;
    }

    int ret = Access(parent_in, W_OK, uid, gid);
    if (ret) {
      parent_in->unlock();
      delete in;
      return ret;
    }

    in->set_ino(next_ino_++);
    in->i_st.st_ino = in->ino();

    parent_in->i_st.st_ctime = now;
    parent_in->i_st.st_mtime = now;
    parent_in->i_st.st_nlink++;

    children[name] = in;
    add_inode(in);

    *st = in->i_st;

    parent_in->unlock();

    return 0;
  }

  /*
   *
   */
  int Rmdir(fuse_ino_t parent_ino, const std::string& name,
      uid_t uid, gid_t gid) {

    DirInode *parent_in;
    get_inode_locked(parent_ino, &parent_in);
    assert(parent_in);

    DirInode::dir_t& children = parent_in->dentries;
    DirInode::dir_t::const_iterator it = children.find(name);
    if (it == children.end()) {
      parent_in->unlock();
      return -ENOENT;
    }

    Inode *in = it->second;
    in->lock();

    if (!is_directory(in)) {
      in->unlock();
      parent_in->unlock();
      return -ENOTDIR;
    }

    DirInode *dir_in = reinterpret_cast<DirInode*>(in);

    if (dir_in->dentries.size()) {
      in->unlock();
      parent_in->unlock();
      return -ENOTEMPTY;
    }

    if (parent_in->i_st.st_mode & S_ISVTX) {
      if (uid && uid != in->i_st.st_uid && uid != parent_in->i_st.st_uid) {
        in->unlock();
        parent_in->unlock();
        return -EPERM;
      }
    }

    children.erase(it);

    std::time_t now = time_now();
    parent_in->i_st.st_mtime = now;
    parent_in->i_st.st_ctime = now;
    parent_in->i_st.st_nlink--;

    put_inode(in->ino()); fixme locking

    in->unlock();
    parent_in->unlock();

    return 0;
  }

  /*
   *
   */
  int Rename(fuse_ino_t parent_ino, const std::string& name,
      fuse_ino_t newparent_ino, const std::string& newname,
      uid_t uid, gid_t gid)
  {
    std::lock_guard<std::mutex> l(mutex_);

    if (name.length() > NAME_MAX || newname.length() > NAME_MAX)
      return -ENAMETOOLONG;

    // old
    DirInode *parent_in = dir_inode_get(parent_ino);
    DirInode::dir_t& parent_children = parent_in->dentries;
    DirInode::dir_t::const_iterator old_it = parent_children.find(name);
    if (old_it == parent_children.end())
      return -ENOENT;

    Inode *old_in = old_it->second;
    assert(old_in);

    // new
    DirInode *newparent_in = dir_inode_get(newparent_ino);
    DirInode::dir_t& newparent_children = newparent_in->dentries;
    DirInode::dir_t::const_iterator new_it = newparent_children.find(newname);

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
          DirInode *new_dir_in = reinterpret_cast<DirInode*>(new_in);
          DirInode::dir_t& new_children = new_dir_in->dentries;
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

  int SetAttr(fuse_ino_t ino, struct stat *attr, int to_set,
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

  int Symlink(const std::string& link, fuse_ino_t parent_ino,
      const std::string& name, struct stat *st, uid_t uid, gid_t gid)
  {
    std::lock_guard<std::mutex> l(mutex_);

    // TODO: check length of link path components
    if (name.length() > NAME_MAX)
      return -ENAMETOOLONG;

    DirInode *parent_in = dir_inode_get(parent_ino);
    DirInode::dir_t& children = parent_in->dentries;
    if (children.find(name) != children.end())
      return -EEXIST;

    int ret = Access(parent_in, W_OK, uid, gid);
    if (ret)
      return ret;

    SymlinkInode *in = new SymlinkInode(next_ino_++);
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

  ssize_t Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid)
  {
    std::lock_guard<std::mutex> l(mutex_);

    SymlinkInode *in = symlink_inode_get(ino);
    size_t link_len = in->link.size();

    if (link_len > maxlen)
      return -ENAMETOOLONG;

    in->link.copy(path, link_len, 0);

    return link_len;
  }

  int Statfs(fuse_ino_t ino, struct statvfs *stbuf) {
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

  int Link(fuse_ino_t ino, fuse_ino_t newparent_ino, const std::string& newname,
      struct stat *st, uid_t uid, gid_t gid) {
    std::lock_guard<std::mutex> l(mutex_);

    if (newname.length() > NAME_MAX)
      return -ENAMETOOLONG;

    DirInode *newparent_in = dir_inode_get(newparent_ino);
    DirInode::dir_t& children = newparent_in->dentries;
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

  int Access(Inode *in, int mask, uid_t uid, gid_t gid) {
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


  int Access(fuse_ino_t ino, int mask, uid_t uid, gid_t gid) {
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
  int Mknod(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      dev_t rdev, struct stat *st, uid_t uid, gid_t gid)
  {
    std::lock_guard<std::mutex> l(mutex_);

    if (name.length() > NAME_MAX)
      return -ENAMETOOLONG;

    DirInode *parent_in = dir_inode_get(parent_ino);
    DirInode::dir_t& children = parent_in->dentries;
    if (children.find(name) != children.end())
      return -EEXIST;

    int ret = Access(parent_in, W_OK, uid, gid);
    if (ret)
      return ret;

    // FIXME: assert this is only used for specific types of inodes
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

  int OpenDir(fuse_ino_t ino, int flags, uid_t uid, gid_t gid) {
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
  ssize_t ReadDir(fuse_req_t req, fuse_ino_t ino, char *buf,
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

    DirInode *dir_in = dir_inode_get(ino);
    const DirInode::dir_t& children = dir_in->dentries;

    size_t count = 0;
    size_t target = off - 2;

    for (DirInode::dir_t::const_iterator it = children.begin();
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
  void ReleaseDir(fuse_ino_t ino) {}

 private:
  typedef std::unordered_map<fuse_ino_t, Inode*> inode_table_t;

  /*
   * must hold mutex_
   *
   * FIXME: holding in->lock from Open
   */
  int Truncate(Inode *in, off_t newsize, uid_t uid, gid_t gid) {
    std::cout << in->ino() << " " << newsize << std::endl;
    int ret = Access(in, W_OK, uid, gid);
    if (ret)
      return ret;
    if (in->i_st.st_size == newsize) {
      return 0;
    } else if (in->i_st.st_size > newsize) {
      std::vector<BlockAllocator::Block>& blks = in->blocks();
      size_t blkid = newsize / BLOCK_SIZE;
      assert(blkid < blks.size());
      for (size_t i = blks.size() - 1; i > blkid; --i) {
        BlockAllocator::Block blk = blks.back();
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
  ssize_t Write(Inode *in, off_t offset, size_t size, const char *buf) {
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

      const std::vector<BlockAllocator::Block>& blks = in->blocks();
      assert(blkid < blks.size());
      const BlockAllocator::Block& b = blks[blkid];
#ifdef STORE_LOCAL
      memcpy(b.data + blkoff, src, done);
#elif defined(STORE_GASNET)
      gasnet_put_bulk(b.node, (void*)(b.addr + blkoff), (void*)src, done);
#else
#error
#endif

      left -= done;
      src += done;
      offset += done;
    }

    in->i_st.st_size = std::max(in->i_st.st_size, orig_offset + (off_t)size);

    return size;
  }

  bool is_directory(const Inode *in) const {
    return in->i_st.st_mode & S_IFDIR;
  }

  /*
   *
   */
  Inode *inode_get(fuse_ino_t ino) const {
    inode_table_t::const_iterator it = ino_to_inode_.find(ino);
    if (it == ino_to_inode_.end())
      return NULL;
    return it->second;
  }

  DirInode *__dir_inode_get(fuse_ino_t ino) const {
    Inode *in = inode_get(ino);
    assert(in);
    if (!(in->i_st.st_mode & S_IFDIR))
      return NULL;
    return reinterpret_cast<DirInode*>(in);
  }

  DirInode *dir_inode_get(fuse_ino_t ino) const {
    Inode *in = inode_get(ino);
    assert(in);
    assert(in->i_st.st_mode & S_IFDIR);
    return reinterpret_cast<DirInode*>(in);
  }

  SymlinkInode *symlink_inode_get(fuse_ino_t ino) const {
    Inode *in = inode_get(ino);
    assert(in);
    assert(in->i_st.st_mode & S_IFLNK);
    return reinterpret_cast<SymlinkInode*>(in);
  }

  void add_inode(Inode *in) {
    lock.lock();
    assert(ino_to_ino_.find(in->ino()) == ino_to_ino_.end());
    ino_to_inode_[in->ino()] = in;
    lock.unlock();
  }

  void get_inode_locked(fuse_ino_t ino, DirInode **inp) {
    lock.lock_shared();

    inode_table_t::const_iterator it = ino_to_inode_.find(ino);
    if (it == ino_to_inode_.end()) {
      *inp = NULL;
      lock.unlock_shared();
      return;
    }

    Inode *in = it->second;
    lock.unlock_shared();

    in->lock();
    assert(in->i_st.st_mode & S_IFDIR);

    /*
     * The idea here is that unlink might race with other operations,
     * and we can check while holding the inode lock if this is the case.
     * This could be avoided by using dentries that all point to the inode,
     * which could probably be a good idea anyway (TODO: what state is a
     * dentry vs in an inode?).
     *
     * FIXME: as it stands this doesn't exactly work for links because the
     * flag below can't express multiple directory entries. Instead, switch to
     * using n_link.
     *
     * It is still a very weird race that I'm not sure in which way it is
     * handled. What I'm going to do is assume this is handled in the vfs some
     * how. I will just assert here that we never return a reference to an
     * inode that has been unlinked. This doesn't apply to open file handles
     * that have raced with unlink, but in those cases there is no inode
     * lookup, just a raw pointer. This is only for new lookups
     */
    assert(!in->unlinked);

    *inp = reinterpret_cast<DirInode*>(in);
  }

  /*
   *
   */
  void put_inode(fuse_ino_t ino, long unsigned dec = 1) {
    inode_table_t::iterator it = ino_to_inode_.find(ino);
    assert(it != ino_to_inode_.end());
    Inode *in = it->second;
    if (!in->put(dec)) {
      ino_to_inode_.erase(ino);
      in->free_blocks(ba_);
      delete in;
    }
  }

  std::atomic_uint next_ino_;
  inode_table_t ino_to_inode_;
  BlockAllocator *ba_;
  struct statvfs stat;
};

/*
 *
 */
static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);
  FileHandle *fh;

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Create(parent, name, mode, fi->flags, &fe.attr, &fh, ctx->uid, ctx->gid);
  if (ret == 0) {
    fi->fh = (long)fh;
    fe.ino = fe.attr.st_ino;
    fe.generation = 0;
    fe.entry_timeout = 1.0;
    fuse_reply_create(req, &fe, fi);
  } else
    fuse_reply_err(req, -ret);
}

static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  FileHandle *fh = (FileHandle*)fi->fh;

  fs->Release(ino);
  delete fh;
  fuse_reply_err(req, 0);
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->Unlink(parent, name, ctx->uid, ctx->gid);
  fuse_reply_err(req, -ret);
}

static void ll_forget(fuse_req_t req, fuse_ino_t ino, long unsigned nlookup)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  fs->Forget(ino, nlookup);
  fuse_reply_none(req);
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
void ll_forget_multi(fuse_req_t req, size_t count,
    struct fuse_forget_data *forgets)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  for (size_t i = 0; i < count; i++) {
    const struct fuse_forget_data *f = forgets + i;
    fs->Forget(f->ino, f->nlookup);
  }

  fuse_reply_none(req);
}
#endif

static void ll_getattr(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);
  struct stat st;

  int ret = fs->GetAttr(ino, &st, ctx->uid, ctx->gid);
  if (ret == 0)
    fuse_reply_attr(req, &st, ret);
  else
    fuse_reply_err(req, -ret);
}

static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Lookup(parent, name, &fe.attr);
  if (ret == 0) {
    fe.ino = fe.attr.st_ino;
    fe.generation = 0;
    fuse_reply_entry(req, &fe);
  } else
    fuse_reply_err(req, -ret);
}

/*
 *
 */
static void ll_opendir(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->OpenDir(ino, fi->flags, ctx->uid, ctx->gid);
  if (ret == 0) {
    fuse_reply_open(req, fi);
  } else {
    fuse_reply_err(req, -ret);
  }
}

/*
 *
 */
static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
    off_t off, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  char *buf = new char[size];

  ssize_t ret = fs->ReadDir(req, ino, buf, size, off);
  if (ret >= 0) {
    fuse_reply_buf(req, buf, (size_t)ret);
  } else {
    int r = (int)ret;
    fuse_reply_err(req, -r);
  }

  delete [] buf;
}

/*
 *
 */
static void ll_releasedir(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  fs->ReleaseDir(ino);
  fuse_reply_err(req, 0);
}


static void ll_open(fuse_req_t req, fuse_ino_t ino,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);
  FileHandle *fh;

  assert(!(fi->flags & O_CREAT));

  int ret = fs->Open(ino, fi->flags, &fh, ctx->uid, ctx->gid);
  if (ret == 0) {
    fi->fh = (long)fh;
    fuse_reply_open(req, fi);
  } else
    fuse_reply_err(req, -ret);
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
static void ll_write_buf(fuse_req_t req, fuse_ino_t ino,
    struct fuse_bufvec *bufv, off_t off,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  FileHandle *fh = (FileHandle*)fi->fh;

  ssize_t ret = fs->WriteBuf(fh, bufv, off);
  if (ret >= 0)
    fuse_reply_write(req, ret);
  else
    fuse_reply_err(req, -ret);
}
#else
static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
    size_t size, off_t off, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  FileHandle *fh = (FileHandle*)fi->fh;

  ssize_t ret = fs->Write(fh, off, size, buf);
  if (ret >= 0)
    fuse_reply_write(req, ret);
  else
    fuse_reply_err(req, -ret);
}
#endif

static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  FileHandle *fh = (FileHandle*)fi->fh;

  char buf[1<<20];
  size_t new_size = std::min(size, sizeof(buf));

  ssize_t ret = fs->Read(fh, off, new_size, buf);
  if (ret >= 0)
    fuse_reply_buf(req, buf, ret);
  else
    fuse_reply_err(req, -ret);
}

static void ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Mkdir(parent, name, mode, &fe.attr, ctx->uid, ctx->gid);
  if (ret == 0) {
    fe.ino = fe.attr.st_ino;
    fe.generation = 0;
    fe.entry_timeout = 1.0;
    fuse_reply_entry(req, &fe);
  } else
    fuse_reply_err(req, -ret);
}

static void ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->Rmdir(parent, name, ctx->uid, ctx->gid);
  fuse_reply_err(req, -ret);
}

static void ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
    fuse_ino_t newparent, const char *newname)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->Rename(parent, name, newparent, newname,
      ctx->uid, ctx->gid);
  fuse_reply_err(req, -ret);
}

static void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
    int to_set, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->SetAttr(ino, attr, to_set, ctx->uid, ctx->gid);
  if (ret == 0)
    fuse_reply_attr(req, attr, 0);
  else
    fuse_reply_err(req, -ret);
}

static void ll_readlink(fuse_req_t req, fuse_ino_t ino)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);
  char path[PATH_MAX + 1];

  ssize_t ret = fs->Readlink(ino, path, sizeof(path) - 1, ctx->uid, ctx->gid);
  if (ret >= 0) {
    path[ret] = '\0';
    fuse_reply_readlink(req, path);
  } else {
    int r = (int)ret;
    fuse_reply_err(req, -r);
  }
}

static void ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
    const char *name)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Symlink(link, parent, name, &fe.attr, ctx->uid, ctx->gid);
  if (ret == 0) {
    fe.ino = fe.attr.st_ino;
    fuse_reply_entry(req, &fe);
  } else
    fuse_reply_err(req, -ret);
}

static void ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
  fuse_reply_err(req, 0);
}

static void ll_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
  fuse_reply_err(req, 0);
}

static void ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  struct statvfs stbuf;
  memset(&stbuf, 0, sizeof(stbuf));

  int ret = fs->Statfs(ino, &stbuf);
  if (ret == 0)
    fuse_reply_statfs(req, &stbuf);
  else
    fuse_reply_err(req, -ret);
}

static void ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
    const char *newname)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Link(ino, newparent, newname, &fe.attr, ctx->uid, ctx->gid);
  if (ret == 0) {
    fe.ino = fe.attr.st_ino;
    fuse_reply_entry(req, &fe);
  } else
    fuse_reply_err(req, -ret);
}

static void ll_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  int ret = fs->Access(ino, mask, ctx->uid, ctx->gid);
  fuse_reply_err(req, -ret);
}

static void ll_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
    mode_t mode, dev_t rdev)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  const struct fuse_ctx *ctx = fuse_req_ctx(req);

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  int ret = fs->Mknod(parent, name, mode, rdev, &fe.attr, ctx->uid, ctx->gid);
  if (ret == 0) {
    fe.ino = fe.attr.st_ino;
    fuse_reply_entry(req, &fe);
  } else
    fuse_reply_err(req, -ret);
}

static void ll_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
    off_t offset, off_t length, struct fuse_file_info *fi)
{
  // not implemented, but return OK for now.
  fuse_reply_err(req, 0);
}

struct gassyfs_param {
  bool local;
  size_t local_size_mb;
};

enum {
  KEY_GASSYFS_OPT,
  KEY_USE_LOCAL_RAM,
};

static struct fuse_opt gassyfs_opts[] = {
  FUSE_OPT_KEY("local", KEY_USE_LOCAL_RAM),
  {"local_size_mb=%lu", offsetof(struct gassyfs_param, local_size_mb), KEY_GASSYFS_OPT},
  FUSE_OPT_END
};

static int gassyfs_opt_proc(void *data, const char *arg, int key,
    struct fuse_args *outargs)
{
  struct gassyfs_param *p = (struct gassyfs_param *)data;

  switch (key) {
    case FUSE_OPT_KEY_OPT:
      return 1;
    case FUSE_OPT_KEY_NONOPT:
      return 1;
    case KEY_USE_LOCAL_RAM:
      p->local = true;
      return 0;
    default:
      return 0;
  }

}

int main(int argc, char *argv[])
{
#ifdef STORE_GASNET
  GASNET_SAFE(gasnet_init(&argc, &argv));

  size_t segsz = gasnet_getMaxLocalSegmentSize();
  GASNET_SAFE(gasnet_attach(NULL, 0, segsz, 0));

  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    return 0;
  }

  fprintf(stdout, "GASNet(%d): segment size = %lu\n",
      gasnet_mynode(), segsz);
  fflush(stdout);

  assert(gasnet_mynode() == 0);

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));
#endif

  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse_chan *ch;
  char *mountpoint;
  int err = -1;

  struct gassyfs_param params;
  params.local = false;
  params.local_size_mb = 1024;

  if (fuse_opt_parse(&args, &params, gassyfs_opts, gassyfs_opt_proc) == -1) {
    fprintf(stderr, "failed to parse options\n");
    exit(1);
  }

#ifdef STORE_GASNET
  params.local = false;
#elif defined(STORE_LOCAL)
  params.local = true;
#else
#error
#endif

  std::cout << "backend: ";
  if (params.local)
    std::cout << "local memory: (" << params.local_size_mb << " MB)";
  else
    std::cout << "gasnet";
  std::cout << std::endl;

  // Operation registry
  struct fuse_lowlevel_ops ll_oper;
  memset(&ll_oper, 0, sizeof(ll_oper));
  ll_oper.lookup      = ll_lookup;
  ll_oper.getattr     = ll_getattr;
  ll_oper.opendir     = ll_opendir;
  ll_oper.readdir     = ll_readdir;
  ll_oper.releasedir  = ll_releasedir;
  ll_oper.open        = ll_open;
  ll_oper.read        = ll_read;
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
# define USING_WRITE_BUF
  ll_oper.write_buf   = ll_write_buf;
#else
  ll_oper.write       = ll_write;
#endif
  ll_oper.create      = ll_create;
  ll_oper.release     = ll_release;
  ll_oper.unlink      = ll_unlink;
  ll_oper.mkdir       = ll_mkdir;
  ll_oper.rmdir       = ll_rmdir;
  ll_oper.rename      = ll_rename;
  ll_oper.setattr     = ll_setattr;
  ll_oper.symlink     = ll_symlink;
  ll_oper.readlink    = ll_readlink;
  ll_oper.fsync       = ll_fsync;
  ll_oper.fsyncdir    = ll_fsyncdir;
  ll_oper.statfs      = ll_statfs;
  ll_oper.link        = ll_link;
  ll_oper.access      = ll_access;
  ll_oper.mknod       = ll_mknod;
  ll_oper.forget      = ll_forget;
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
  ll_oper.forget_multi = ll_forget_multi;
#endif
  ll_oper.fallocate   = ll_fallocate;

  /*
   *
   */
  std::cout << "write interface: ";
#ifdef USING_WRITE_BUF
  std::cout << "write_buf";
#else
  std::cout << "write";
#endif
  std::cout << std::endl;
  fflush(stdout); // FIXME: std::abc version?

  BlockAllocator *ba;
#ifdef STORE_LOCAL
  ba = new BlockAllocator(params.local_size_mb << 20);
#elif defined(STORE_GASNET)
  ba = new BlockAllocator(segments, gasnet_nodes());
#else
#error
#endif

  Gassy *fs = new Gassy(ba);

  if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
      (ch = fuse_mount(mountpoint, &args)) != NULL) {
    struct fuse_session *se;

    se = fuse_lowlevel_new(&args, &ll_oper, sizeof(ll_oper), fs);
    if (se != NULL) {
      if (fuse_set_signal_handlers(se) != -1) {
        fuse_session_add_chan(se, ch);
        err = fuse_session_loop_mt(se);
        fuse_remove_signal_handlers(se);
        fuse_session_remove_chan(ch);
      }
      fuse_session_destroy(se);
    }
    fuse_unmount(mountpoint, ch);
  }
  fuse_opt_free_args(&args);

#ifdef STORE_GASNET
  gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
  gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
#endif

  int rv = err ? 1 : 0;
#ifdef STORE_GASNET
  gasnet_exit(rv);
#endif
  return rv;
}
