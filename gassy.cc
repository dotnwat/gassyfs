/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall hello_ll.c `pkg-config fuse --cflags --libs` -o hello_ll
*/

#define FUSE_USE_VERSION 30

#include <map>
#include <string>
#include <deque>
#include <vector>
#include <iostream>
#include <chrono>

#include <fuse.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <gasnet.h>

/*
 * Helpers
 */

class Mutex {
 public:
  Mutex() {
    pthread_mutex_init(&mutex_, NULL);
  }

  void Lock() {
    pthread_mutex_lock(&mutex_);
  }

  void Unlock() {
    pthread_mutex_unlock(&mutex_);
  }

 private:
  pthread_mutex_t mutex_;
};

class MutexLock {
 public:
  explicit MutexLock(Mutex *mutex) : mutex_(mutex) {
    mutex_->Lock();
  }

  ~MutexLock() {
    mutex_->Unlock();
  }

 private:
  Mutex *mutex_;
};

#define GASNET_SAFE(fncall) do {                                     \
    int _retval;                                                     \
    if ((_retval = fncall) != GASNET_OK) {                           \
      fprintf(stderr, "ERROR calling: %s\n"                          \
                      " at: %s:%i\n"                                 \
                      " error: %s (%s)\n",                           \
              #fncall, __FILE__, __LINE__,                           \
              gasnet_ErrorName(_retval), gasnet_ErrorDesc(_retval)); \
      fflush(stderr);                                                \
      gasnet_exit(_retval);                                          \
    }                                                                \
  } while(0)

/*
 * Block Allocation
 *
 * The entire GASNet address space is divided into fixed size blocks. New
 * blocks are allocated from a free list, otherwise new blocks are assigned in
 * round-robin across all GASNet segments.
 */
#define BLOCK_SIZE 1048576
class BlockAllocator {
 public:
  struct Block {
    gasnet_node_t node;
    size_t addr;
    size_t size;
  };

  BlockAllocator(gasnet_seginfo_t *segments, unsigned nsegments)
  {
    // FIXME: we don't really fill up the global address space at this point,
    // but it we need to be making sure that everything is aligned when we
    // approach the end of a segment.
    for (unsigned i = 0; i < nsegments; i++) {
      Node n;
      n.addr = (size_t)segments[i].addr;
      n.size = segments[i].size;
      n.curr = n.addr;
      nodes_.push_back(n);
    }
    curr_node = 0;
    num_nodes = nsegments;
  }

  int GetBlock(Block *bp) {
    MutexLock l(&mutex_);

    if (!free_blks_.empty()) {
      Block b = free_blks_.front();
      free_blks_.pop_front();
      *bp = b;
      return 0;
    }

    // node we are allocating from
    Node& n = nodes_[curr_node];

    Block bb;
    bb.node = curr_node;
    bb.addr = n.curr;
    bb.size = BLOCK_SIZE;

    n.curr += BLOCK_SIZE;
    if (n.curr >= (n.addr + n.size))
      return -ENOSPC;

    // next node to allocate from
    curr_node = (curr_node + 1) % num_nodes;

    *bp = bb;
    return 0;
  }

  void ReturnBlock(Block b) {
    MutexLock l(&mutex_);
    free_blks_.push_back(b);
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

  Mutex mutex_;
};

/*
 *
 */
class Inode {
 public:
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

  fuse_ino_t ino() const {
    return ino_;
  }

  const std::vector<BlockAllocator::Block>& blocks() const {
    return blks_;
  }

  struct stat i_st;

 private:
  fuse_ino_t ino_;
  long int ref_;
  std::vector<BlockAllocator::Block> blks_;
};

/*
 *
 */
struct FileHandle {
  Inode *in;
  off_t pos;

  FileHandle(Inode *in) :
    in(in), pos(0)
  {}
};

/*
 *
 */
class Gassy {
 public:
  explicit Gassy(BlockAllocator *ba) :
    next_ino_(FUSE_ROOT_ID + 1), ba_(ba)
  {
    // setup root inode
    Inode *root = new Inode(FUSE_ROOT_ID);
    root->i_st.st_mode = S_IFDIR | 0755;
    root->i_st.st_nlink = 2;
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    root->i_st.st_atime = now;
    root->i_st.st_mtime = now;
    root->i_st.st_ctime = now;
    root->i_st.st_birthtime = now;
    ino_to_inode_[root->ino()] = root;
    children_[FUSE_ROOT_ID] = std::map<std::string, fuse_ino_t>();
  }

  /*
   *
   */
  int Create(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      int flags, struct stat *st, FileHandle **fhp, uid_t uid, gid_t gid) {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    if (children.find(name) != children.end())
      return -EEXIST;

    Inode *in = new Inode(next_ino_++);
    in->get();

    children[name] = in->ino();
    ino_to_inode_[in->ino()] = in;

    in->i_st.st_ino = in->ino();
    in->i_st.st_mode = S_IFREG | mode;
    in->i_st.st_nlink = 1;
    in->i_st.st_blksize = 4096;
    in->i_st.st_uid = uid;
    in->i_st.st_gid = gid;
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_atime = now;
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;
    in->i_st.st_birthtime = now;

    *st = in->i_st;

    FileHandle *fh = new FileHandle(in);
    *fhp = fh;

    return 0;
  }

  /*
   *
   */
  int GetAttr(fuse_ino_t ino, struct stat *st) {
    MutexLock l(&mutex_);

    Inode *in = inode_get(ino);
    *st = in->i_st;

    return 0;
  }

  /*
   *
   */
  int Unlink(fuse_ino_t parent_ino, const std::string& name) {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    std::map<std::string, fuse_ino_t>::const_iterator it = children.find(name);
    if (it == children.end())
      return -ENOENT;

    Inode *in = inode_get(it->second);
    assert(in);
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_ctime = now;

    symlinks_.erase(it->second);
    children.erase(it);

    return 0;
  }

  /*
   *
   */
  int Lookup(fuse_ino_t parent_ino, const std::string& name, struct stat *st) {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    const std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    std::map<std::string, fuse_ino_t>::const_iterator it = children.find(name);
    if (it == children.end())
      return -ENOENT;

    Inode *in = inode_get(it->second);
    in->get();

    *st = in->i_st;

    return 0;
  }

  /*
   *
   */
  int Open(fuse_ino_t ino, FileHandle **fhp) {
    MutexLock l(&mutex_);

    Inode *in = inode_get(ino);
    in->get();

    FileHandle *fh = new FileHandle(in);
    *fhp = fh;

    return 0;
  }

  /*
   *
   */
  void Release(fuse_ino_t ino) {
    MutexLock l(&mutex_);
    put_inode(ino);
  }

  /*
   *
   */
  void Forget(fuse_ino_t ino, long unsigned nlookup) {
    MutexLock l(&mutex_);
    put_inode(ino, nlookup);
  }

  /*
   *
   */
  void PathNames(fuse_ino_t ino, std::vector<std::string>& names) {
    MutexLock l(&mutex_);

    assert(children_.find(ino) != children_.end());
    const std::map<std::string, fuse_ino_t>& children = children_.at(ino);

    std::vector<std::string> out;
    for (auto &it : children) {
      out.push_back(it.first);
    }
    names.swap(out);
  }

  /*
   *
   */
  ssize_t Write(FileHandle *fh, off_t offset, size_t size, const char *buf) {
    MutexLock l(&mutex_);

    Inode *in = fh->in;

    int ret = in->set_capacity(offset + size, ba_);
    if (ret)
      return ret;

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
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
      gasnet_put_bulk(b.node, (void*)(b.addr + blkoff), (void*)src, done);

      left -= done;
      src += done;
      offset += done;
    }

    in->i_st.st_size = std::max(in->i_st.st_size, orig_offset + (off_t)size);

    fh->pos += size;

    return size;
  }

  /*
   *
   */
  ssize_t Read(FileHandle *fh, off_t offset,
      size_t size, char *buf) {
    MutexLock l(&mutex_);

    Inode *in = fh->in;

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_atime = now;

    // don't read past eof
    size_t left;
    if ((offset + size) > in->i_st.st_size)
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
      gasnet_get_bulk(dest, b.node, (void*)(b.addr + blkoff), done);

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
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    if (children.find(name) != children.end())
      return -EEXIST;

    Inode *in = new Inode(next_ino_++);
    in->get();

    in->i_st.st_uid = uid;
    in->i_st.st_gid = gid;
    in->i_st.st_ino = in->ino();
    in->i_st.st_mode = S_IFDIR | mode;
    in->i_st.st_nlink = 2;
    in->i_st.st_blksize = 4096;
    in->i_st.st_blocks = 1;
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_atime = now;
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;
    in->i_st.st_birthtime = now;

    *st = in->i_st;

    children_[in->ino()] = std::map<std::string, fuse_ino_t>();
    children[name] = in->ino();
    ino_to_inode_[in->ino()] = in;

    return 0;
  }

  /*
   *
   */
  int Rmdir(fuse_ino_t parent_ino, const std::string& name) {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    std::map<std::string, fuse_ino_t>::const_iterator it = children.find(name);
    if (it == children.end())
      return -ENOENT;

    Inode *in = inode_get(it->second);
    if (!(in->i_st.st_mode & S_IFDIR))
      return -ENOTDIR;

    std::map<fuse_ino_t, std::map<std::string, fuse_ino_t>>::iterator it2 =
      children_.find(it->second);
    assert(it2 != children_.end());

    if (it2->second.size())
      return -ENOTEMPTY;

    children.erase(it);
    children_.erase(it2);

    return 0;
  }

  /*
   * FIXME:
   *   - There are a lot of different cases that aren't currently handled.
   */
  int Rename(fuse_ino_t parent_ino, const std::string& name,
      fuse_ino_t newparent_ino, const std::string& newname)
  {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& parent_children = children_.at(parent_ino);
    std::map<std::string, fuse_ino_t>::const_iterator parent_it = parent_children.find(name);
    if (parent_it == parent_children.end())
      return -ENOENT;

    assert(children_.find(newparent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& newparent_children = children_.at(newparent_ino);
    std::map<std::string, fuse_ino_t>::const_iterator newparent_it = newparent_children.find(newname);
    if (newparent_it != newparent_children.end())
      return -ENOTDIR;

    Inode *in = inode_get(parent_it->second);
    parent_children.erase(parent_it);
    newparent_children[newname] = in->ino();

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_ctime = now;

    return 0;
  }

  int SetAttr(fuse_ino_t ino, struct stat *attr, int to_set,
      uid_t uid, gid_t gid)
  {
    MutexLock l(&mutex_);

    Inode *in = inode_get(ino);
    assert(in);

    if (to_set & FUSE_SET_ATTR_MODE)
      in->i_st.st_mode = attr->st_mode;

    if (to_set & FUSE_SET_ATTR_UID)
      in->i_st.st_uid = attr->st_uid;

    if (to_set & FUSE_SET_ATTR_GID)
      in->i_st.st_gid = attr->st_gid;

    if (to_set & FUSE_SET_ATTR_MTIME)
      in->i_st.st_mtime = attr->st_mtime;

    if (to_set & FUSE_SET_ATTR_ATIME)
      in->i_st.st_atime = attr->st_atime;

    if (to_set & FUSE_SET_ATTR_SIZE)
      in->i_st.st_size = attr->st_size;

    *attr = in->i_st;

    return 0;
  }

  int Symlink(const std::string& link, fuse_ino_t parent_ino,
      const std::string& name, struct stat *st, uid_t uid, gid_t gid)
  {
    MutexLock l(&mutex_);

    assert(children_.find(parent_ino) != children_.end());
    std::map<std::string, fuse_ino_t>& children = children_.at(parent_ino);
    if (children.find(name) != children.end())
      return -EEXIST;

    Inode *in = new Inode(next_ino_++);
    in->get();

    children[name] = in->ino();
    ino_to_inode_[in->ino()] = in;
    symlinks_[in->ino()] = link;

    in->i_st.st_ino = in->ino();
    in->i_st.st_mode = S_IFLNK;
    in->i_st.st_nlink = 1;
    in->i_st.st_blksize = 4096;
    in->i_st.st_uid = uid;
    in->i_st.st_gid = gid;
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    in->i_st.st_atime = now;
    in->i_st.st_mtime = now;
    in->i_st.st_ctime = now;
    in->i_st.st_birthtime = now;

    *st = in->i_st;

    return 0;
  }

  int Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid)
  {
    MutexLock l(&mutex_);

    Inode *in = inode_get(ino);
    assert(in);
    assert(in->i_st.st_mode & S_IFLNK);

    assert(symlinks_.find(ino) != symlinks_.end());
    const std::string& link = symlinks_.at(ino);
    int link_len = link.size();

    if (link_len > maxlen)
      return -ENAMETOOLONG;

    std::strncpy(path, link.c_str(), maxlen);

    return link_len;
  }

  /*
   *
   */
  Inode *inode_get(fuse_ino_t ino) {
    std::map<fuse_ino_t, Inode*>::const_iterator it = ino_to_inode_.find(ino);
    if (it == ino_to_inode_.end())
      return NULL;
    return it->second;
  }

 private:
  /*
   *
   */
  void put_inode(fuse_ino_t ino, long unsigned dec = 1) {
    std::map<fuse_ino_t, Inode*>::const_iterator it = ino_to_inode_.find(ino);
    assert(it != ino_to_inode_.end());
    Inode *in = it->second;
    if (!in->put(dec)) {
      ino_to_inode_.erase(ino);
      delete in;
    }
  }

  fuse_ino_t next_ino_;
  Mutex mutex_;
  std::map<fuse_ino_t, std::map<std::string, fuse_ino_t>> children_;
  std::map<fuse_ino_t, Inode*> ino_to_inode_;
  std::map<fuse_ino_t, std::string> symlinks_;
  BlockAllocator *ba_;
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

  delete fh;
  fs->Release(ino);
  fuse_reply_err(req, 0);
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  int ret = fs->Unlink(parent, name);
  fuse_reply_err(req, -ret);
}

static void ll_forget(fuse_req_t req, fuse_ino_t ino, long unsigned nlookup)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  fs->Forget(ino, nlookup);
  fuse_reply_none(req);
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  struct stat st;

  int ret = fs->GetAttr(ino, &st);
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

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
		       fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

#define xmin(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      xmin(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

/*
 *
 */
static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  struct dirbuf b;
  memset(&b, 0, sizeof(b));
  dirbuf_add(req, &b, ".", 1);
  dirbuf_add(req, &b, "..", 1);

  std::vector<std::string> names;
  fs->PathNames(ino, names);

  for (std::vector<std::string>::const_iterator it = names.begin(); it != names.end(); it++) {
    dirbuf_add(req, &b, it->c_str(), strlen(it->c_str()));
  }

  reply_buf_limited(req, b.p, b.size, off, size);
  free(b.p);
}

static void ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);
  FileHandle *fh;

  assert(!(fi->flags & O_CREAT));

  int ret = fs->Open(ino, &fh);
  if (ret == 0) {
    fi->fh = (long)fh;
    fuse_reply_open(req, fi);
  } else
		fuse_reply_err(req, -ret);
}

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

  int ret = fs->Rmdir(parent, name);
  fuse_reply_err(req, -ret);
}

static void ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
			fuse_ino_t newparent, const char *newname)
{
  Gassy *fs = (Gassy*)fuse_req_userdata(req);

  int ret = fs->Rename(parent, name, newparent, newname);
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

  int ret = fs->Readlink(ino, path, sizeof(path) - 1, ctx->uid, ctx->gid);
  if (ret >= 0) {
    path[ret] = '\0';
    fuse_reply_readlink(req, path);
  } else
    fuse_reply_err(req, -ret);
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

int main(int argc, char *argv[])
{
  GASNET_SAFE(gasnet_init(&argc, &argv));

  size_t segsz = gasnet_getMaxLocalSegmentSize();
  GASNET_SAFE(gasnet_attach(NULL, 0, segsz, 0));

  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    return 0;
  }

  assert(gasnet_mynode() == 0);

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;

  // Operation registry
  struct fuse_lowlevel_ops ll_oper;
  memset(&ll_oper, 0, sizeof(ll_oper));
  ll_oper.lookup      = ll_lookup;
  ll_oper.getattr     = ll_getattr;
  ll_oper.readdir     = ll_readdir;
  ll_oper.open        = ll_open;
  ll_oper.read        = ll_read;
  ll_oper.write        = ll_write;
  ll_oper.create      = ll_create;
  ll_oper.release     = ll_release;
  ll_oper.unlink      = ll_unlink;
  ll_oper.forget      = ll_forget;
  ll_oper.mkdir       = ll_mkdir;
  ll_oper.rmdir       = ll_rmdir;
  ll_oper.rename      = ll_rename;
  ll_oper.setattr     = ll_setattr;
  ll_oper.symlink     = ll_symlink;
  ll_oper.readlink    = ll_readlink;
  ll_oper.fsync       = ll_fsync;
  ll_oper.fsyncdir    = ll_fsyncdir;

  BlockAllocator *ba = new BlockAllocator(segments, gasnet_nodes());
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


  gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
  gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);

  int rv = err ? 1 : 0;
  gasnet_exit(rv);
  return rv;
}

#if 0
  // not a huge priority
	void (*init) (void *userdata, struct fuse_conn_info *conn);
	void (*destroy) (void *userdata);
	void (*mknod) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);
	void (*link) (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		      const char *newname);
	void (*opendir) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);
	void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi);
	void (*setxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);
	void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  size_t size);
	void (*removexattr) (fuse_req_t req, fuse_ino_t ino, const char *name);
	void (*listxattr) (fuse_req_t req, fuse_ino_t ino, size_t size);
	void (*getlk) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi, struct flock *lock);
	void (*setlk) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi,
		       struct flock *lock, int sleep);
	void (*bmap) (fuse_req_t req, fuse_ino_t ino, size_t blocksize,
		      uint64_t idx);
	void (*poll) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi,
		      struct fuse_pollhandle *ph);
	void (*flock) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi, int op);

  // easy and priority
	void (*statfs) (fuse_req_t req, fuse_ino_t ino);
	void (*access) (fuse_req_t req, fuse_ino_t ino, int mask);
	void (*fallocate) (fuse_req_t req, fuse_ino_t ino, int mode,
		       off_t offset, off_t length, struct fuse_file_info *fi);

  // harder and priority
	void (*write_buf) (fuse_req_t req, fuse_ino_t ino,
			   struct fuse_bufvec *bufv, off_t off,
			   struct fuse_file_info *fi);
	void (*retrieve_reply) (fuse_req_t req, void *cookie, fuse_ino_t ino,
				off_t offset, struct fuse_bufvec *bufv);
	void (*forget_multi) (fuse_req_t req, size_t count,
			      struct fuse_forget_data *forgets);

  // v2
	void (*ioctl) (fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
		       struct fuse_file_info *fi, unsigned flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
#endif
