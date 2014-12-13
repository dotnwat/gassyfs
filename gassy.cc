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

#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>
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


class Inode;
static std::map<fuse_ino_t, Inode*> ino_inodes;

class Inode {
 public:
  Inode() : ref_(1) {}

  void get() {
    assert(ref_);
    ref_++;
    printf("get: ino:%lu ref:%ld\n", ino, ref_);
    fflush(0);
  }

  void put(long int dec = 1) {
    assert(ref_);
    ref_ -= dec;
    assert(ref_ >= 0);
    printf("put: ino:%lu ref:%ld\n", ino, ref_);
    fflush(0);
    if (ref_ == 0) {
      assert(ino_inodes.count(ino));
      ino_inodes.erase(ino);
      delete this;
    }
  }

  fuse_ino_t ino;
  struct stat i_st;

 private:
  long int ref_;
};

static std::map<std::string, Inode*> path_inodes;
static fuse_ino_t next_inode_num = FUSE_ROOT_ID + 1;
static pthread_mutex_t mutex;

/*
 *
 */
static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, struct fuse_file_info *fi)
{
  assert(parent == FUSE_ROOT_ID);

	printf("create: parent:%lu name:%s\n", parent, name);
    fflush(0);

  pthread_mutex_lock(&mutex);

  Inode *in;
  std::string fname(name);
  if (path_inodes.count(fname) == 0) {
    in = new Inode;
    memset(&in->i_st, 0, sizeof(in->i_st));
    in->ino = next_inode_num++;
    in->get();
    path_inodes[fname] = in;
    ino_inodes[in->ino] = in;
  } else
    assert(0);

  in->i_st.st_ino = in->ino;
  in->i_st.st_mode = S_IFREG | 0666;
  in->i_st.st_nlink = 1;
  in->i_st.st_blksize = 4096;

  struct fuse_entry_param fe;
  memset(&fe, 0, sizeof(fe));

  fe.attr = in->i_st;
  fe.ino = fe.attr.st_ino;
  fe.generation = 1;
  fe.entry_timeout = 1.0;

	fuse_reply_create(req, &fe, fi);

  pthread_mutex_unlock(&mutex);
}

static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  printf("release: %lu\n", ino);
    fflush(0);

  pthread_mutex_lock(&mutex);
  assert(ino_inodes.count(ino));

  Inode *in = ino_inodes[ino];
  in->put();

  fuse_reply_err(req, 0);

  pthread_mutex_unlock(&mutex);
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
  printf("unlink: parent:%lu name:%s\n", parent, name);
    fflush(0);

  pthread_mutex_lock(&mutex);

  std::string fname(name);
  if (path_inodes.count(fname)) {
    path_inodes.erase(fname);
    fuse_reply_err(req, 0);
  } else
    fuse_reply_err(req, ENOENT);

  pthread_mutex_unlock(&mutex);
}

static void ll_forget(fuse_req_t req, fuse_ino_t ino, long unsigned nlookup)
{
  printf("forget: ino:%lu nlookup:%lu\n", ino, nlookup);
  fflush(0);

  pthread_mutex_lock(&mutex);
  assert(ino_inodes.count(ino));

  Inode *in = ino_inodes[ino];
  in->put(nlookup);

  pthread_mutex_unlock(&mutex);

  fuse_reply_none(req);
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
  printf("getattr: ino:%lu\n", ino);
  fflush(0);

  pthread_mutex_lock(&mutex);

  if (ino_inodes.count(ino)) {
    Inode *in = ino_inodes[ino];
    fuse_reply_attr(req, &in->i_st, 0);
  } else
    fuse_reply_err(req, ENOENT);

  pthread_mutex_unlock(&mutex);
}

static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	printf("lookup: parent:%lu, name:%s\n", parent, name);
    fflush(0);

  pthread_mutex_lock(&mutex);

  std::string fname(name);
  if (path_inodes.count(fname)) {
    Inode *in = path_inodes[fname];
    assert(ino_inodes.count(in->ino));
    assert(ino_inodes[in->ino] == in);

    struct fuse_entry_param fe;
    memset(&fe, 0, sizeof(fe));
    fe.attr = in->i_st;
    fe.ino = in->ino;
    fe.generation = 1;
    
    in->get();

		fuse_reply_entry(req, &fe);
  } else
		fuse_reply_err(req, ENOENT);

  pthread_mutex_unlock(&mutex);
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

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

/*
 *
 */
static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *fi)
{
  assert(ino == FUSE_ROOT_ID);

  printf("readdir: ino:%lu\n", ino);
  fflush(0);

  pthread_mutex_lock(&mutex);

  struct dirbuf b;

  memset(&b, 0, sizeof(b));
  dirbuf_add(req, &b, ".", 1);
  dirbuf_add(req, &b, "..", 1);

  for (std::map<std::string, Inode*>::const_iterator it = path_inodes.begin();
      it != path_inodes.end(); it++) {
    dirbuf_add(req, &b, it->first.c_str(), strlen(it->first.c_str()));
  }

  reply_buf_limited(req, b.p, b.size, off, size);
  free(b.p);

  pthread_mutex_unlock(&mutex);
}

static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
  printf("open: %lu\n", ino);
  fflush(0);

  pthread_mutex_lock(&mutex);

  assert(!(fi->flags & O_CREAT));

  if (ino_inodes.count(ino)) {
    Inode *in = ino_inodes[ino];
    in->get();
    fuse_reply_open(req, fi);
  } else
		fuse_reply_err(req, ENOENT);

  pthread_mutex_unlock(&mutex);
}

static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
	(void) fi;
	printf("read: %lu\n", ino);
    fflush(0);

	assert(ino == 2);
  static const char *hello_str = "asdf";
	reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
}

int main(int argc, char *argv[])
{
  GASNET_SAFE(gasnet_init(&argc, &argv));

  size_t segsz = gasnet_getMaxLocalSegmentSize();
  GASNET_SAFE(gasnet_attach(NULL, 0, segsz, 0));

  if (gasnet_mynode()) {
    gasnet_barrier_notify(0,GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0,GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    exit(0);
  }

  assert(gasnet_mynode() == 0);

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));



	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	char *mountpoint;
	int err = -1;

  struct fuse_lowlevel_ops hello_ll_oper;
  memset(&hello_ll_oper, 0, sizeof(hello_ll_oper));
hello_ll_oper.lookup=		 hello_ll_lookup;
hello_ll_oper.getattr=	 hello_ll_getattr;
hello_ll_oper.readdir=	 hello_ll_readdir;
hello_ll_oper.open=		 hello_ll_open;
hello_ll_oper.read=		 hello_ll_read;
hello_ll_oper.create=		 ll_create;
hello_ll_oper.release = ll_release;
hello_ll_oper.unlink = ll_unlink;
hello_ll_oper.forget = ll_forget;

  pthread_mutex_init(&mutex, NULL);

  // add root inode
  Inode *root = new Inode;
  root->ino = FUSE_ROOT_ID;
  root->i_st.st_mode = S_IFDIR | 0755;
  root->i_st.st_nlink = 2;
  ino_inodes[root->ino] = root;


	if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
	    (ch = fuse_mount(mountpoint, &args)) != NULL) {
		struct fuse_session *se;

		se = fuse_lowlevel_new(&args, &hello_ll_oper,
				       sizeof(hello_ll_oper), NULL);
		if (se != NULL) {
			if (fuse_set_signal_handlers(se) != -1) {
				fuse_session_add_chan(se, ch);
				err = fuse_session_loop(se);
				fuse_remove_signal_handlers(se);
				fuse_session_remove_chan(ch);
			}
			fuse_session_destroy(se);
		}
		fuse_unmount(mountpoint, ch);
	}
	fuse_opt_free_args(&args);

	return err ? 1 : 0;
}
