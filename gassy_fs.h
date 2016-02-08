#include <fuse.h>
#include <fuse_lowlevel.h>
#include <unordered_map>
#include <map>
#include <string>
#include <mutex>
#include "common.h"

class BlockAllocator;

class GassyFs {
 public:
  explicit GassyFs(BlockAllocator *ba);

  int Create(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      int flags, struct stat *st, FileHandle **fhp, uid_t uid, gid_t gid);

  int GetAttr(fuse_ino_t ino, struct stat *st, uid_t uid, gid_t gid);

  int Unlink(fuse_ino_t parent_ino, const std::string& name, uid_t uid, gid_t gid);

  int Lookup(fuse_ino_t parent_ino, const std::string& name, struct stat *st);

  int Open(fuse_ino_t ino, int flags, FileHandle **fhp, uid_t uid, gid_t gid);

  void Release(fuse_ino_t ino);

  void Forget(fuse_ino_t ino, long unsigned nlookup);

  ssize_t Write(FileHandle *fh, off_t offset, size_t size, const char *buf);

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
  ssize_t WriteBuf(FileHandle *fh, struct fuse_bufvec *bufv, off_t off);
#endif

  ssize_t Read(FileHandle *fh, off_t offset, size_t size, char *buf);

  int Mkdir(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      struct stat *st, uid_t uid, gid_t gid);

  int Rmdir(fuse_ino_t parent_ino, const std::string& name,
      uid_t uid, gid_t gid);

  int Rename(fuse_ino_t parent_ino, const std::string& name,
      fuse_ino_t newparent_ino, const std::string& newname,
      uid_t uid, gid_t gid);

  int SetAttr(fuse_ino_t ino, struct stat *attr, int to_set,
      uid_t uid, gid_t gid);

  int Symlink(const std::string& link, fuse_ino_t parent_ino,
      const std::string& name, struct stat *st, uid_t uid, gid_t gid);

  int Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid);

  int Statfs(fuse_ino_t ino, struct statvfs *stbuf);

  int Link(fuse_ino_t ino, fuse_ino_t newparent_ino, const std::string& newname,
      struct stat *st, uid_t uid, gid_t gid);

  int Access(Inode *in, int mask, uid_t uid, gid_t gid);

  int Access(fuse_ino_t ino, int mask, uid_t uid, gid_t gid);

  int Mknod(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      dev_t rdev, struct stat *st, uid_t uid, gid_t gid);

  int OpenDir(fuse_ino_t ino, int flags, uid_t uid, gid_t gid);

  ssize_t ReadDir(fuse_req_t req, fuse_ino_t ino, char *buf,
      size_t bufsize, off_t off);

  void ReleaseDir(fuse_ino_t ino);

 private:
  typedef std::unordered_map<fuse_ino_t, Inode*> inode_table_t;
  typedef std::unordered_map<fuse_ino_t, std::string> symlink_table_t;

  int Truncate(Inode *in, off_t newsize, uid_t uid, gid_t gid);

  ssize_t Write(Inode *in, off_t offset, size_t size, const char *buf);

  Inode *inode_get(fuse_ino_t ino) const;

  void put_inode(fuse_ino_t ino, long unsigned dec = 1);

  fuse_ino_t next_ino_;
  std::mutex mutex_;
  inode_table_t ino_to_inode_;
  symlink_table_t symlinks_;
  BlockAllocator *ba_;
  struct statvfs stat;
};
