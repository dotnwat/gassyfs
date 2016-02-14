#ifndef GASSYFS_GASSY_FS_H_
#define GASSYFS_GASSY_FS_H_
#include <cassert>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include "common.h"
#include "inode.h"
#include "file_handle.h"

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

  void Release(fuse_ino_t ino, FileHandle *fh);

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

  int SetAttr(fuse_ino_t ino, FileHandle *fh, struct stat *attr, int to_set,
      uid_t uid, gid_t gid);

  int Symlink(const std::string& link, fuse_ino_t parent_ino,
      const std::string& name, struct stat *st, uid_t uid, gid_t gid);

  ssize_t Readlink(fuse_ino_t ino, char *path, size_t maxlen, uid_t uid, gid_t gid);

  int Statfs(fuse_ino_t ino, struct statvfs *stbuf);

  int Link(fuse_ino_t ino, fuse_ino_t newparent_ino, const std::string& newname,
      struct stat *st, uid_t uid, gid_t gid);

  int Access(Inode::Ptr in, int mask, uid_t uid, gid_t gid);

  int Access(fuse_ino_t ino, int mask, uid_t uid, gid_t gid);

  int Mknod(fuse_ino_t parent_ino, const std::string& name, mode_t mode,
      dev_t rdev, struct stat *st, uid_t uid, gid_t gid);

  int OpenDir(fuse_ino_t ino, int flags, uid_t uid, gid_t gid);

  ssize_t ReadDir(fuse_req_t req, fuse_ino_t ino, char *buf,
      size_t bufsize, off_t off);

  void ReleaseDir(fuse_ino_t ino);

 private:
  int Truncate(Inode::Ptr in, off_t newsize, uid_t uid, gid_t gid);
  ssize_t Write(Inode::Ptr in, off_t offset, size_t size, const char *buf);

  fuse_ino_t next_ino_;
  std::mutex mutex_;
  BlockAllocator *ba_;
  struct statvfs stat;

  class InodeTable {
   public:
    void add(Inode::Ptr inode) {
      assert(refs_.find(inode->ino()) == refs_.end());
      assert(inode->lookup_get());
      refs_[inode->ino()] = inode;
    }

    void get(Inode::Ptr inode) {
      auto it = refs_.find(inode->ino());
      if (inode->lookup_get()) {
        assert(it == refs_.end());
        refs_[inode->ino()] = inode;
      } else
        assert(it != refs_.end());
    }

    void put(fuse_ino_t ino, long int dec) {
      auto it = refs_.find(ino);
      assert(it != refs_.end());
      if (it->second->lookup_put(dec))
        refs_.erase(it);
    }

    Inode::Ptr inode(fuse_ino_t ino) {
      return refs_.at(ino);
    }

    DirInode::Ptr dir_inode(fuse_ino_t ino) {
      auto in = inode(ino);
      assert(in->is_directory());
      return std::static_pointer_cast<DirInode>(in);
    }

    SymlinkInode::Ptr symlink_inode(fuse_ino_t ino) {
      auto in = inode(ino);
      assert(in->is_symlink());
      return std::static_pointer_cast<SymlinkInode>(in);
    }

    uint64_t nfiles() {
      uint64_t ret = 0;
      for (auto it = refs_.begin(); it != refs_.end(); it++)
        if (it->second->i_st.st_mode & S_IFREG)
          ret++;
      return ret;
    }

   private:
    std::unordered_map<fuse_ino_t, Inode::Ptr> refs_;
  };

  InodeTable ino_refs_;
};

#endif
