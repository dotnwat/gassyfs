#ifndef GASSYFS_FILE_HANDLE_H_
#define GASSYFS_FILE_HANDLE_H_
#include "inode.h"

struct FileHandle {
  Inode::Ptr in;
  off_t pos;
  int flags;

  FileHandle(Inode::Ptr in) :
    in(in), pos(0), flags(0)
  {}
};

#endif
