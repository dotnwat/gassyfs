#include "inode.h"
#include <cassert>
#include <fuse.h>
#include "json.hpp"
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
  return S_ISDIR(i_st.st_mode);
}

bool Inode::is_symlink() const
{
  return S_ISLNK(i_st.st_mode);
}

bool Inode::is_regular() const
{
  return S_ISREG(i_st.st_mode);
}

std::string Inode::type_name() const
{
  if (is_regular())
    return "regular";
  else if (is_directory())
    return "directory";
  else if (is_symlink())
    return "symlink";
  else
    assert(0);
}

bool Inode::setlua_atime(std::string policy)
{
  return lua_atime.assign(policy) == policy;
}

std::string Inode::getlua_atime()
{
  std::string policy = lua_atime;
  if (!lua_atime.empty())
    printf("atime policy: \n===\n%s===\n", lua_atime.c_str());
  std::string ret(lua_atime.c_str());
  return lua_atime.c_str();
}

Inode::Ptr Inode::from_json(json& state)
{
  if (state["type"] == "regular") {
  } else if (state["type"] == "directory") {
  } else if (state["type"] == "symlink") {
  } else
    assert(0);
}

void Inode::to_json(json& inode)
{
  inode["ino"]        =  ino();
  inode["st_dev"]     =  i_st.st_dev;
  inode["st_mode"]    =  i_st.st_mode;
  inode["st_nlink"]   =  i_st.st_nlink;
  inode["st_uid"]     =  i_st.st_uid;
  inode["st_gid"]     =  i_st.st_gid;
  inode["st_rdev"]    =  i_st.st_rdev;
  inode["st_size"]    =  i_st.st_size;
  inode["st_blksize"] =  i_st.st_blksize;
  inode["st_blocks"]  =  i_st.st_blocks;
  inode["st_atime"]   =  i_st.st_atime;
  inode["st_mtime"]   =  i_st.st_mtime;
  inode["st_ctime"]   =  i_st.st_ctime;
  inode["type"]       =  type_name();

  // avoid special case with RegInode type
  if (is_regular()) {
    json extents = json::array();
    for (auto it : extents_) {
      extents.push_back({
        {"offset", it.first},
        {"length", it.second.length},
        {"nodeid",  it.second.node->node->id()},
        {"phyaddr", it.second.addr},
        {"physize", it.second.size},
      });
    }
    inode["extents"] = extents;
  } else
    assert(is_directory() || is_symlink());
}

void DirInode::to_json(json& inode)
{
  Inode::to_json(inode);

  json children = json::array();
  for (auto entry : dentries) {
    children.push_back({
      {"name", entry.first},
      {"ino", entry.second->ino()},
    });
  }
  inode["children"] = children;
}

void SymlinkInode::to_json(json& inode)
{
  Inode::to_json(inode);

  inode["link"] = link;
}
