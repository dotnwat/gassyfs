#ifndef GASSYFS_ALLOC_H_
#define GASSYFS_ALLOC_H_
/*
 * Adapted from:
 * https://github.com/StanfordLegion/legion/blob/stable/runtime/realm/mem_impl.cc 
 *
 * This might not be the best allocation strategy, but it should work for the
 * time being.
 */
#include <cassert>
#include <deque>
#include <map>
#include <errno.h>
#include "json.hpp"

using json = nlohmann::json;

class Allocator {
 public:
  explicit Allocator(size_t size) {
    alignment = 0;
    free_blocks[0] = size;
  }

  off_t alloc(size_t size) {
    assert(size);

    if (alignment > 0) {
      assert(0);
      off_t leftover = size % alignment;
      if (leftover > 0) {
        size += (alignment - leftover);
      }
    }

    // HACK: pad the size by a bit to see if we have people falling off
    //  the end of their allocations
    size += 0;

    if (free_blocks.empty())
      return -ENOMEM;

    std::map<off_t, off_t>::iterator it = free_blocks.end();

    do {
      --it;

      if (it->second == (off_t)size) {
        off_t retval = it->first;
        free_blocks.erase(it);
        return retval;
      }

      if (it->second > (off_t)size) {
        off_t leftover = it->second - size;
        off_t retval = it->first + leftover;
        it->second = leftover;
        return retval;
      }

    } while (it != free_blocks.begin());

    return -ENOMEM;
  }

  void free(off_t offset, size_t size) {
    assert(size);

    if (alignment > 0) {
      off_t leftover = size % alignment;
      if (leftover > 0) {
        size += (alignment - leftover);
      }
    }

    if (!free_blocks.empty()) {
      // find the first existing block that comes _after_ us
      std::map<off_t, off_t>::iterator after = free_blocks.lower_bound(offset);
      if (after != free_blocks.end()) {
        // found one - is it the first one?
        if (after == free_blocks.begin()) {
          // yes, so no "before"
          assert((offset + (off_t)size) <= after->first); // no overlap!
          if((offset + (off_t)size) == after->first) {
            // merge the ranges by eating the "after"
            size += after->second;
            free_blocks.erase(after);
          }
          free_blocks[offset] = size;
        } else {
          // no, get range that comes before us too
          std::map<off_t, off_t>::iterator before = after;
          before--;

          // if we're adjacent to the after, merge with it
          assert((offset + (off_t)size) <= after->first); // no overlap!
          if((offset + (off_t)size) == after->first) {
            // merge the ranges by eating the "after"
            size += after->second;
            free_blocks.erase(after);
          }

          // if we're adjacent with the before, grow it instead of adding
          //  a new range
          assert((before->first + before->second) <= offset);
          if((before->first + before->second) == offset) {
            before->second += size;
          } else {
            free_blocks[offset] = size;
          }
        }
      } else {
        // nothing's after us, so just see if we can merge with the range
        // that's before us

        std::map<off_t, off_t>::iterator before = after;
        before--;

        // if we're adjacent with the before, grow it instead of adding
        // a new range
        assert((before->first + before->second) <= offset);
        if((before->first + before->second) == offset) {
          before->second += size;
        } else {
          free_blocks[offset] = size;
        }
      }
    } else {
      // easy case - nothing was free, so now just our block is
      free_blocks[offset] = size;
    }
  }

  /*
   * serialize allocator state to json
   */
  void to_json(json& out) {
    out["alignment"] = alignment;
    json blocks = json::array();
    for (auto& entry : free_blocks) {
      json block = json::object();
      block["offset"] = entry.first;
      block["length"] = entry.second;
      blocks.push_back(block);
    }
    out["free_blocks"] = blocks;
  }

  /*
   * restore from json
   */
  void restore(json& cp) {
    alignment = cp["alignment"];
    free_blocks.clear();
    for (auto& entry : cp["free_blocks"]) {
      free_blocks[entry["offset"]] = entry["length"];
    }
  }

 private:
  size_t alignment;
  std::map<off_t, off_t> free_blocks;
};

#endif
