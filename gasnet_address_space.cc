#include "address_space.h"
#include <cassert>
#include <iostream>
#include <sys/mman.h>
#include <gasnet.h>
#include <gasnet_tools.h>
#include "common.h"

class GASNetNodeImpl : public Node {
 public:
  GASNetNodeImpl(gasnet_node_t node, void *base, uintptr_t size) :
    node_(node), base_((char*)base), size_(size)
  {}

  size_t size() {
    return size_;
  }

  void read(void *dst, void *src, size_t len) {
    char *abs_src = base_ + (uintptr_t)src;
    assert((abs_src + len - 1) < (base_ + size_));
    gasnet_get_bulk(dst, node_, abs_src, len);
  }

  void write(void *dst, void *src, size_t len) {
    char *abs_dst = base_ + (uintptr_t)dst;
    assert((abs_dst + len - 1) < (base_ + size_));
    gasnet_put_bulk(node_, abs_dst, src, len);
  }

  void aio_read(group_io_handle_t handle, void *dst, void *src, size_t len) {
    char *abs_src = base_ + (uintptr_t)src;
    assert((abs_src + len - 1) < (base_ + size_));
    gasnet_handle_t h = gasnet_get_nb_bulk(dst, node_, abs_src, len);
    auto handles = static_cast<std::vector<gasnet_handle_t>*>(handle);
    handles->push_back(h);
  }

  void aio_write(group_io_handle_t handle, void *dst, void *src, size_t len) {
    char *abs_dst = base_ + (uintptr_t)dst;
    assert((abs_dst + len - 1) < (base_ + size_));
    gasnet_handle_t h = gasnet_put_nb_bulk(node_, abs_dst, src, len);
    auto handles = static_cast<std::vector<gasnet_handle_t>*>(handle);
    handles->push_back(h);
  }

 private:
  gasnet_node_t node_;
  char *base_;
  uintptr_t size_;
};


Node::group_io_handle_t GASNetAddressSpace::group_io_start()
{
  auto handles = new std::vector<gasnet_handle_t>;
  handles->reserve(4);
  return handles;
}

void GASNetAddressSpace::group_io_wait(Node::group_io_handle_t handle)
{
  auto handles = static_cast<std::vector<gasnet_handle_t>*>(handle);
  size_t num_handles = handles->size();
  if (num_handles)
    gasnet_wait_syncnb_all(handles->data(), num_handles);
  delete handles;
}

#ifdef GASNET_SEGMENT_EVERYTHING

static gasnet_seginfo_t *segments_ptr;
static int seginfo_done;
static gasnet_hsl_t seginfo_lock;

#define AM_SEGINFO 128

static void AM_seginfo(gasnet_token_t token, void *buf, size_t nbytes)
{
  gasnet_node_t src;
  GASNET_SAFE(gasnet_AMGetMsgSource(token, &src));

  gasnet_seginfo_t contrib;
  assert(nbytes == sizeof(contrib));
  memcpy(&contrib, buf, sizeof(contrib));

  // barrier: seginfo_done is checked without lock
  gasnett_local_wmb();

  gasnet_hsl_lock(&seginfo_lock);
  segments_ptr[src] = contrib;
  seginfo_done++;
  gasnet_hsl_unlock(&seginfo_lock);
}

int GASNetAddressSpace::init(int *argc, char ***argv,
    struct gassyfs_opts *opts)
{
  std::cout << "gasnet segment = everything" << std::endl;

  GASNET_SAFE(gasnet_init(argc, argv));

  // handler for sending segment info to rank 0
  gasnet_handlerentry_t handlers[1];
  handlers[0].index = AM_SEGINFO;
  handlers[0].fnptr = (void(*)())AM_seginfo;

  // segment info ignored for gasnet-everything
  GASNET_SAFE(gasnet_attach(handlers, 1, 0, 0));

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));

  gasnet_hsl_init(&seginfo_lock);
  segments_ptr = segments;
  seginfo_done = 0;

  // synchronized everyone before sending AMs so rank 0 initialization of
  // segments structure above doesn't race. could also hold lock above...
  gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
  gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);

  /*
   * currently rank 0 also contributes memory. We want to avoid this in the
   * future because rank 0 should have a large kernel cache for the FUSE
   * mount. But we over ride the decision if there is only one node in the
   * cluster.
   */
  if (!opts->rank0_alloc) {
    if (gasnet_nodes() == 1)
      opts->rank0_alloc = 1;
  }

  // heap contribution
  gasnet_seginfo_t contrib;
  contrib.addr = 0;
  contrib.size = 0;

  // if not rank 0 or alloc on rank 0 is OK
  if (gasnet_mynode() || opts->rank0_alloc) {
    const size_t size = opts->heap_size << 20;
    void *data = mmap(NULL, size, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(data != MAP_FAILED);

    contrib.addr = data;
    contrib.size = size;
  }

  // notify rank 0 of contribution (rank 0 sends to self)
  GASNET_SAFE(gasnet_AMRequestMedium0(0, AM_SEGINFO,
        &contrib, sizeof(contrib)));

  // everyone but rank 0 snoozes now
  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    assert(0);
    return 0;
  }

  // wait for nodes to report on contribution
  GASNET_BLOCKUNTIL((seginfo_done == gasnet_nodes()));

  gasnet_hsl_lock(&seginfo_lock);
  assert(seginfo_done == gasnet_nodes());

  for (int i = 0; i < gasnet_nodes(); i++) {
    gasnet_seginfo_t *s = &segments[i];
    if (s->size == 0)
      continue;

    GASNetNodeImpl *node = new GASNetNodeImpl(i,
        s->addr, s->size);

    nodes_.push_back(node);
  }

  gasnet_hsl_unlock(&seginfo_lock);

  assert(gasnet_mynode() == 0);

  return 0;
}

#else

/*
 * When GASNet is configured with segment-[fast|large] then GASNet will
 * allocate and register memory segments automatically.
 */
int GASNetAddressSpace::init(int *argc, char ***argv,
    struct gassyfs_opts *opts)
{
  std::cout << "gasnet segment = fast|large" << std::endl;

  GASNET_SAFE(gasnet_init(argc, argv));

  // how much this rank will try to allocate
  size_t segsz = gasnet_getMaxLocalSegmentSize();

  /*
   * Rank 0 allocation can be disabled, but that configuration is overridden
   * when there is only one node in the GASNet cluster.
   */
  if (!opts->rank0_alloc) {
    if (gasnet_nodes() == 1)
      opts->rank0_alloc = 1;
    else if (gasnet_mynode() == 0)
      segsz = 0;
  }

  GASNET_SAFE(gasnet_attach(NULL, 0, segsz, 0));

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));

  // all nodes except rank 0 can start serving memory
  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    assert(0);
    return 0;
  }

  size_t total = 0;
  size_t num_nodes = 0;

  for (int i = 0; i < gasnet_nodes(); i++) {
    gasnet_seginfo_t *s = &segments[i];
    if (s->size == 0)
      continue;

    GASNetNodeImpl *node = new GASNetNodeImpl(i,
        s->addr, s->size);

    nodes_.push_back(node);

    total += node->size();
    num_nodes++;
  }

  opts->heap_size = (total >> 20) / num_nodes;

  assert(gasnet_mynode() == 0);

  return 0;
}

#endif
