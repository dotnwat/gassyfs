#include "address_space.h"
#include <cassert>
#include <iostream>
#include <sys/mman.h>
#include <gasnet.h>
#include <gasnet_tools.h>
#include "common.h"

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

int AddressSpace::init(int *argc, char ***argv)
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
   * mount.
   */
  const size_t size = 1ULL << 30;
  void *data = mmap(NULL, size, PROT_READ|PROT_WRITE,
      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  assert(data != MAP_FAILED);

  // notify rank 0 of contribution (rank 0 sends to self)
  gasnet_seginfo_t contrib;
  contrib.addr = data;
  contrib.size = size;
  GASNET_SAFE(gasnet_AMRequestMedium0(0, AM_SEGINFO,
        &contrib, sizeof(contrib)));

  // everyone but rank 0 snoozes now
  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    return 0;
  }

  // wait for nodes to report on contribution
  GASNET_BLOCKUNTIL((seginfo_done == gasnet_nodes()));

  gasnet_hsl_lock(&seginfo_lock);
  assert(seginfo_done == gasnet_nodes());

  for (int i = 0; i < gasnet_nodes(); i++) {
    Segment seg;
    seg.addr = (size_t)segments[i].addr;
    seg.len = segments[i].size;

    Node node;
    node.segment = seg;
    node.node = i;

    nodes.push_back(node);

    std::cout << "node-%02d: segment: " <<
      segments[i].size << "/" << segments[i].addr << std::endl;
  }

  gasnet_hsl_unlock(&seginfo_lock);

  return 0;
}
#else
int AddressSpace::init(int *argc, char ***argv)
{
  std::cout << "gasnet segment = fast|large" << std::endl;

  GASNET_SAFE(gasnet_init(argc, argv));

  size_t segsz = gasnet_getMaxLocalSegmentSize();
  GASNET_SAFE(gasnet_attach(NULL, 0, segsz, 0));

  gasnet_seginfo_t segments[gasnet_nodes()];
  GASNET_SAFE(gasnet_getSegmentInfo(segments, gasnet_nodes()));

  if (gasnet_mynode()) {
    gasnet_barrier_notify(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_barrier_wait(0, GASNET_BARRIERFLAG_ANONYMOUS);
    gasnet_exit(0);
    return 0;
  }

  for (int i = 0; i < gasnet_nodes(); i++) {
    Segment seg;
    seg.addr = (size_t)segments[i].addr;
    seg.len = segments[i].size;

    Node node;
    node.segment = seg;
    node.node = i;

    nodes.push_back(node);

    std::cout << "node-%02d: segment: " <<
      segments[i].size << "/" << segments[i].addr << std::endl;
  }

  return 0;
}
#endif

void AddressSpace::write(int node, void *dst, void *src, size_t len)
{
  gasnet_put_bulk(nodes[node].node, dst, src, len);
}

void AddressSpace::read(void *dest, int node, void *src, size_t len)
{
  gasnet_get_bulk(dest, nodes[node].node, src, len);
}
