#include "address_space.h"
#include <iostream>
#include <gasnet.h>
#include "common.h"

int AddressSpace::init(int *argc, char ***argv)
{
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

void AddressSpace::write(int node, void *dst, void *src, size_t len)
{
  gasnet_put_bulk(nodes[node].node, dst, src, len);
}

void AddressSpace::read(void *dest, int node, void *src, size_t len)
{
  gasnet_get_bulk(dest, nodes[node].node, src, len);
}
