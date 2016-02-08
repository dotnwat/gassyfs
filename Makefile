
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
endif

CXX=g++ -g

CXXFLAGS += -Wall -std=c++11 -Wno-deprecated-register
CPPFLAGS += -DGASNET_PAR=1
CPPFLAGS += -I$(GASNET)/include
LDFLAGS += -L$(GASNET)/lib

CONDUIT ?= udp
ifeq ($(strip $(CONDUIT)),udp)
  CPPFLAGS += -I$(GASNET)/include/udp-conduit
  LIBS     += -lgasnet-udp-par -lamudp
endif

CPPFLAGS += $(shell pkg-config fuse --cflags)
LIBS += $(shell pkg-config fuse --libs)
LIBS += -lm

ifneq ($(shell uname -s),Darwin)
  LIBS += -lrt
endif

CPPFLAGS += -DFUSE_USE_VERSION=30

OBJS = inode.o block_allocator.o gassy_fs.o

%.o: %.cc %.h
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c -o $@ $<

gassy: gassy.cc $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) gassy
