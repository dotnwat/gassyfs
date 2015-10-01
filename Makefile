
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
endif

CXX=g++ -g

CXXFLAGS += -Wall -std=c++11 -Wno-deprecated-register

GASNET_CPPFLAGS += -DGASNET_PAR=1 -I$(GASNET)/include
GASNET_LDFLAGS  += -L$(GASNET)/lib

CONDUIT ?= udp
ifeq ($(strip $(CONDUIT)),udp)
  GASNET_CPPFLAGS += -I$(GASNET)/include/udp-conduit
  GASNET_LIBS     += -lgasnet-udp-par -lamudp
endif

CPPFLAGS += $(shell pkg-config fuse --cflags)
LIBS += $(shell pkg-config fuse --libs)
LIBS += -lm

ifneq ($(shell uname -s),Darwin)
  LIBS += -lrt
endif

all: gassy-gn gassy-mem

gassy-gn: gassy.cc
	$(CXX) -DSTORE_GASNET $(CXXFLAGS) $(CPPFLAGS) $(GASNET_CPPFLAGS) $(LDFLAGS) $(GASNET_LDFLAGS) -o $@ $< $(LIBS) $(GASNET_LIBS)

gassy-mem: gassy.cc
	$(CXX) -DSTORE_LOCAL $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
