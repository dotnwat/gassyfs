
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
endif

CXX=g++

CXXFLAGS += -Wall
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
LIBS += -lrt -lm

gassy: gassy.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
