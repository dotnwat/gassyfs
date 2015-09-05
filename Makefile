
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
endif

CXX=g++

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
	LD_FLAGS	+= -lrt
endif

gassy: gassy.cc
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
