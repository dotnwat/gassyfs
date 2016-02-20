
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
endif

ifndef LUA_CPPFLAGS
  $(warning LUA_CPPFLAGS variable is not defined, continuing without Lua)
else
  CPPFLAGS += -I$(LUA_CPPFLAGS) -DHAVE_LUA
  LIBS     += $(shell pkg-config lua5.2 --libs)
endif

CXX=g++ -g

CXXFLAGS += -Wall -std=c++11 -Wno-unused-function
CPPFLAGS += -DGASNET_PAR=1
CPPFLAGS += -I$(GASNET)/include
LDFLAGS += -L$(GASNET)/lib

CONDUIT ?= udp
ifeq ($(strip $(CONDUIT)),udp)
  CPPFLAGS += -I$(GASNET)/include/udp-conduit
  LIBS     += -lgasnet-udp-par -lamudp
endif
ifeq ($(strip $(CONDUIT)),ibv)
  CPPFLAGS += -I$(GASNET)/include/ibv-conduit
  LIBS     += -lgasnet-ibv-par -libverbs
endif

CPPFLAGS += $(shell pkg-config fuse --cflags)
LIBS += $(shell pkg-config fuse --libs)
LIBS += -lm

ifneq ($(shell uname -s),Darwin)
  LIBS += -lrt
endif

all: gassy gassy-cmd

CPPFLAGS += -DFUSE_USE_VERSION=30

OBJS = gassy.o inode.o gassy_fs.o inode_index.o \
	   local_address_space.o gasnet_address_space.o

dep_files := $(foreach f, $(OBJS), $(dir f).depend/$(notdir $f).d)
dep_dirs := $(addsuffix .depend, $(sort $(dir $(OBJS))))

$(dep_dirs):
	@mkdir -p $@

missing_dep_dirs := $(filter-out $(wildcard $(dep_dirs)), $(dep_dirs))
dep_file = $(dir $@).depend/$(notdir $@).d
dep_args = -MF $(dep_file) -MQ $@ -MMD -MP

%.o: %.cc $(missing_dep_dirs)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $*.o -c $(dep_args) $<

gassy: $(OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

gassy-cmd: gassy-cmd.cc
	$(CXX) -Wall -o $@ $<

dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif

clean:
	rm -rf $(dep_dirs) $(OBJS) gassy
