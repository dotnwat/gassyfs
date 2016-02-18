
ifndef GASNET
  $(error GASNET variable is not defined, aborting build)
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

ifeq ($(shell uname -s),Darwin)
  CXXFLAGS += -Wno-deprecated-register
endif

ifneq ($(shell uname -s),Darwin)
  LIBS += -lrt
endif


CPPFLAGS += -DFUSE_USE_VERSION=30

OBJS = gassy.o inode.o block_allocator.o gassy_fs.o inode_index.o \
	   address_space.o

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

dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif

clean:
	rm -rf $(dep_dirs) $(OBJS) gassy
