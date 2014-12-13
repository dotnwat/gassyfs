INC=-I/usr/local/gasnet/include -I/usr/local/gasnet/include/udp-conduit
LIB=-L/usr/local/gasnet/lib
all:
	g++ $(INC) $(LIB) -DGASNET_PAR=1 -Wall gassy.cc `pkg-config fuse --cflags --libs` -lgasnet-udp-par -lamudp -lrt -o gassy
