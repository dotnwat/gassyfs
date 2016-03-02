node0   clnode010   c8220   ssh -p 22 nwatkins@clnode010.clemson.cloudlab.us    
node1   clnode031   c8220   ssh -p 22 nwatkins@clnode031.clemson.cloudlab.us    
node2   clnode009   c8220   ssh -p 22 nwatkins@clnode009.clemson.cloudlab.us

Cluster: Clemson
Hardware: c8220
OS: CentOS 7.1 64-bit

yum -y update
yum -y --setopt=group_package_types=optional groupinstall "Infiniband Support"
yum -y install libibverbs-utils libibverbs-devel libipathverbs fuse fuse-devel

- password-less ssh setup from head node to all other nodes (including self).
- limits

add
```
* soft memlock unlimited
* hard memlock unlimited
```
to
/etc/security/limits.conf

logout/login

[nwatkins@node0 ~]$ ulimit -l
unlimited


```
[nwatkins@node0 ~]$ ibv_devinfo
hca_id: qib0
        transport:                      InfiniBand (0)
        fw_ver:                         0.0.0
        node_guid:                      0011:7500:0070:5f2c
        sys_image_guid:                 0011:7500:0070:5f2c
        vendor_id:                      0x1175
        vendor_part_id:                 29474
        hw_ver:                         0x2
        board_id:                       InfiniPath_QLE7340
        phys_port_cnt:                  1
                port:   1
                        state:                  PORT_ACTIVE (4)
                        max_mtu:                4096 (5)
                        active_mtu:             2048 (4)
                        sm_lid:                 1
                        port_lid:               141
                        port_lmc:               0x00
                        link_layer:             InfiniBand
```

curl -O https://gasnet.lbl.gov/GASNet-1.26.0.tar.gz
tar xzvf GASNet-1.26.0.tar.gz
cd GASNet-1.26.0
./configure --prefix=/usr --enable-udp --enable-ibv --disable-mpi --enable-par --enable-segment-fast --disable-aligned-segments --disable-pshm --with-segment-mmap-max=160GB
where 160 = 5/8 of system memory (5/8 * 256 GB)

We can also set that size at runtime if it is convenient.

make
sudo make install
cd ..




git clone https://github.com/noahdesu/gassyfs.git
cd gassyfs
GASNET=/usr CONDUIT=ibv make

GASNET_SSH_SERVERS="node0 node1 node2" gasnetrun_ibv -np 3 ./gassy mount -o name=gassy -o atomic_o_trunc -o rank0_alloc

may take a while to start up

It seems like there are multiple ranks running and it is unclear what is
happening

[nwatkins@node0 gassyfs]$ GASNET_SSH_SERVERS="node0" GASNET_USE_XRC=0
gasnetrun_ibv -n 1 -N 1 -- gassy mount -o fsname=gassy -o atomic_o_trunc -o
rank0_alloc                                                      
gasnet segment = fast|large
Local mode:            no
Rank 0 allocation:     yes
Heap size:             163838
write interface: write_buf
fuse: missing mountpoint parameter

