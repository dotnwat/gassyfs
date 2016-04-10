On each participating node including the master create a directory with
sufficient space to hold checkpoint data. the path should be the same on
every node.

```
mkfs.ext4 /dev/sdb
mkdir /gassyfs-checkpoint
mount /dev/sdb /gassyfs-checkpoint
chown nwatkins:zlog-PG0 /gassyfs-checkpoint
```

Create a checkpoint

```
[nwatkins@node0 gassyfs]$ cp /usr/include/zlib.h /gassy                                                                                                                                                            
[nwatkins@node0 gassyfs]$ ./gassy-cmd /gassy/zlib.h checkpoint
/gassyfs-checkpoint
checkpoint path: /gassyfs-checkpoint
checkpoint id: 3db236bd-ef33-4f02-8130-dfac9db79c1b
```

* Only works in local mode right now
