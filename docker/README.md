Quickstart
==========

docker run \
  -d \
  -e SSHD_PORT=2222 \
  --net=host \
  -e AUTHORIZED_KEYS="`cat ~/.ssh/id_rsa.pub`" \
  --privileged \
  --device /dev/fuse \
  -v /home/msevilla/code/gassyfs/:/gassyfs \
  michaelsevilla/gassyfs 

