#!/bin/bash

set -x
set -e

if [ "$USE_LOCAL_MODE" != "1" ]; then
  # password-less ssh to localhost
  ssh-keygen -f $HOME/.ssh/id_rsa -t rsa -N ''
  cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys

  # disable key checking stuff
  cat ~/.ssh/config || true

cat <<EOF > ~/.ssh/config
Host localhost
StrictHostKeyChecking no
UserKnownHostsFile=/dev/null
EOF
chmod 600 ~/.ssh/config

fi

# build test
pushd test/pjd-fstest-20090130-RC
make
popd

groups
echo user_allow_other | sudo tee -a /etc/fuse.conf
sudo cat /etc/fuse.conf || true

mkdir mount
if [ "$USE_LOCAL_MODE" = "1" ]; then
  ./gassy mount -o allow_other -o fsname=gassy -o atomic_o_trunc -o local_mode -o heap_size=1024 &
else
  SSH_SERVERS="localhost" /usr/local/bin/amudprun -np 1 ./gassy mount -o allow_other -o fsname=gassy -o atomic_o_trunc &
fi
sleep 5
mount

cd mount
sudo prove -r ../test/pjd-fstest-20090130-RC/tests/
sudo rm -rf *

sudo ../test/git.sh
sudo rm -rf *

sudo ../test/bamsort.sh
sudo rm -rf *
