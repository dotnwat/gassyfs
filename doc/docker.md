GassyFS Docker Image
====================

This image has all the packages and environmental settings for building and running GassyFS. It also sets up an SSH daemon in the container that listens on the SSHD_PORT environment variable (by default, port 22). Right now, we run with the `--privileged` flag because the container doesn't export the fuse device properly. If anyone knows how to do this, without passing `--privileged`, let us know.

We've uploaded an image on Dockerhub [here](https://hub.docker.com/r/michaelsevilla/gassyfs). The commands below pull from this image.

Quickstart
==========

Start the container with networking/device privileges and ssh keys:

    ```bash
    docker run \
      --name gassyfs \
      -d \
      --net=host \
      -e SSHD_PORT=2222 \
      -e AUTHORIZED_KEYS="`cat ~/.ssh/id_rsa.pub`" \
      --privileged \
      -v <PATH-TO-GASSYFS-SRC>/:/gassyfs \
      michaelsevilla/gassyfs 
    ```

Build GassyFS:

    ```bash
    cd /gassyfs
    ci/build.sh
    ```

Run the POSIX tests:

    ```bash
    cd /gassyfs
    ci/test.sh
    ```

Build
=====

From outside the container:

    ```bash
    cd gassyfs/docker
    docker build -t <MYNAME>/gassyfs
    ```
