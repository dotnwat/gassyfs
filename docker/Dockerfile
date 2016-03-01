FROM tutum/ubuntu:trusty

RUN echo "===> Install the basics..." && \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
      curl \
      git \
      wget \
      libfuse-dev \
      build-essential \
      libacl1-dev \
      lua5.2 \
      liblua5.2-dev \
      samtools \
      libexpat1-dev \
      libcurl4-openssl-dev \
      gettext \
      pkg-config && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
       --reinstall linux-image-4.2.0-25-generic

RUN echo "===> Cleanup apt-get..." && \
    DEBIAN_FRONTEND=noninteractive apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /debian

RUN echo "====> Make some users" && \
    groupadd fuse && \
    usermod -a -G fuse root

RUN echo "====> Install GassyFS" && \
    wget https://raw.githubusercontent.com/noahdesu/gassyfs/master/ci/install-gasnet.sh && \
    chmod 755 install-gasnet.sh && \
    ./install-gasnet.sh

# * modify sshd conf
# * workaround for the way ubuntu deals with env for sudo
# * create expected dirs/links
RUN sed -i "s/UsePAM.*/UsePAM yes/" /etc/ssh/sshd_config && \
    sed -i "s/AcceptEnv LANG LC_*/#AcceptEnv LANG LC_*/" /etc/ssh/sshd_config && \
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" > /etc/environment && \
    echo "alias sudo='sudo env PATH=\$PATH'" >> /etc/environment && \
    sed -i "s/Defaults.*env_reset//" /etc/sudoers && \
    sed -i "s/Defaults.*secure_path.*//" /etc/sudoers 

ADD run.sh /run.sh
RUN chmod 755 /run.sh
ENTRYPOINT ["/run.sh"]
