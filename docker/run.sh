#!/bin/bash

if [ ! -f /.root_pw_set ]; then
    /set_root_pw.sh
fi

if [ "${AUTHORIZED_KEYS}" != "**None**" ]; then
    echo "=> Found authorized keys"
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    IFS=$'\n'
    arr=$(echo ${AUTHORIZED_KEYS} | tr "," "\n")
    for x in $arr
    do
        x=$(echo $x |sed -e 's/^ *//' -e 's/ *$//')
        cat /root/.ssh/authorized_keys | grep "$x" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "=> Adding public key to /root/.ssh/authorized_keys: $x"
            echo "$x" >> /root/.ssh/authorized_keys
        fi
    done
fi


if [ -z "$SSHD_PORT" ]; then
  SSHD_PORT=22
fi
sed -i "s/Port.*/Port ${SSHD_PORT}/" /etc/ssh/sshd_config
echo "    Port ${SSHD_PORT}" >> /etc/ssh/ssh_config

echo "===> Add passwordless login for myself"
ssh-keygen -t rsa -f ~/.ssh/id_rsa -N ''
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

echo "===> You shouold be able to ssh to port=$SSHD_PORT"
exec /usr/sbin/sshd -D
