#!/bin/bash

if [ "$1" == "user" ] ; then
    target="i386-linux-user"
    opts=""
else
    target="i386-softmmu"
    opts="--disable-user"
fi

./configure --target-list=$target --enable-vnc --disable-kvm \
    --disable-docs --disable-vhost-net --disable-vhost-scsi $opts
