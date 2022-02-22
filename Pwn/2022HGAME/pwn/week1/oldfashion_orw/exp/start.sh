#!/bin/bash

rm /home/ctf/flag*
cp /flag "/home/ctf/flag`head /dev/urandom |cksum |md5sum |cut -c 1-20`"
cd /home/ctf
exec 2>/dev/null
/usr/sbin/chroot --userspec=1000:1000 /home/ctf timeout 300 ./vuln
