#!/bin/sh
echo $FLAG > /home/ctf/flag
chown root:ctf_pwn /home/ctf/flag
chmod 640 /home/ctf/flag
export FLAG=not_flag
FLAG=not_flag

echo "ctf:NUAA2021" | chpasswd

/usr/sbin/sshd -D
