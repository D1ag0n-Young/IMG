#!/bin/sh

echo "[+] Waiting for connections"
socaz --bind 1337 --cmd "qemu-hexagon -L libc ./chall"
echo "[+] Exiting"
