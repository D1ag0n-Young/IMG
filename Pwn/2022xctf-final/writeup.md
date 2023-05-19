# 前言

在高版本的glibc中freehook等回调函数不能用，除了IOFile的利用方式之外，TLS劫持也是一种好方法。

# 利用条件

测试在ubuntu22.04-glibc2.35环境，利用条件如下：

1. 能在任意地址写一个可控制的堆地址
2. 可以修露出pointer_guard值或者可以修改pointer_guard
3. 程序可以正常从main 函数 的return返回或者可以触发exit()退出程序

# 分析调用链及原理

在函数退出或者显示调用exit的时候，会有如下调用链:
```c
__libc_start_main -> exit -> __run_exit_handlers -> __call_tls_dtors -> func(cur->obj)
```

```c

void exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```
```c
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
             bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();

  __libc_lock_lock (__exit_funcs_lock);
  ··· ···
}
```
```c
/* Call the destructors.  This is called either when a thread returns from the
   initial function or when the process exits via the exit function.  */
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif
      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);<----target
      /* Ensure that the MAP dereference happens before
	 l_tls_dtor_count decrement.  That way, we protect this access from a
	 potential DSO unload in _dl_close_worker, which happens when
	 l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
libc_hidden_def (__call_tls_dtors)
```
我们的目标就是将`func(cur->obj`变为`execl`或`system`等。

我们先来看func的定义是dtor_func,而dtor_func就是函数指针，实现调用：
```c
typedef void (*dtor_func) (void *);

```
给func赋值的是cur->func，cur是`dtor_list`结构体的成员：
```c
struct dtor_list
{
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};
```
而`cur->obj`就是func的参数。假设我们可以控制`dtor_list`结构体，将func改为已知可控地址，同时构造对应参数，那么在程序exit的时候就可以执行getshell函数。

`cur`和`tls_dtor_list`都是`dtor_list`结构体的实例，tls_dtor_list存储函数调用列表，cur是函数调用列表的头指针即func。

# 调用链bypass

我们要让程序能走到target，需要过一些条件判断：

1. tls_dtor_list不为空
2. PTR_DEMANGLE (func)解密，payload需要先加密

程序正常退出tls_dtor_list为空，不会去执行目标函数，可以通过覆盖tls_dtor_list成可控地址指向函数指针即可；
关键是2需要先加密写入，程序会自行解密为目标函数。

首先我们来了解下`Pointer Guard`，这个功能是 glibc 为了安全，增加攻击者在 glibc 中操纵指针（尤其是函数指针）的难度的做法。此功能也被称为 `pointer mangling`或 `pointer guard`。

实现方法就是`PTR_MANGLE` 这个宏，可以理解成 “加密”。 与之对应的“解密” 的宏是 `PTR_DEMANGLE` 。

如果应用程序想要加密在 *stored_ptr 中存储的函数指针，可以这样做：`*stored_ptr = PTR_MANGLE(ptr)；` 对应的，解密就是 `ptr = PTR_DEMANGLE(*stored_ptr);`

我们来看看PTR_DEMANGLE怎么实现的:
```c
#  define PTR_MANGLE(var)	asm ("xor %%fs:%c2, %0\n"		      \
				     "rol $2*" LP_SIZE "+1, %0"		      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))
#  define PTR_DEMANGLE(var)	asm ("ror $2*" LP_SIZE "+1, %0\n"	      \
				     "xor %%fs:%c2, %0"			      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))

```
宏定义使用内联汇编来实现：
PTR_MANGLE加密：var 寄存器和 `%fs:offsetof (tcbhead_t,	pointer_guard))` 进行异或，然后按位循环左旋转 (bitwise rotate) var 寄存器 2 * LP_SIZE + 1 位（在64位的机器上， LP_SIZE 为 8）；`offsetof (tcbhead_t,	pointer_guard))`为pointer_guard 在结构体 tcbhead_t 中的偏移量，实际上就干了以下两条指令:
```asm
xor %fs:offsetof(tcbhead_t, pointer_guard), var;
rol $2*LP_SIZE+1, var
```
PTR_DEMANGLE解密：是PTR_MANGLE加密的逆运算，先循环右移再做异或。

这两个宏利用 pointer_guard 分别对指针进行了加密和解密操作，加密由异或以及 bitwise rotate，而加密使用的 key 来自` %fs:offsetof(tcbhead_t, pointer_guard)`。由此可以得出， %fs 寄存器保存了 tcbhead_t 这个结构体的基地址。

查看 glibc 源码找到 tcbhead_t 的定义，根据代码，在 X86-64 下 pointer_guard 在 tcbhead_t 中的偏移就是 0x30：

```c
typedef struct
{
  void *tcb;		/* Pointer to the TCB.  Not necessarily the
			   thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;		/* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int unused_vgetcpu_cache[2];
  /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
  unsigned int feature_1;
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  /* The lowest address of shadow stack,  */
  unsigned long long int ssp_base;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));
  void *__padding[8];
} tcbhead_t;

```
FS 段寄存器在如今的内存平坦化下已经不像它的名字所表达的意思一样，如今操作系统可以自由的使用他们。在 Linux 下，FS 寄存器用于存放线程控制块（TCB）的地址，一般由线程库管理。 在 x86 架构下，由于支持分段，访问内存的指令可以使用基于段寄存器的寻址模式：Segment-register:Byte-address， PTR_MANGLE 这个宏中的 %fs:offsetof(tcbhead_t, pointer_guard) 就是使用这种寻址模式。通过 Segment base address + Byte-address 计算出了所要访问虚拟地址，这允许实现 TLS 在不同线程访问同一个变量得到不同的值。

所以我们在构造payload的时候需要先将target地址循环右移0x11位（64位），然后再和`pointer_guard`异或即可。python实现如下：
```python
def glibc_ptr_demangle(val, pointer_guard):
    return gdb.parse_and_eval('(((uint64_t)%s >> 0x11) | ((uint64_t)%s << (64 - 0x11))) ^ (uint64_t)%s'
                              % (val, val, pointer_guard))
def glibc_ptr_mangle(val, pointer_guard):
    return gdb.parse_and_eval('((((uint64_t)%s)^(uint64_t)%s)<<0x11)|((((uint64_t)%s)^(uint64_t)%s)<<(64-0x11))'
                              % (val, pointer_guard, val, pointer_guard))
```
如果泄露不出来pointer_guard，可以将pointer_guard覆盖为0即可。

__call_tls_dtors的汇编如下：
```
=> 0x7ff6370e1d60 <__GI___call_tls_dtors>:  endbr64 
   0x7ff6370e1d64 <__GI___call_tls_dtors+4>:    push   rbp
   0x7ff6370e1d65 <__GI___call_tls_dtors+5>:    push   rbx
   0x7ff6370e1d66 <__GI___call_tls_dtors+6>:    sub    rsp,0x8
   0x7ff6370e1d6a <__GI___call_tls_dtors+10>:   mov    rbx,QWORD PTR [rip+0x1d301f]        # 0x7ff6372b4d90
   0x7ff6370e1d71 <__GI___call_tls_dtors+17>:   mov    rbp,QWORD PTR fs:[rbx]
   0x7ff6370e1d75 <__GI___call_tls_dtors+21>:   test   rbp,rbp
   0x7ff6370e1d78 <__GI___call_tls_dtors+24>:   je     0x7ff6370e1dbd <__GI___call_tls_dtors+93># 检查链表是否为空
   0x7ff6370e1d7a <__GI___call_tls_dtors+26>:   nop    WORD PTR [rax+rax*1+0x0]
   0x7ff6370e1d80 <__GI___call_tls_dtors+32>:   mov    rdx,QWORD PTR [rbp+0x18]
   0x7ff6370e1d84 <__GI___call_tls_dtors+36>:   mov    rax,QWORD PTR [rbp+0x0]
   0x7ff6370e1d88 <__GI___call_tls_dtors+40>:   ror    rax,0x11
   0x7ff6370e1d8c <__GI___call_tls_dtors+44>:   xor    rax,QWORD PTR fs:0x30
   0x7ff6370e1d95 <__GI___call_tls_dtors+53>:   mov    QWORD PTR fs:[rbx],rdx
   0x7ff6370e1d99 <__GI___call_tls_dtors+57>:   mov    rdi,QWORD PTR [rbp+0x8]
   0x7ff6370e1d9d <__GI___call_tls_dtors+61>:   call   rax
   0x7ff6370e1d9f <__GI___call_tls_dtors+63>:   mov    rax,QWORD PTR [rbp+0x10]
   0x7ff6370e1da3 <__GI___call_tls_dtors+67>:   lock sub QWORD PTR [rax+0x468],0x1
   0x7ff6370e1dac <__GI___call_tls_dtors+76>:   mov    rdi,rbp
   0x7ff6370e1daf <__GI___call_tls_dtors+79>:   call   0x7ff6370c4370 <free@plt>
   0x7ff6370e1db4 <__GI___call_tls_dtors+84>:   mov    rbp,QWORD PTR fs:[rbx]
   0x7ff6370e1db8 <__GI___call_tls_dtors+88>:   test   rbp,rbp
   0x7ff6370e1dbb <__GI___call_tls_dtors+91>:   jne    0x7ff6370e1d80 <__GI___call_tls_dtors+32>
   0x7ff6370e1dbd <__GI___call_tls_dtors+93>:   add    rsp,0x8
   0x7ff6370e1dc1 <__GI___call_tls_dtors+97>:   pop    rbx
   0x7ff6370e1dc2 <__GI___call_tls_dtors+98>:   pop    rbp
   0x7ff6370e1dc3 <__GI___call_tls_dtors+99>:   ret
```

这里不会对tls_dtor_list的结构做是否合法的检查。而且这里还设置了rbp栈底指向结构体的地址，

所以，如果我们将rbp劫持到某一个地址，然后call rax的时候执行leave ret;就可以实现栈的迁移！

所以我们的利用思路有两个：
1. 栈迁移：把tls_dtor_list的头节点写为一个堆地址heap_address_ctr，然后在heap_address_ctr写入leave ret的gadget指针，这样，call rax 后，rip 指向了heap_address_ctr +8，我们就完成了栈的劫持，我们可以在这里布置rop。
2. 直接劫持func：把tls_dtor_list的头节点写为一个可控地址，然后在可控地址写入target函数指针，可控地址+8处写入arg参数，将tls_dtors_list附近的pointer_guard覆盖为0

**tls_dtor_list 地址如何获取？**

加载调试符号的libc文件，可以直接使用 gdb的p 指令 p &tls_dtor_list，附近可以找到pointer_guard。

[协程](https://zhuanlan.zhihu.com/p/489753875)

# 例题

[2023xctf-sp1]()